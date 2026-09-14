"""
REST API viewsets.

The reveal endpoint is the one place in this plugin where secret material
crosses an HTTP boundary, so its defences are concentrated and explicit rather
than inherited:

* **JSON renderer only.** `BrowsableAPIRenderer` would template the payload
  into an HTML page, which browsers and intermediaries treat as cacheable
  content. Overriding `renderer_classes` on the action removes it regardless
  of the deployment's `DEFAULT_RENDERER_CLASSES`.
* **`Cache-Control: no-store`.** Stops the response being written to disk by a
  browser, a proxy, or a corporate TLS-inspecting middlebox.
* **A dedicated permission.** `reveal_credential` is separate from
  `view_credential`, so a role can inventory every credential and read none.
  Resolution goes through `restrict()`, which also applies any per-object
  constraints attached to the granting permission.
* **Rate limiting**, so a leaked token cannot drain the store silently.

The plugin registers no GraphQL schema at all, so none of this is reachable
that way: GraphQL queries are logged verbatim by most gateways, and a graph
API's response shape is harder to audit than a single named REST action.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import DatabaseError, IntegrityError, router, transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from netbox.api.viewsets import NetBoxModelViewSet, NetBoxReadOnlyModelViewSet
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from utilities.exceptions import AbortRequest

from netbox_openbao import filtersets
from netbox_openbao.administration import (
    get_administration_backend,
    record_capability_observation,
    record_health_observation,
)
from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.api.transactions import material_api_operation
from netbox_openbao.backends import get_backend
from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.choices import AccessActionChoices
from netbox_openbao.material_transactions import material_operation
from netbox_openbao.models import (
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    CredentialTypeSchema,
    OpenBaoAdministrationLog,
    OpenBaoCluster,
    OpenBaoProcedureRun,
    OpenBaoSettings,
    SecretEngine,
)
from netbox_openbao.rpc import dispatch_openbao_procedure
from netbox_openbao.services import (
    discard_staged,
    enforce_policy_access,
    enforce_update_access,
    promote_staged,
    reveal_material,
    rotate_material,
    stage_material,
    store_credential,
)
from netbox_openbao.synchronization import lock_material_subject, lock_material_subjects

from .automation import AutomationResolveRequestSerializer, AutomationResolveResponseSerializer
from .permissions import SecretActionPermissions
from .serializers import (
    CredentialAccessLogSerializer,
    CredentialAssignmentSerializer,
    CredentialPolicySerializer,
    CredentialSerializer,
    CredentialTypeSchemaSerializer,
    OpenBaoAdministrationLogSerializer,
    OpenBaoClusterSerializer,
    OpenBaoProcedureRunSerializer,
    OpenBaoSettingsSerializer,
    PromoteRequestSerializer,
    RevealRequestSerializer,
    RunProcedureSerializer,
    SecretEngineSerializer,
)
from .throttling import RevealRateThrottle

__all__ = (
    'CredentialAccessLogViewSet',
    'CredentialAssignmentViewSet',
    'CredentialPolicyViewSet',
    'CredentialTypeSchemaViewSet',
    'CredentialViewSet',
    'OpenBaoProcedureRunViewSet',
    'OpenBaoAdministrationLogViewSet',
    'OpenBaoClusterViewSet',
    'OpenBaoSettingsViewSet',
    'SecretEngineViewSet',
)


class OpenBaoAdministrationUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'OpenBao administration is unavailable.'
    default_code = 'openbao_administration_unavailable'


def _as_drf_validation_error(exc):
    """
    Translate a Django ValidationError into DRF's.

    The service layer raises Django's, because it is also called from forms and
    management commands where DRF is not in play. DRF does not translate it, so
    left alone it escapes as a **500** — which is what a user got for something
    as ordinary as promoting a credential with nothing staged, or revealing one
    whose policy requires a reason without supplying it.
    """
    detail = exc.message_dict if hasattr(exc, 'message_dict') else {'detail': exc.messages}
    return DRFValidationError(detail)


def _no_store(response):
    """Mark a response as never storable by any cache along the path."""
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response


class SecretEngineViewSet(NetBoxModelViewSet):
    queryset = SecretEngine.objects.annotate(credential_count=Count('credentials'))
    serializer_class = SecretEngineSerializer
    filterset_class = filtersets.SecretEngineFilterSet

    @action(detail=True, methods=['get'])
    def health(self, request, pk=None):
        """Probe the engine and record the observed status."""
        engine = get_object_or_404(self.queryset.restrict(request.user, 'view'), pk=pk)
        result = get_backend(engine).health()

        SecretEngine.objects.filter(pk=engine.pk).update(
            status=result['status'],
            status_message=result['message'][:500],
            last_checked=timezone.now(),
        )
        return Response({
            'engine': engine.slug,
            'status': result['status'],
            'message': result['message'],
            'checked': timezone.now(),
        })

    @action(detail=True, methods=['post'], url_path='run-procedure')
    def run_procedure(self, request, pk=None):
        """Dispatch an audited OpenBao RPC procedure against the engine host device."""
        engine = get_object_or_404(self.queryset.restrict(request.user, 'change'), pk=pk)
        serializer = RunProcedureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            execution, run = dispatch_openbao_procedure(
                engine=engine,
                procedure_name=serializer.validated_data['procedure_name'],
                user=request.user,
                request=request,
                params=serializer.validated_data.get('params') or {},
            )
        except DjangoValidationError as exc:
            raise _as_drf_validation_error(exc) from exc
        return Response(
            OpenBaoProcedureRunSerializer(run, context={'request': request}).data,
            status=status.HTTP_202_ACCEPTED,
        )


class OpenBaoClusterViewSet(NetBoxModelViewSet):
    """Cluster inventory plus safe read-only administrative discovery."""

    queryset = OpenBaoCluster.objects.annotate(mount_count=Count('secret_engines'))
    serializer_class = OpenBaoClusterSerializer
    filterset_class = filtersets.OpenBaoClusterFilterSet

    def _safe_failure(self, request, cluster, action):
        try:
            log_administration(
                cluster,
                request.user,
                action=action,
                risk_level='read',
                success=False,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                message='OpenBao administration is unavailable.',
                request=request,
            )
        except AdministrationAuditError:
            pass
        raise OpenBaoAdministrationUnavailable()

    @action(detail=True, methods=['get'])
    def health(self, request, pk=None):
        cluster = get_object_or_404(self.queryset.restrict(request.user, 'view'), pk=pk)
        try:
            result = get_administration_backend(cluster).health()
            checked = record_health_observation(cluster, request.user, result, request)
        except (AdministrationAuditError, DatabaseError, OpenBaoError):
            self._safe_failure(request, cluster, 'health')
        return _no_store(Response({
            'cluster': cluster.slug,
            'status': result['status'],
            'message': result['message'],
            'checked': checked,
        }))

    @action(detail=True, methods=['get'])
    def capabilities(self, request, pk=None):
        cluster = get_object_or_404(self.queryset.restrict(request.user, 'discover'), pk=pk)
        try:
            document = get_administration_backend(cluster).discover_capabilities()
            record_capability_observation(cluster, request.user, document, request)
        except (AdministrationAuditError, DatabaseError, OpenBaoError):
            self._safe_failure(request, cluster, 'discover-capabilities')
        return _no_store(Response(document.as_dict()))


class OpenBaoAdministrationLogViewSet(NetBoxReadOnlyModelViewSet):
    queryset = OpenBaoAdministrationLog.objects.select_related('cluster', 'user')
    serializer_class = OpenBaoAdministrationLogSerializer
    filterset_class = filtersets.OpenBaoAdministrationLogFilterSet


class OpenBaoProcedureRunViewSet(NetBoxReadOnlyModelViewSet):
    queryset = OpenBaoProcedureRun.objects.select_related(
        'engine', 'initiated_by', 'rpc_execution', 'rpc_execution__procedure',
    )
    serializer_class = OpenBaoProcedureRunSerializer
    filterset_class = filtersets.OpenBaoProcedureRunFilterSet


class OpenBaoSettingsViewSet(NetBoxModelViewSet):
    """REST CRUD for the database-enforced singleton settings row."""

    queryset = OpenBaoSettings.objects.all().order_by('id')
    serializer_class = OpenBaoSettingsSerializer
    filterset_class = filtersets.OpenBaoSettingsFilterSet

    def perform_create(self, serializer):
        # The serializer's exists() check provides a useful early error, but it
        # cannot serialize two concurrent POSTs. The model re-checks under the
        # singleton advisory lock and refuses with AbortRequest, which is what
        # keeps the HTML form off an uncaught IntegrityError; IntegrityError is
        # still translated here because the constraint remains the last
        # authority if that lock is ever bypassed. Both become the same
        # structured 400 rather than a 500 or an unexplained detail string.
        try:
            super().perform_create(serializer)
        except (AbortRequest, IntegrityError) as exc:
            raise DRFValidationError({
                'non_field_errors': ['The OpenBao settings row already exists.'],
            }) from exc


class CredentialPolicyViewSet(NetBoxModelViewSet):
    queryset = CredentialPolicy.objects.select_related('engine').annotate(
        credential_count=Count('credentials')
    )
    serializer_class = CredentialPolicySerializer
    filterset_class = filtersets.CredentialPolicyFilterSet


class CredentialViewSet(NetBoxModelViewSet):
    queryset = Credential.objects.select_related('policy', 'engine').annotate(
        assignment_count=Count('assignments')
    )
    serializer_class = CredentialSerializer
    filterset_class = filtersets.CredentialFilterSet

    @material_api_operation
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @material_api_operation
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @material_api_operation
    def bulk_create(self, request, *args, **kwargs):
        if isinstance(request.data, list):
            self._lock_batch_participants([], request.data)
        return super().bulk_create(request, *args, **kwargs)

    @material_api_operation
    def bulk_update(self, request, *args, **kwargs):
        return super().bulk_update(request, *args, **kwargs)

    def _lock_batch_participants(self, subjects, entries):
        """Predeclare valid destination selectors; native serializers report errors."""
        policy_field = self.get_serializer().fields['policy']
        policy_ids = set()
        for data in entries:
            if not isinstance(data, dict) or 'policy' not in data:
                continue
            try:
                policy = policy_field.run_validation(data['policy'])
            except (DRFValidationError, DjangoValidationError):
                continue
            if policy is not None:
                policy_ids.add(policy.pk)
        lock_material_subjects(list(subjects), additional_policy_ids=policy_ids)

    @extend_schema(request=AutomationResolveRequestSerializer, responses={200: AutomationResolveResponseSerializer})
    @action(
        detail=False, methods=['post'], url_path='resolve-automation',
        renderer_classes=[JSONRenderer], throttle_classes=[RevealRateThrottle],
        permission_classes=[SecretActionPermissions],
    )
    def resolve_automation(self, request) -> Response:
        """Deliver one execution-authorized named bundle over verified TLS only."""
        from netbox_openbao.automation import AutomationResolutionDenied, resolve_automation

        request._request.sensitive_post_parameters = '__ALL__'
        if not request.is_secure():
            return _no_store(Response({'detail': 'A secure transport is required.'}, status=403))
        serializer = AutomationResolveRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return _no_store(Response({'detail': 'Invalid automation resolution request.'}, status=400))
        try:
            result = resolve_automation(request, serializer.validated_data)
        except AutomationResolutionDenied:
            return _no_store(Response({'detail': 'Automation credential resolution was refused.'}, status=403))
        return _no_store(Response(result))

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def _require_rotate(self, instance):
        """
        Demand `rotate_credential` before material on an existing credential is
        replaced.

        `rotate` is a permission of its own precisely so that replacing
        material can be withheld from someone who may otherwise edit a
        credential — rename it, retag it, change its rotation interval. But
        `PUT`, `PATCH`, and the bulk list endpoint all reach `perform_update()`
        under `change_credential`, and a `secret_data` key in that body writes a
        new version. Gating only the dedicated `rotate` action therefore left
        the *same write* reachable by a different verb, and a principal
        deliberately denied rotation could inject replacement credentials or
        take an integration offline.

        Resolved through `restrict()` rather than `has_perm()` so the
        constraints on the granting ObjectPermission apply, and against the
        committed row rather than `serializer.instance`, which NetBox has
        already mutated with the incoming data.

        A 403 rather than a 404: the caller reached this point holding
        `change`, so the credential's existence is not a secret from them.
        """
        permitted = Credential.objects.restrict(self.request.user, 'rotate').filter(pk=instance.pk)
        if not permitted.exists():
            raise PermissionDenied(
                'Replacing secret material requires the rotate permission on this credential.'
            )

    def _conform(self, instance):
        """
        Re-check a just-saved object against the view's restricted queryset.

        This is NetBox's `_validate_objects()`, and it is what enforces
        *constraints* on a create or an update: `restrict()` bounds which rows
        you may act on, but only a post-save check can tell you whether the row
        you just wrote is still one of them. Without it a constrained
        `add_credential` grant creates credentials outside its allowed policy,
        and a constrained `change_credential` grant moves an existing one out
        of scope.

        These viewsets override `perform_create`/`perform_update` to thread the
        material write through `store_credential`, and an earlier revision
        dropped the check along with the rest of NetBox's implementation.

        It is called from **inside** the persist callback on purpose, so it
        runs within `store_credential`'s atomic block. Raising it outside would
        roll the row back while leaving the OpenBao write stranded, which is
        precisely the residue the compensator exists to prevent.
        """
        if not self.queryset.filter(pk=instance.pk).exists():
            raise ObjectDoesNotExist

    def perform_create(self, serializer):
        """
        Persist the row and the material as one unit.

        `secret_data` is popped before anything is saved, so it never reaches a
        model constructor even transiently. Persistence is handed to
        `store_credential` as a callback so the serializer still owns tags,
        custom fields, and m2m assignment while the rollback compensator wraps
        the whole operation — and so the post-save permission check happens
        inside that compensated region.
        """
        payload = serializer.validated_data.pop('secret_data', None)
        credential_type = serializer.validated_data['credential_type']

        def persist(metadata):
            instance = serializer.save(**metadata)
            self._conform(instance)
            return instance

        try:
            store_credential(
                persist,
                credential_type,
                payload,
                cas=0,
                user=self.request.user,
                request=self.request,
                target_policy=serializer.validated_data.get('policy'),
            )
        except ObjectDoesNotExist:
            raise PermissionDenied() from None

    def perform_update(self, serializer):
        """
        Update the row, and the material with it when a payload is supplied.

        The tier's group gate is applied to **every** update, not only to those
        carrying material, and against the instance as it is *now* — before the
        serializer's changes land.

        Both of those matter. `PUT`/`PATCH` are routed by DRF's own `update()`
        and never reach `_authorize`, so gating only the dedicated `rotate`
        action left the same write reachable by a different verb.

        And gating only material-bearing updates left a worse hole: `policy` is
        a writable field, so a caller outside a tier's groups could move a
        credential to a tier they *are* in — an update carrying no
        `secret_data`, and therefore ungated — and then reveal it. The paths are
        UUID-derived under one shared prefix, so the receiving tier's AppRole
        reads the same secret; layer 2 and layer 3 both fall to one `PATCH`.
        Checking the pre-change instance is what refuses the move, because the
        instance still carries the tier the caller has to satisfy.

        A create is deliberately not gated: the policy is being chosen there and
        `add_credential` governs it. See `services.enforce_update_access` for
        why the committed row has to be re-read rather than trusting
        `serializer.instance`, which NetBox has already mutated by this point.

        Separately, an update **carrying material** is a rotation whatever verb
        it arrives on, so it demands `rotate_credential` and not merely
        `change_credential` — see `_require_rotate`.
        """
        lock_material_subject(serializer.instance, serializer.validated_data.get('policy'))
        enforce_update_access(
            serializer.instance,
            self.request.user,
            AccessActionChoices.ACTION_WRITE,
            request=self.request,
        )

        payload = serializer.validated_data.pop('secret_data', None)

        if not payload:
            try:
                with transaction.atomic(using=router.db_for_write(self.queryset.model)):
                    instance = serializer.save()
                    self._conform(instance)
            except ObjectDoesNotExist:
                raise PermissionDenied() from None
            return

        instance = serializer.instance
        # The tier the credential is on *now*.
        self._require_rotate(instance)
        credential_type = serializer.validated_data.get('credential_type', instance.credential_type)

        def persist(metadata):
            saved = serializer.save(**metadata)
            self._conform(saved)
            # ...and the tier it has *become*. Checking only the source lets a
            # rotate constraint scoped to `lab` be satisfied by a PATCH that
            # simultaneously moves the credential to `prod` and writes the new
            # material through prod's policy and AppRole. Both ends, or the
            # constraint means nothing on a move.
            self._require_rotate(saved)
            return saved

        try:
            store_credential(
                persist,
                credential_type,
                payload,
                # Check-and-set against the version we believe is current, so a
                # concurrent write cannot be silently clobbered.
                cas=instance.kv_version,
                subject=instance,
                target_policy=serializer.validated_data.get('policy'),
                user=self.request.user,
                request=self.request,
                action=AccessActionChoices.ACTION_ROTATE,
            )
        except ObjectDoesNotExist:
            raise PermissionDenied() from None

    @material_operation
    def perform_bulk_update(self, objects, update_data, partial):
        """
        Preserve metadata batches while refusing unsupported bulk rotations.

        The outer owner and complete source/destination graph now cover native
        batch persistence. This does not enable a new multi-rotation REST
        workflow: material updates still require the detail or rotate action.
        """
        offenders = sorted(
            str(pk) for pk, data in (update_data or {}).items()
            if isinstance(data, dict) and data.get('secret_data')
        )
        if offenders:
            raise DRFValidationError({
                'secret_data': (
                    'Secret material cannot be written through a bulk update. Rotate these credentials individually, '
                    'through the detail endpoint or the rotate action. '
                    f'Offending credential ID(s): {", ".join(offenders)}.'
                ),
            })
        self._lock_batch_participants(objects, (update_data or {}).values())
        return super().perform_bulk_update(objects, update_data, partial)

    # ------------------------------------------------------------------
    # Reveal
    # ------------------------------------------------------------------

    # Audit action recorded when the tier's group gate refuses. `view` — the
    # `versions` action — records nothing: listing version numbers is not an
    # access to material, and an audit row for every refused metadata read
    # would bury the reveals that matter.
    _GATE_AUDIT_ACTION = {
        'reveal': AccessActionChoices.ACTION_REVEAL,
        'rotate': AccessActionChoices.ACTION_ROTATE,
    }

    def _authorize(self, request, pk, action_name):
        """
        Resolve a credential the user is permitted to act on.

        `restrict()` applies both the permission and any constraints on the
        granting ObjectPermission, so a group limited to `{"policy__slug":
        "lab"}` gets a 404 on a production credential rather than a 403 that
        confirms it exists.

        The tier's group gate is then applied through `enforce_policy_access`,
        which is the same function the service layer calls. It used to be
        implemented inline here, which meant the API enforced it and every UI
        path did not — see that function's docstring.
        """
        credential = get_object_or_404(
            Credential.objects.restrict(request.user, action_name).select_related('policy', 'engine'),
            pk=pk,
        )
        enforce_policy_access(
            credential,
            request.user,
            self._GATE_AUDIT_ACTION.get(action_name),
            request=request,
        )
        return credential

    @action(
        detail=True,
        methods=['get', 'post'],
        renderer_classes=[JSONRenderer],
        throttle_classes=[RevealRateThrottle],
        permission_classes=[SecretActionPermissions],
    )
    def reveal(self, request, pk=None):
        """Return the secret payload. Requires `netbox_openbao.reveal_credential`."""
        credential = self._authorize(request, pk, 'reveal')

        params = RevealRequestSerializer(data=request.data if request.method == 'POST' else request.query_params)
        params.is_valid(raise_exception=True)

        try:
            data, ttl = reveal_material(
                credential,
                request.user,
                request=request,
                reason=params.validated_data.get('reason', ''),
                version=params.validated_data.get('version'),
            )
        except DjangoValidationError as exc:
            raise _as_drf_validation_error(exc) from None
        except OpenBaoError as exc:
            return _no_store(Response(
                {'detail': str(exc)},
                status=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            ))

        return _no_store(Response({
            'id': credential.pk,
            'uuid': str(credential.uuid),
            'name': credential.name,
            'credential_type': credential.credential_type,
            'username': credential.username,
            'kv_version': credential.kv_version,
            'ttl': ttl,
            'secret_data': data,
        }))

    @action(
        detail=True,
        methods=['post'],
        renderer_classes=[JSONRenderer],
        permission_classes=[SecretActionPermissions],
    )
    def rotate(self, request, pk=None):
        """Write a new version of the material, keeping the same path and row."""
        credential = self._authorize(request, pk, 'rotate')

        payload = request.data.get('secret_data')
        if not payload:
            raise DRFValidationError({'secret_data': 'Secret data is required to rotate a credential.'})

        try:
            # rotate_material returns (credential, version); returning the
            # tuple straight into the response body rendered kv_version as a
            # pair containing the model instance.
            _credential, version = rotate_material(
                credential, payload, user=request.user, request=request
            )
        except OpenBaoError as exc:
            return _no_store(Response(
                {'detail': str(exc)},
                status=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            ))

        return _no_store(Response({'id': credential.pk, 'kv_version': version}))

    # ------------------------------------------------------------------
    # Staged rotation
    # ------------------------------------------------------------------
    #
    # All three transitions are gated on `rotate_credential` rather than each
    # getting its own permission. They are three steps of one operation, and
    # anyone trusted to replace a credential's material is necessarily trusted
    # to finish or abandon the replacement. Splitting them would produce
    # permission combinations with no coherent meaning — the right to promote
    # material you were not allowed to stage, for one.

    @action(
        detail=True,
        methods=['post'],
        renderer_classes=[JSONRenderer],
        permission_classes=[SecretActionPermissions],
    )
    def stage(self, request, pk=None):
        """Write replacement material without putting it into service."""
        credential = self._authorize(request, pk, 'rotate')

        payload = request.data.get('secret_data')
        if not payload:
            raise DRFValidationError({'secret_data': 'Secret data is required to stage a rotation.'})

        try:
            credential, version = stage_material(
                credential, payload, user=request.user, request=request
            )
        except DjangoValidationError as exc:
            raise _as_drf_validation_error(exc) from None
        except OpenBaoError as exc:
            return _no_store(Response(
                {'detail': str(exc)}, status=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            ))

        return _no_store(Response({
            'id': credential.pk,
            'status': credential.status,
            'kv_version': version,
            'live_kv_version': credential.live_kv_version,
            'has_staged_version': credential.has_staged_version,
        }))

    @action(
        detail=True,
        methods=['post'],
        renderer_classes=[JSONRenderer],
        permission_classes=[SecretActionPermissions],
    )
    def promote(self, request, pk=None):
        """Put the staged version into service."""
        credential = self._authorize(request, pk, 'rotate')

        params = PromoteRequestSerializer(data=request.data)
        params.is_valid(raise_exception=True)

        try:
            credential = promote_staged(
                credential,
                user=request.user,
                request=request,
                verified=params.validated_data.get('verified', False),
                note=params.validated_data.get('note', ''),
            )
        except DjangoValidationError as exc:
            raise _as_drf_validation_error(exc) from None
        return _no_store(Response({
            'id': credential.pk,
            'status': credential.status,
            'kv_version': credential.kv_version,
            'live_kv_version': credential.live_kv_version,
            'has_staged_version': credential.has_staged_version,
        }))

    @action(
        detail=True,
        methods=['post'],
        renderer_classes=[JSONRenderer],
        permission_classes=[SecretActionPermissions],
    )
    def discard(self, request, pk=None):
        """Destroy the staged version, leaving the live one untouched."""
        credential = self._authorize(request, pk, 'rotate')

        try:
            credential = discard_staged(credential, user=request.user, request=request)
        except DjangoValidationError as exc:
            raise _as_drf_validation_error(exc) from None
        except OpenBaoError as exc:
            return _no_store(Response(
                {'detail': str(exc)}, status=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            ))

        return _no_store(Response({
            'id': credential.pk,
            'status': credential.status,
            'kv_version': credential.kv_version,
            'live_kv_version': credential.live_kv_version,
            'has_staged_version': credential.has_staged_version,
        }))

    @action(detail=True, methods=['get'])
    def versions(self, request, pk=None):
        """
        List version metadata for a credential. Metadata only, never values,
        so this needs `view` rather than `reveal`.
        """
        credential = self._authorize(request, pk, 'view')
        backend = get_backend(credential.engine, credential.policy)
        try:
            versions = backend.list_versions(credential.path)
        except OpenBaoError as exc:
            return Response(
                {'detail': str(exc)},
                status=exc.status_code or status.HTTP_502_BAD_GATEWAY,
            )
        return Response({'id': credential.pk, 'versions': versions})


class CredentialAssignmentViewSet(NetBoxModelViewSet):
    queryset = CredentialAssignment.objects.select_related(
        'credential', 'assigned_object_type'
    ).prefetch_related('assigned_object')
    serializer_class = CredentialAssignmentSerializer
    filterset_class = filtersets.CredentialAssignmentFilterSet


class CredentialTypeSchemaViewSet(NetBoxModelViewSet):
    queryset = CredentialTypeSchema.objects.all()
    serializer_class = CredentialTypeSchemaSerializer
    filterset_class = filtersets.CredentialTypeSchemaFilterSet


class CredentialAccessLogViewSet(NetBoxReadOnlyModelViewSet):
    """
    Read-only by construction. The audit trail is evidence: exposing create,
    update, or delete would let the same token that reveals a secret erase the
    record of having done so.

    `NetBoxReadOnlyModelViewSet` rather than DRF's `ReadOnlyModelViewSet`,
    because object permissions are applied in NetBox's `BaseViewSet.initial()`
    — it is the thing that calls `queryset.restrict(user, action)`. A viewset
    outside that hierarchy is still gated on the model-level permission by
    `TokenPermissions`, but every **constraint** attached to the granting
    ObjectPermission is silently ignored. This viewset was outside it, so a
    role scoped to one tier with `{"credential__policy__slug": "lab"}` was
    held to that in the UI list view and read the whole estate's log through
    the API — credential names, usernames, reveal reasons, and source IPs.

    The base composes only `RetrieveModelMixin` and `ListModelMixin`, so
    append-only is preserved: there is still no create, update, or delete
    route. Its `CustomFieldsMixin`, `ExportTemplatesMixin`, and `ETagMixin` all
    probe with `hasattr`/`getattr` and tolerate a plain Django model that has
    no custom fields and no `last_updated`.
    """

    queryset = CredentialAccessLog.objects.select_related('credential', 'user')
    serializer_class = CredentialAccessLogSerializer
    filterset_class = filtersets.CredentialAccessLogFilterSet
