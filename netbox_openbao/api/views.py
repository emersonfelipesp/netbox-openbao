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

from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet

from netbox_openbao import filtersets
from netbox_openbao.backends import get_backend
from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.choices import AccessActionChoices
from netbox_openbao.models import (
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    SecretEngine,
)
from netbox_openbao.services import reveal_material, rotate_material, store_credential

from .permissions import SecretActionPermissions
from .serializers import (
    CredentialAccessLogSerializer,
    CredentialAssignmentSerializer,
    CredentialPolicySerializer,
    CredentialSerializer,
    RevealRequestSerializer,
    SecretEngineSerializer,
)
from .throttling import RevealRateThrottle

__all__ = (
    'CredentialAccessLogViewSet',
    'CredentialAssignmentViewSet',
    'CredentialPolicyViewSet',
    'CredentialViewSet',
    'SecretEngineViewSet',
)


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

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def perform_create(self, serializer):
        """
        Persist the row and the material as one unit.

        `secret_data` is popped before anything is saved, so it never reaches a
        model constructor even transiently. Persistence is handed to
        `store_credential` as a callback so the serializer still owns tags,
        custom fields, and m2m assignment while the rollback compensator wraps
        the whole operation.
        """
        payload = serializer.validated_data.pop('secret_data', None)
        credential_type = serializer.validated_data['credential_type']
        store_credential(
            lambda metadata: serializer.save(**metadata),
            credential_type,
            payload,
            cas=0,
            user=self.request.user,
            request=self.request,
        )

    def perform_update(self, serializer):
        payload = serializer.validated_data.pop('secret_data', None)
        if not payload:
            serializer.save()
            return

        instance = serializer.instance
        credential_type = serializer.validated_data.get('credential_type', instance.credential_type)
        store_credential(
            lambda metadata: serializer.save(**metadata),
            credential_type,
            payload,
            # Check-and-set against the version we believe is current, so a
            # concurrent write cannot be silently clobbered.
            cas=instance.kv_version,
            user=self.request.user,
            request=self.request,
            action=AccessActionChoices.ACTION_ROTATE,
        )

    # ------------------------------------------------------------------
    # Reveal
    # ------------------------------------------------------------------

    def _authorize(self, request, pk, action_name):
        """
        Resolve a credential the user is permitted to act on.

        `restrict()` applies both the permission and any constraints on the
        granting ObjectPermission, so a group limited to `{"policy__slug":
        "lab"}` gets a 404 on a production credential rather than a 403 that
        confirms it exists.
        """
        credential = get_object_or_404(
            Credential.objects.restrict(request.user, action_name).select_related('policy', 'engine'),
            pk=pk,
        )

        # Coarse tier gate, applied in addition to object permissions.
        groups = credential.policy.groups.all()
        if groups.exists() and not request.user.is_superuser:
            if not request.user.groups.filter(pk__in=groups.values_list('pk', flat=True)).exists():
                raise PermissionDenied(
                    "Your groups are not permitted to access credentials under this policy."
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


class CredentialAccessLogViewSet(ReadOnlyModelViewSet):
    """
    Read-only by construction. The audit trail is evidence: exposing create,
    update, or delete would let the same token that reveals a secret erase the
    record of having done so.
    """

    queryset = CredentialAccessLog.objects.select_related('credential', 'user')
    serializer_class = CredentialAccessLogSerializer
    filterset_class = filtersets.CredentialAccessLogFilterSet
