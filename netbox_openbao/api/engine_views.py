"""Fixed REST actions for OpenBao secret engines and the mounted explorer."""

from django.views.decorators.debug import sensitive_variables
from packaging.version import InvalidVersion, Version
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from netbox_openbao.administration import get_administration_backend
from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.administration.engines import (
    RESERVED_MOUNT_PATHS,
    classify_explorer_operations,
    compile_operation_path,
    mount_parameter_for_path,
    resolve_explorer_operation,
    validate_declared_field_types,
)
from netbox_openbao.administration.schema import CapabilitySchemaError
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoError, OpenBaoMutationUnknown
from netbox_openbao.models import SecretEngine

from .engine_serializers import (
    DisableSecretEngineSerializer,
    EnableSecretEngineSerializer,
    ExplorerExecuteSerializer,
    ReadSecretEngineSerializer,
    RemountSecretEngineSerializer,
    RemountStatusSerializer,
    TuneSecretEngineSerializer,
)
from .permissions import ClusterActionPermissions

ENGINE_LIFECYCLE_OPERATIONS = {
    ("GET", "/sys/mounts"): "mounts-list-secrets-engines",
    ("GET", "/sys/mounts/{path}"): "mounts-read-configuration",
    ("POST", "/sys/mounts/{path}"): "mounts-enable-secrets-engine",
    ("GET", "/sys/mounts/{path}/tune"): "mounts-read-tuning-information",
    ("POST", "/sys/mounts/{path}/tune"): "mounts-tune-configuration-parameters",
    ("DELETE", "/sys/mounts/{path}"): "mounts-disable-secrets-engine",
    ("POST", "/sys/remount"): "remount",
    ("GET", "/sys/remount/status/{migration_id}"): "remount-status",
}


def _no_store(response):
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


class SecretEngineAdministrationMixin:
    """Secrets-engine actions mixed into the cluster model viewset."""

    @staticmethod
    def _serializer(serializer_class, request, cluster):
        serializer = serializer_class(data=request.data, context={"request": request, "cluster": cluster})
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def _prepare_engine_operation(self, cluster, method, path_template):
        backend, document = self._engine_document(cluster)
        expected_operation_id = ENGINE_LIFECYCLE_OPERATIONS.get((method, path_template))
        if expected_operation_id is None or not any(
            item.method == method
            and item.path_template == path_template
            and item.operation_id == expected_operation_id
            for item in document.operations
        ):
            raise OpenBaoConflict("OpenBao does not advertise the reviewed operation.")
        return backend, document

    def _engine_document(self, cluster):
        backend = get_administration_backend(cluster)
        seal = backend.seal_status()
        self._require_baseline(seal)
        if not seal.initialized or seal.sealed:
            raise OpenBaoConflict("The OpenBao cluster is not ready for secret-engine administration.")
        document = backend.discover_capabilities()
        try:
            version = Version(document.product_version)
        except InvalidVersion:
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.") from None
        if version < Version("2.6.2") or version.release[:2] != (2, 6):
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.")
        return backend, document

    @staticmethod
    def _audit(cluster, request, operation, *, risk, method, path, digest, reason="", status_code=200):
        log_administration(
            cluster,
            request.user,
            action=operation,
            operation_id=operation,
            risk_level=risk,
            method=method,
            path_template=path,
            reason=reason,
            capability_digest=digest,
            success=True,
            status_code=status_code,
            message="Completed a reviewed OpenBao secrets-engine operation.",
            request=request,
        )

    @staticmethod
    def _unknown_mutation_response():
        response = _no_store(Response({
            "outcome": "unknown",
            "audit_status": "preflight-only",
            "message": "OpenBao may have accepted the request. Do not retry; verify current state first.",
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE))
        response["X-OpenBao-Operation-Outcome"] = "unknown"
        response["X-OpenBao-Audit-Status"] = "preflight-only"
        return response

    def _record_unknown(self, cluster, request, operation, *, risk, method, path, digest, reason):
        try:
            log_administration(
                cluster,
                request.user,
                action=f"{operation}-outcome-unknown",
                operation_id=operation,
                risk_level=risk,
                method=method,
                path_template=path,
                reason=reason,
                capability_digest=digest,
                outcome="unknown",
                success=False,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                message="OpenBao may have accepted the request; state verification is required before retry.",
                request=request,
            )
        except AdministrationAuditError:
            pass

    @action(detail=True, methods=["get"], url_path="secret-engines", permission_classes=[ClusterActionPermissions])
    def secret_engines(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_secret_engines")
        try:
            backend, document = self._prepare_engine_operation(cluster, "GET", "/sys/mounts")
            mounts = backend.list_secret_engines()
            self._audit(
                cluster,
                request,
                "secret-engine-list",
                risk="read",
                method="GET",
                path="/sys/mounts",
                digest=document.digest,
            )
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "secret-engine-list", exc, risk_level="read")
        return _no_store(
            Response({"mounts": [mount.as_dict() for mount in mounts], "capability_digest": document.digest})
        )

    def _read_secret_engine_metadata(self, request, cluster, *, operation, template, producer):
        data = self._serializer(ReadSecretEngineSerializer, request, cluster)
        try:
            backend, document = self._prepare_engine_operation(cluster, "GET", template)
            if data["mount_path"] not in {mount.path for mount in backend.list_secret_engines()}:
                raise OpenBaoConflict("The secret-engine mount is unavailable.")
            result = producer(backend, data["mount_path"])
            self._audit(
                cluster,
                request,
                operation,
                risk="read",
                method="GET",
                path=template,
                digest=document.digest,
            )
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, operation, exc, risk_level="read")
        return _no_store(Response(result))

    @action(
        detail=True,
        methods=["post"],
        url_path="secret-engines/configuration",
        permission_classes=[ClusterActionPermissions],
    )
    def secret_engine_configuration(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_secret_engines")
        return self._read_secret_engine_metadata(
            request,
            cluster,
            operation="secret-engine-configuration",
            template="/sys/mounts/{path}",
            producer=lambda backend, path: backend.read_secret_engine(path),
        )

    @action(
        detail=True, methods=["post"], url_path="secret-engines/tuning", permission_classes=[ClusterActionPermissions]
    )
    def secret_engine_tuning(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_secret_engines")
        return self._read_secret_engine_metadata(
            request,
            cluster,
            operation="secret-engine-tuning",
            template="/sys/mounts/{path}/tune",
            producer=lambda backend, path: backend.read_secret_engine_tuning(path),
        )

    @action(
        detail=True, methods=["post"], url_path="secret-engines/enable", permission_classes=[ClusterActionPermissions]
    )
    def enable_secret_engine(self, request, pk=None):
        cluster = self._cluster(request, pk, "manage_secret_engines")
        data = self._serializer(EnableSecretEngineSerializer, request, cluster)
        return self._engine_mutation(
            request,
            cluster,
            "secret-engine-enable",
            "POST",
            "/sys/mounts/{path}",
            data,
            lambda backend: backend.enable_secret_engine(data["mount_path"], data["configuration"]),
        )

    @action(
        detail=True, methods=["post"], url_path="secret-engines/tune", permission_classes=[ClusterActionPermissions]
    )
    def tune_secret_engine(self, request, pk=None):
        cluster = self._cluster(request, pk, "manage_secret_engines")
        data = self._serializer(TuneSecretEngineSerializer, request, cluster)
        return self._engine_mutation(
            request,
            cluster,
            "secret-engine-tune",
            "POST",
            "/sys/mounts/{path}/tune",
            data,
            lambda backend: backend.tune_secret_engine(data["mount_path"], data["configuration"]),
        )

    @action(
        detail=True, methods=["post"], url_path="secret-engines/remount", permission_classes=[ClusterActionPermissions]
    )
    def remount_secret_engine(self, request, pk=None):
        cluster = self._cluster(request, pk, "manage_secret_engines")
        data = self._serializer(RemountSecretEngineSerializer, request, cluster)
        return self._engine_mutation(
            request,
            cluster,
            "secret-engine-remount",
            "POST",
            "/sys/remount",
            data,
            lambda backend: backend.remount_secret_engine(data["source"], data["destination"]),
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="secret-engines/remount-status",
        permission_classes=[ClusterActionPermissions],
    )
    def secret_engine_remount_status(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_secret_engines")
        data = self._serializer(RemountStatusSerializer, request, cluster)
        try:
            backend, document = self._prepare_engine_operation(cluster, "GET", "/sys/remount/status/{migration_id}")
            result = backend.secret_engine_remount_status(data["migration_id"])
            self._audit(
                cluster,
                request,
                "secret-engine-remount-status",
                risk="read",
                method="GET",
                path="/sys/remount/status/{migration_id}",
                digest=document.digest,
            )
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "secret-engine-remount-status", exc, risk_level="read")
        return _no_store(Response(result))

    @action(
        detail=True, methods=["post"], url_path="secret-engines/disable", permission_classes=[ClusterActionPermissions]
    )
    def disable_secret_engine(self, request, pk=None):
        cluster = self._cluster(request, pk, "disable_secret_engines")
        data = self._serializer(DisableSecretEngineSerializer, request, cluster)
        if SecretEngine.objects.filter(
            cluster=cluster, kv_mount=data["mount_path"], credentials__isnull=False
        ).exists():
            raise ValidationError("The mount still contains NetBox credential inventory and cannot be disabled.")
        return self._engine_mutation(
            request,
            cluster,
            "secret-engine-disable",
            "DELETE",
            "/sys/mounts/{path}",
            data,
            lambda backend: backend.disable_secret_engine(data["mount_path"]),
            risk="destructive",
        )

    @sensitive_variables()
    def _engine_mutation(self, request, cluster, operation, method, template, data, producer, *, risk="write"):
        raw_request = getattr(request, "_request", request)
        raw_request.sensitive_post_parameters = "__ALL__"
        try:
            backend, document = self._prepare_engine_operation(cluster, method, template)
            mount_paths = {mount.path for mount in backend.list_secret_engines()}
            if operation == "secret-engine-enable" and data["mount_path"] in mount_paths:
                raise OpenBaoConflict("The secret-engine mount already exists.")
            if operation in {"secret-engine-tune", "secret-engine-disable"} and data["mount_path"] not in mount_paths:
                raise OpenBaoConflict("The secret-engine mount is unavailable.")
            if operation == "secret-engine-remount" and (
                data["source"] not in mount_paths or data["destination"] in mount_paths
            ):
                raise OpenBaoConflict("The remount source or destination changed.")
            log_administration(
                cluster,
                request.user,
                action=f"{operation}-authorized",
                operation_id=operation,
                risk_level=risk,
                method=method,
                path_template=template,
                reason=data["reason"],
                capability_digest=document.digest,
                outcome="authorized",
                success=True,
                status_code=202,
                message="Authorized a reviewed OpenBao secrets-engine mutation.",
                request=request,
                require_durable=True,
            )
            result = producer(backend) or {}
        except OpenBaoMutationUnknown:
            self._record_unknown(
                cluster,
                request,
                operation,
                risk=risk,
                method=method,
                path=template,
                digest=document.digest,
                reason=data["reason"],
            )
            return self._unknown_mutation_response()
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, operation, exc, reason=data["reason"], risk_level=risk)
        audit_complete = True
        try:
            self._audit(
                cluster,
                request,
                operation,
                risk=risk,
                method=method,
                path=template,
                digest=document.digest,
                reason=data["reason"],
            )
        except AdministrationAuditError:
            audit_complete = False
        return self._mutation_response(result, audit_complete=audit_complete)

    @action(detail=True, methods=["get"], url_path="secret-operations", permission_classes=[ClusterActionPermissions])
    def secret_operations(self, request, pk=None):
        cluster = self._cluster(request, pk, "explore_secret_operations")
        try:
            _backend, document = self._engine_document(cluster)
            operations = classify_explorer_operations(document)
            self._audit(
                cluster,
                request,
                "secret-operation-catalog",
                risk="read",
                method="GET",
                path="/sys/internal/specs/openapi",
                digest=document.digest,
            )
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "secret-operation-catalog", exc, risk_level="read")
        return _no_store(
            Response({"capability_digest": document.digest, "operations": [item.as_dict() for item in operations]})
        )

    def _prepare_explorer_execution(self, request, cluster, data):
        backend, document = self._engine_document(cluster)
        if data["capability_digest"] != document.digest:
            raise OpenBaoConflict("The OpenBao capability document changed; reload the operation catalog.")
        operation = resolve_explorer_operation(document, data["operation_key"])
        if set(data["query"]) - set(operation.query_parameters):
            raise ValidationError("The request contains an undeclared query parameter.")
        if not set(operation.required_query_parameters) <= set(data["query"]):
            raise ValidationError("The request omits a required query parameter.")
        if set(data["body"]) - set(operation.body_fields):
            raise ValidationError("The request contains an undeclared body field.")
        if not set(operation.required_body_fields) <= set(data["body"]):
            raise ValidationError("The request omits a required body field.")
        validate_declared_field_types(data["query"], operation.query_parameter_types)
        validate_declared_field_types(data["body"], operation.body_field_types)
        validate_declared_field_types(data["path_parameters"], operation.path_parameter_types)
        if not request.user.has_perm(operation.required_permission, cluster):
            raise PermissionDenied("The reviewed operation permission is required.")
        mounts = {mount.path for mount in backend.list_secret_engines()}
        if data["mount_path"] not in mounts or data["mount_path"] in RESERVED_MOUNT_PATHS:
            raise ValidationError("The selected live secret-engine mount is unavailable.")
        if operation.mount_parameter != mount_parameter_for_path(data["mount_path"]):
            raise ValidationError("The selected operation was not advertised by this live mount.")
        path = compile_operation_path(
            operation.path_template,
            data["mount_path"],
            data["resource_path"],
            data["path_parameters"],
        )
        if operation.risk_level == "destructive" and data["confirmation"] != (
            f"{operation.method} {path} ON {cluster.slug}"
        ):
            raise ValidationError("The exact destructive-operation confirmation is required.")
        return backend, document, operation, path

    @action(
        detail=True,
        methods=["post"],
        url_path="secret-operations/execute",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def execute_secret_operation(self, request, pk=None):
        cluster = self._cluster(request, pk, "explore_secret_operations")
        data = self._serializer(ExplorerExecuteSerializer, request, cluster)
        raw_request = getattr(request, "_request", request)
        raw_request.sensitive_post_parameters = "__ALL__"
        try:
            backend, document, operation, path = self._prepare_explorer_execution(request, cluster, data)
            log_administration(
                cluster,
                request.user,
                action="secret-operation-authorized",
                operation_id=operation.operation_id,
                risk_level=operation.risk_level,
                method=operation.method,
                path_template=operation.path_template,
                reason=data["reason"],
                capability_digest=document.digest,
                outcome="authorized",
                success=True,
                status_code=202,
                message="Authorized a classified mounted OpenBao operation.",
                request=request,
                require_durable=True,
            )
            result = backend.execute_mounted_operation(operation.method, path, query=data["query"], body=data["body"])
        except CapabilitySchemaError as exc:
            raise ValidationError(str(exc)) from None
        except OpenBaoMutationUnknown:
            self._record_unknown(
                cluster,
                request,
                operation.operation_id,
                risk=operation.risk_level,
                method=operation.method,
                path=operation.path_template,
                digest=document.digest,
                reason=data["reason"],
            )
            return self._unknown_mutation_response()
        except (AdministrationAuditError, OpenBaoError) as exc:
            self._backend_failure(
                request,
                cluster,
                "secret-operation-execute",
                exc,
                reason=data["reason"],
                risk_level=operation.risk_level if "operation" in locals() else "write",
            )
        audit_complete = True
        try:
            self._audit(
                cluster,
                request,
                operation.operation_id,
                risk=operation.risk_level,
                method=operation.method,
                path=operation.path_template,
                digest=document.digest,
                reason=data["reason"],
            )
        except AdministrationAuditError:
            audit_complete = False
        response = self._mutation_response(
            {"operation": operation.as_dict(), "data": result},
            audit_complete=audit_complete,
        )
        return _no_store(response)
