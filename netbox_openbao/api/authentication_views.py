"""Fixed REST actions for OpenBao 2.6.2 authentication and MFA administration."""

from __future__ import annotations

import secrets
from hashlib import sha256
from urllib.parse import quote, urlsplit
from uuid import UUID

from django.core import signing
from django.db import DatabaseError
from django.views.decorators.debug import sensitive_variables
from packaging.version import InvalidVersion, Version
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from netbox_openbao.administration import get_administration_backend
from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.administration.authentication import (
    AUTH_CONFIG_FIELDS,
    MFA_ENFORCEMENT_FIELDS,
    auth_mount,
    resource_spec,
)
from netbox_openbao.administration.schema import CapabilitySchemaError
from netbox_openbao.backends.exceptions import (
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoMutationUnknown,
    OpenBaoUnavailable,
)

from .authentication_serializers import (
    AppRoleRoleIDSerializer,
    AppRoleSecretIDSerializer,
    AuthenticationLoginSerializer,
    AuthResourceRequestSerializer,
    ConfirmAuthenticationActionSerializer,
    EnableAuthMethodSerializer,
    MFAValidateSerializer,
    OIDCPollSerializer,
    OIDCStartSerializer,
    RemountAuthMethodSerializer,
    ReviewedPayloadSerializer,
    SecretIDAccessorSerializer,
    TokenOperationSerializer,
    TOTPSetupSelfResetSerializer,
    TOTPSetupSelfSerializer,
    TuneAuthMethodSerializer,
    mfa_method_fields,
)
from .permissions import ClusterActionPermissions

OIDC_ENVELOPE_SALT = "netbox_openbao.oidc.direct.v1"
OIDC_ENVELOPE_MAX_AGE = 300

AUTH_RESOURCE_OPERATION_IDS = {
    "token-roles": {
        "list": "token-list-roles",
        "read": "token-read-role",
        "write": "token-write-role",
        "delete": "token-delete-role",
    },
    "userpass-users": {
        "list": "userpass-list-users",
        "read": "userpass-read-user",
        "write": "userpass-write-user",
        "delete": "userpass-delete-user",
    },
    "approle-roles": {
        "list": "app-role-list-roles",
        "read": "app-role-read-role",
        "write": "app-role-write-role",
        "delete": "app-role-delete-role",
    },
    "kubernetes-roles": {
        "list": "kubernetes-list-auth-roles",
        "read": "kubernetes-read-auth-role",
        "write": "kubernetes-write-auth-role",
        "delete": "kubernetes-delete-auth-role",
    },
    "jwt-roles": {
        "list": "jwt-list-roles",
        "read": "jwt-read-role",
        "write": "jwt-write-role",
        "delete": "jwt-delete-role",
    },
    "ldap-groups": {
        "list": "ldap-list-groups",
        "read": "ldap-read-group",
        "write": "ldap-write-group",
        "delete": "ldap-delete-group",
    },
    "ldap-users": {
        "list": "ldap-list-users",
        "read": "ldap-read-user",
        "write": "ldap-write-user",
        "delete": "ldap-delete-user",
    },
    "radius-users": {
        "list": "radius-list-users",
        "read": "radius-read-user",
        "write": "radius-write-user",
        "delete": "radius-delete-user",
    },
    "certificates": {
        "list": "cert-list-certificates",
        "read": "cert-read-certificate",
        "write": "cert-write-certificate",
        "delete": "cert-delete-certificate",
    },
    "certificate-crls": {
        "list": "cert-list-crls",
        "read": "cert-read-crl",
        "write": "cert-write-crl",
        "delete": "cert-delete-crl",
    },
}

AUTH_CONFIG_OPERATION_IDS = {
    "cert": ("cert-read-configuration", "cert-configure"),
    "jwt": ("jwt-read-configuration", "jwt-configure"),
    "oidc": ("jwt-read-configuration", "jwt-configure"),
    "kubernetes": ("kubernetes-read-auth-configuration", "kubernetes-configure-auth"),
    "ldap": ("ldap-read-auth-configuration", "ldap-configure-auth"),
    "radius": ("radius-read-configuration", "radius-configure"),
}

LOGIN_OPERATION_IDS = {
    "token": "token-look-up-self-get",
    "userpass": "userpass-login",
    "ldap": "ldap-login",
    "radius": "radius-login-with-username",
    "jwt": "jwt-login",
    "approle": "app-role-login",
    "kubernetes": "kubernetes-login",
}

TOKEN_OPERATION_IDS = {
    "lookup-self": "token-look-up-self-get",
    "renew-self": "token-renew-self",
    "revoke-self": "token-revoke-self",
    "lookup-accessor": "token-look-up-by-accessor",
    "renew-accessor": "token-renew-accessor",
    "revoke-accessor": "token-revoke-accessor",
}

TOKEN_OPERATION_PATHS = {
    "lookup-self": "/auth/token/lookup-self",
    "renew-self": "/auth/token/renew-self",
    "revoke-self": "/auth/token/revoke-self",
    "lookup-accessor": "/auth/token/lookup-accessor",
    "renew-accessor": "/auth/token/renew-accessor",
    "revoke-accessor": "/auth/token/revoke-accessor",
}


def _no_store(response):
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


def _hash_challenge(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _result_dict(result):
    return result.as_dict() if hasattr(result, "as_dict") else result


def _canonical_uuid(value: str, field_name: str) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise DRFValidationError({field_name: "Enter a canonical UUID."}) from None
    canonical = str(parsed)
    if value.lower() != canonical:
        raise DRFValidationError({field_name: "Enter a canonical UUID."})
    return canonical


def _namespace_callback_path(namespace: str) -> str:
    if not namespace:
        return ""
    normalized = namespace.strip("/")
    if not normalized:
        raise DRFValidationError("The OpenBao namespace cannot be represented in an OIDC callback URL.")
    segments = normalized.split("/")
    if not segments or any(not segment or segment in {".", ".."} for segment in segments):
        raise DRFValidationError("The OpenBao namespace cannot be represented in an OIDC callback URL.")
    return "/".join(quote(segment, safe="-._~") for segment in segments) + "/"


class AuthenticationAdministrationMixin:
    """Authentication actions mixed into the cluster model viewset."""

    def _prepare_auth_operation(self, cluster, operation_id, required_operation_ids=()):
        backend = get_administration_backend(cluster)
        seal = backend.seal_status()
        self._require_baseline(seal)
        if not seal.initialized or seal.sealed:
            raise OpenBaoConflict("The OpenBao cluster is not ready for authentication administration.")
        document = backend.discover_capabilities()
        try:
            version = Version(document.product_version)
        except InvalidVersion:
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.") from None
        if version < Version("2.6.2") or version.release[:2] != (2, 6):
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.")
        expected = {operation_id, *required_operation_ids}
        discovered = {operation.operation_id for operation in document.operations}
        if not expected <= discovered:
            raise OpenBaoConflict("OpenBao does not advertise the reviewed operation.")
        return backend, document.digest

    @staticmethod
    def _mounted_method(backend, mount_path):
        try:
            return auth_mount(backend.list_auth_methods(), mount_path)
        except CapabilitySchemaError:
            raise OpenBaoConflict("The selected auth mount is unavailable.") from None

    def _resolve_auth_mount(self, request, cluster, mount_path):
        """Resolve a mount only after the reviewed list capability is proven."""
        try:
            backend, digest = self._prepare_auth_operation(cluster, "auth-list-enabled-methods")
            mount = self._mounted_method(backend, mount_path)
            log_administration(
                cluster,
                request.user,
                action="resolve-auth-mount",
                operation_id="auth-list-enabled-methods",
                risk_level="read",
                method="GET",
                path_template="/sys/auth",
                capability_digest=digest,
                success=True,
                status_code=200,
                message="Resolved an auth mount through the reviewed mount registry.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "resolve-auth-mount", exc, risk_level="read")
        return mount

    def _auth_read(self, request, cluster, *, action_name, operation_id, path_template, producer, method="GET"):
        try:
            backend, digest = self._prepare_auth_operation(cluster, operation_id)
            payload = producer(backend)
            log_administration(
                cluster,
                request.user,
                action=action_name,
                operation_id=operation_id,
                risk_level="read",
                method=method,
                path_template=path_template,
                capability_digest=digest,
                success=True,
                status_code=200,
                message="Read reviewed authentication administration metadata.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, action_name, exc, risk_level="read")
        return _no_store(Response(payload))

    @staticmethod
    def _unknown_mutation_response():
        response = _no_store(
            Response(
                {
                    "outcome": "unknown",
                    "audit_status": "preflight-only",
                    "message": "OpenBao may have accepted the request. Do not retry; verify current state first.",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        )
        response["X-OpenBao-Operation-Outcome"] = "unknown"
        response["X-OpenBao-Audit-Status"] = "preflight-only"
        return response

    @sensitive_variables()
    def _auth_mutation(
        self,
        request,
        cluster,
        *,
        action_name,
        operation_id,
        path_template,
        reason,
        risk_level,
        producer,
        status_code=200,
        method="POST",
        required_operation_ids=(),
    ):
        raw_request = getattr(request, "_request", request)
        raw_request.sensitive_post_parameters = "__ALL__"
        try:
            backend, digest = self._prepare_auth_operation(cluster, operation_id, required_operation_ids)
            log_administration(
                cluster,
                request.user,
                action=f"{action_name}-authorized",
                operation_id=operation_id,
                risk_level=risk_level,
                method=method,
                path_template=path_template,
                reason=reason,
                capability_digest=digest,
                outcome="authorized",
                success=True,
                message="Authorized a reviewed authentication administration operation.",
                request=request,
                require_durable=True,
            )
            payload = producer(backend)
        except OpenBaoMutationUnknown:
            try:
                log_administration(
                    cluster,
                    request.user,
                    action=f"{action_name}-outcome-unknown",
                    operation_id=operation_id,
                    risk_level=risk_level,
                    method=method,
                    path_template=path_template,
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
            return self._unknown_mutation_response()
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, action_name, exc, reason=reason, risk_level=risk_level)
        except Exception:
            self._backend_failure(
                request,
                cluster,
                action_name,
                OpenBaoUnavailable("OpenBao authentication administration failed."),
                reason=reason,
                risk_level=risk_level,
            )
        audit_complete = True
        try:
            log_administration(
                cluster,
                request.user,
                action=action_name,
                operation_id=operation_id,
                risk_level=risk_level,
                method=method,
                path_template=path_template,
                reason=reason,
                capability_digest=digest,
                success=True,
                status_code=status_code,
                message="Completed a reviewed authentication administration operation.",
                request=request,
            )
        except AdministrationAuditError:
            audit_complete = False
        return self._mutation_response(payload or {}, status_code=status_code, audit_complete=audit_complete)

    @action(
        detail=True,
        methods=["get", "post"],
        url_path="auth-methods",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def auth_methods(self, request, pk=None):
        if request.method == "GET":
            cluster = self._cluster(request, pk, "view_authentication")
            return self._auth_read(
                request,
                cluster,
                action_name="list-auth-methods",
                operation_id="auth-list-enabled-methods",
                path_template="/sys/auth",
                producer=lambda backend: {"auth_methods": [item.as_dict() for item in backend.list_auth_methods()]},
            )
        cluster = self._cluster(request, pk, "manage_auth_methods")
        serializer = EnableAuthMethodSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mount_path = serializer.validated_data["mount_path"]
        method_type = serializer.validated_data["method_type"]
        reason = serializer.validated_data["reason"]
        return self._auth_mutation(
            request,
            cluster,
            action_name="enable-auth-method",
            operation_id="auth-enable-method",
            path_template="/sys/auth/{path}",
            reason=reason,
            risk_level="write",
            producer=lambda backend: (
                backend.enable_auth_method(mount_path, serializer.openbao_payload())
                or {"mount_path": mount_path, "method_type": method_type}
            ),
            status_code=status.HTTP_201_CREATED,
        )

    @action(
        detail=True,
        methods=["get", "post", "delete"],
        url_path=r"auth-methods/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def auth_method(self, request, pk=None, mount_path=""):
        if request.method == "GET":
            cluster = self._cluster(request, pk, "view_authentication")
            return self._auth_read(
                request,
                cluster,
                action_name="read-auth-method",
                operation_id="auth-read-configuration",
                path_template="/sys/auth/{path}",
                producer=lambda backend: backend.read_auth_method(mount_path),
            )
        if request.method == "POST":
            cluster = self._cluster(request, pk, "manage_auth_methods")
            serializer = TuneAuthMethodSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            return self._auth_mutation(
                request,
                cluster,
                action_name="tune-auth-method",
                operation_id="auth-tune-configuration-parameters",
                path_template="/sys/auth/{path}/tune",
                reason=serializer.validated_data["reason"],
                risk_level="write",
                producer=lambda backend: (
                    backend.tune_auth_method(mount_path, serializer.openbao_payload()) or {"mount_path": mount_path}
                ),
            )
        cluster = self._cluster(request, pk, "disable_auth_methods")
        expected = f"DISABLE AUTH {mount_path} ON {cluster.slug}"
        serializer = ConfirmAuthenticationActionSerializer(
            data=request.data, context={"expected_confirmation": expected}
        )
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="disable-auth-method",
            operation_id="auth-disable-method",
            path_template="/sys/auth/{path}",
            reason=serializer.validated_data["reason"],
            risk_level="destructive",
            producer=lambda backend: backend.disable_auth_method(mount_path) or {"disabled": mount_path},
            method="DELETE",
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="auth-remount",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def auth_remount(self, request, pk=None):
        cluster = self._cluster(request, pk, "manage_auth_methods")
        serializer = RemountAuthMethodSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        return self._auth_mutation(
            request,
            cluster,
            action_name="remount-auth-method",
            operation_id="remount",
            path_template="/sys/remount",
            reason=data["reason"],
            risk_level="write",
            producer=lambda backend: backend.remount_auth_method(data["source"], data["destination"]),
            status_code=status.HTTP_202_ACCEPTED,
        )

    @action(
        detail=True,
        methods=["get"],
        url_path=r"auth-remount/(?P<migration_id>[0-9a-fA-F-]{36})",
    )
    def auth_remount_status(self, request, pk=None, migration_id=""):
        migration_id = _canonical_uuid(migration_id, "migration_id")
        cluster = self._cluster(request, pk, "view_authentication")
        return self._auth_read(
            request,
            cluster,
            action_name="read-auth-remount-status",
            operation_id="remount-status",
            path_template="/sys/remount/status/{migration_id}",
            producer=lambda backend: backend.remount_status(migration_id),
        )

    @action(
        detail=True,
        methods=["get", "post"],
        url_path=r"auth-config/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_config(self, request, pk=None, mount_path=""):
        permission = "view_authentication" if request.method == "GET" else "manage_auth_methods"
        cluster = self._cluster(request, pk, permission)
        try:
            method_type = self._resolve_auth_mount(request, cluster, mount_path).method_type
            operations = AUTH_CONFIG_OPERATION_IDS[method_type]
            fields = AUTH_CONFIG_FIELDS[method_type]
        except (CapabilitySchemaError, KeyError, OpenBaoError):
            raise DRFValidationError("This auth mount has no reviewed configuration contract.") from None
        if request.method == "GET":
            return self._auth_read(
                request,
                cluster,
                action_name="read-auth-config",
                operation_id=operations[0],
                path_template="/auth/{mount_path}/config",
                producer=lambda backend: backend.read_auth_config(mount_path),
            )
        serializer = ReviewedPayloadSerializer(data=request.data, context={"fields": fields})
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="write-auth-config",
            operation_id=operations[1],
            path_template="/auth/{mount_path}/config",
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: (
                backend.write_auth_config(mount_path, serializer.validated_data["payload"])
                or {"mount_path": mount_path, "method_type": method_type}
            ),
        )

    @action(
        detail=True,
        methods=["get", "post", "delete"],
        url_path=(
            r"auth-resources/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/"
            r"(?P<resource_key>[A-Za-z0-9-]{1,64})(?:/(?P<name>[A-Za-z0-9][A-Za-z0-9_.@-]{0,199}))?"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_resource(self, request, pk=None, mount_path="", resource_key="", name=None):
        operation = "list" if request.method == "GET" and not name else "read" if request.method == "GET" else "write"
        if request.method == "DELETE":
            operation = "delete"
        permission = {
            "list": "view_authentication",
            "read": "view_authentication",
            "write": "manage_auth_resources",
            "delete": "delete_auth_resources",
        }[operation]
        cluster = self._cluster(request, pk, permission)
        try:
            method_type = self._resolve_auth_mount(request, cluster, mount_path).method_type
            spec = resource_spec(resource_key, method_type, operation)
            operation_id = AUTH_RESOURCE_OPERATION_IDS[resource_key][operation]
        except (CapabilitySchemaError, KeyError, OpenBaoError):
            raise DRFValidationError("This auth resource operation is unsupported.") from None
        path_template = f"/auth/{{mount_path}}/{spec.item_suffix if name else spec.collection_suffix}"
        if operation in {"list", "read"}:
            return self._auth_read(
                request,
                cluster,
                action_name=f"{operation}-auth-resource",
                operation_id=operation_id,
                path_template=path_template,
                producer=lambda active: active.run_auth_resource(mount_path, spec, operation, name=name or ""),
                method="LIST" if operation == "list" else "GET",
            )
        if not name:
            raise DRFValidationError({"name": "A resource name is required."})
        if operation == "write":
            serializer = AuthResourceRequestSerializer(
                data=request.data,
                context={
                    "fields": spec.fields,
                    "resource_key": resource_key,
                    "method_type": method_type,
                },
            )
            serializer.is_valid(raise_exception=True)
            reason = serializer.validated_data["reason"]
            payload = serializer.validated_data["payload"]
        else:
            expected = f"DELETE AUTH RESOURCE {resource_key}/{name} ON {cluster.slug}"
            serializer = ConfirmAuthenticationActionSerializer(
                data=request.data, context={"expected_confirmation": expected}
            )
            serializer.is_valid(raise_exception=True)
            reason = serializer.validated_data["reason"]
            payload = None
        return self._auth_mutation(
            request,
            cluster,
            action_name=f"{operation}-auth-resource",
            operation_id=operation_id,
            path_template=path_template,
            reason=reason,
            risk_level="destructive" if operation == "delete" else spec.risk,
            producer=lambda active: (
                active.run_auth_resource(mount_path, spec, operation, name=name, payload=payload)
                or {"resource": resource_key, "name": name}
            ),
            method="DELETE" if operation == "delete" else "POST",
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=(
            r"auth-approle/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/"
            r"(?P<role_name>[A-Za-z0-9][A-Za-z0-9_.@-]{0,199})/secret-id"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def approle_secret_id(self, request, pk=None, mount_path="", role_name=""):
        cluster = self._cluster(request, pk, "issue_auth_material")
        if self._resolve_auth_mount(request, cluster, mount_path).method_type != "approle":
            raise DRFValidationError("The selected mount is not an AppRole mount.")
        serializer = AppRoleSecretIDSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="issue-approle-secret-id",
            operation_id="app-role-write-secret-id",
            path_template="/auth/{mount_path}/role/{role_name}/secret-id",
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: backend.issue_approle_secret_id(
                mount_path, role_name, serializer.openbao_payload()
            ).as_dict(),
            status_code=status.HTTP_201_CREATED,
        )

    @action(
        detail=True,
        methods=["get", "post"],
        url_path=(
            r"auth-approle/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/"
            r"(?P<role_name>[A-Za-z0-9][A-Za-z0-9_.@-]{0,199})/role-id"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def approle_role_id(self, request, pk=None, mount_path="", role_name=""):
        if request.method == "GET":
            cluster = self._cluster(request, pk, "view_authentication")
            if self._resolve_auth_mount(request, cluster, mount_path).method_type != "approle":
                raise DRFValidationError("The selected mount is not an AppRole mount.")
            return self._auth_read(
                request,
                cluster,
                action_name="read-approle-role-id",
                operation_id="app-role-read-role-id",
                path_template="/auth/{mount_path}/role/{role_name}/role-id",
                producer=lambda backend: backend.read_approle_role_id(mount_path, role_name),
            )
        cluster = self._cluster(request, pk, "manage_auth_resources")
        if self._resolve_auth_mount(request, cluster, mount_path).method_type != "approle":
            raise DRFValidationError("The selected mount is not an AppRole mount.")
        serializer = AppRoleRoleIDSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role_id = serializer.validated_data["role_id"]
        return self._auth_mutation(
            request,
            cluster,
            action_name="write-approle-role-id",
            operation_id="app-role-write-role-id",
            path_template="/auth/{mount_path}/role/{role_name}/role-id",
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: (
                backend.write_approle_role_id(mount_path, role_name, role_id) or {"role_name": role_name}
            ),
        )

    @action(
        detail=True,
        methods=["post", "delete"],
        url_path=(
            r"auth-approle/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/"
            r"(?P<role_name>[A-Za-z0-9][A-Za-z0-9_.@-]{0,199})/secret-id-accessor"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def approle_secret_id_accessor(self, request, pk=None, mount_path="", role_name=""):
        destructive = request.method == "DELETE"
        permission = "delete_auth_resources" if destructive else "view_authentication"
        cluster = self._cluster(request, pk, permission)
        if self._resolve_auth_mount(request, cluster, mount_path).method_type != "approle":
            raise DRFValidationError("The selected mount is not an AppRole mount.")
        expected = f"DESTROY APPROLE SECRET ID ON {cluster.slug}"
        serializer = SecretIDAccessorSerializer(
            data=request.data,
            context={"destructive": destructive, "expected_confirmation": expected},
        )
        serializer.is_valid(raise_exception=True)
        accessor = serializer.validated_data["accessor"]
        operation_id = (
            "app-role-destroy-secret-id-by-accessor" if destructive else "app-role-look-up-secret-id-by-accessor"
        )
        if destructive:

            def producer(backend):
                backend.destroy_approle_secret_id(mount_path, role_name, accessor)
                return {"destroyed": True}

        else:

            def producer(backend):
                return backend.lookup_approle_secret_id(mount_path, role_name, accessor)

        return self._auth_mutation(
            request,
            cluster,
            action_name="destroy-approle-secret-id" if destructive else "lookup-approle-secret-id",
            operation_id=operation_id,
            path_template=(
                "/auth/{mount_path}/role/{role_name}/secret-id-accessor/destroy"
                if destructive
                else "/auth/{mount_path}/role/{role_name}/secret-id-accessor/lookup"
            ),
            reason=serializer.validated_data["reason"],
            risk_level="destructive" if destructive else "sensitive",
            producer=producer,
            method="POST",
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-login/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_login(self, request, pk=None, mount_path=""):
        cluster = self._cluster(request, pk, "authenticate")
        serializer = AuthenticationLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        method_type = serializer.validated_data["method_type"]
        mounted_type = self._resolve_auth_mount(request, cluster, mount_path).method_type
        if method_type == "token":
            if mount_path != "token" or mounted_type != "token":
                raise DRFValidationError("The selected mount does not match the login method.")
        elif mounted_type != method_type:
            raise DRFValidationError("The selected mount does not match the login method.")
        path_template = {
            "token": "/auth/token/lookup-self",
            "userpass": "/auth/{mount_path}/login/{username}",
            "ldap": "/auth/{mount_path}/login/{username}",
            "radius": "/auth/{mount_path}/login/{username}",
            "jwt": "/auth/{mount_path}/login",
            "approle": "/auth/{mount_path}/login",
            "kubernetes": "/auth/{mount_path}/login",
        }[method_type]
        return self._auth_mutation(
            request,
            cluster,
            action_name="authenticate",
            operation_id=LOGIN_OPERATION_IDS[method_type],
            path_template=path_template,
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: (
                backend.authenticate(method_type, mount_path, serializer.openbao_payload()).as_dict()
                if method_type != "token"
                else backend.authenticate(method_type, mount_path, serializer.openbao_payload())
            ),
            method="GET" if method_type == "token" else "POST",
        )

    @staticmethod
    def _oidc_callback(cluster, mount_path):
        parsed = urlsplit(cluster.api_url)
        if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise DRFValidationError("OIDC direct callbacks require a secure OpenBao API URL.")
        namespace = _namespace_callback_path(cluster.namespace)
        return f"{cluster.api_url.rstrip('/')}/v1/{namespace}auth/{mount_path}/oidc/callback"

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-oidc/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/start",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_oidc_start(self, request, pk=None, mount_path=""):
        cluster = self._cluster(request, pk, "authenticate")
        serializer = OIDCStartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if self._resolve_auth_mount(request, cluster, mount_path).method_type not in {"jwt", "oidc"}:
            raise DRFValidationError("The selected mount does not support direct OIDC.")
        nonce = secrets.token_urlsafe(32)
        reason = serializer.validated_data["reason"]

        def start(backend):
            backend.read_direct_oidc_role(mount_path, serializer.validated_data["role"])
            result = backend.oidc_start(
                mount_path,
                serializer.validated_data["role"],
                self._oidc_callback(cluster, mount_path),
                nonce,
            )
            envelope = signing.dumps(
                {
                    "cluster": cluster.pk,
                    "user": request.user.pk,
                    "mount": mount_path,
                    "state": _hash_challenge(result.state),
                    "nonce": _hash_challenge(nonce),
                },
                salt=OIDC_ENVELOPE_SALT,
            )
            return {
                "auth_url": result.auth_url,
                "state": result.state,
                "client_nonce": nonce,
                "poll_interval": result.poll_interval,
                "envelope": envelope,
            }

        return self._auth_mutation(
            request,
            cluster,
            action_name="start-oidc-authentication",
            operation_id="jwt-oidc-request-authorization-url",
            path_template="/auth/{mount_path}/oidc/auth_url",
            reason=reason,
            risk_level="sensitive",
            producer=start,
            required_operation_ids=("jwt-read-role",),
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-oidc/(?P<mount_path>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})/poll",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_oidc_poll(self, request, pk=None, mount_path=""):
        cluster = self._cluster(request, pk, "authenticate")
        serializer = OIDCPollSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if self._resolve_auth_mount(request, cluster, mount_path).method_type not in {"jwt", "oidc"}:
            raise DRFValidationError("The selected mount does not support direct OIDC.")
        data = serializer.validated_data
        try:
            envelope = signing.loads(data["envelope"], salt=OIDC_ENVELOPE_SALT, max_age=OIDC_ENVELOPE_MAX_AGE)
        except signing.BadSignature:
            raise DRFValidationError("The OIDC polling envelope is invalid or expired.") from None
        expected = {
            "cluster": cluster.pk,
            "user": request.user.pk,
            "mount": mount_path,
            "state": _hash_challenge(data["state"]),
            "nonce": _hash_challenge(data["client_nonce"]),
        }
        if envelope != expected:
            raise DRFValidationError("The OIDC polling envelope is invalid or expired.")
        return self._auth_mutation(
            request,
            cluster,
            action_name="poll-oidc-authentication",
            operation_id="jwt-write-oidc-poll",
            path_template="/auth/{mount_path}/oidc/poll",
            reason=data["reason"],
            risk_level="sensitive",
            producer=lambda backend: backend.oidc_poll(mount_path, data["state"], data["client_nonce"]).as_dict(),
        )

    @action(
        detail=True,
        methods=["post"],
        url_path="auth-mfa/validate",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_validate(self, request, pk=None):
        cluster = self._cluster(request, pk, "authenticate")
        serializer = MFAValidateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        return self._auth_mutation(
            request,
            cluster,
            action_name="validate-mfa",
            operation_id="mfa-validate",
            path_template="/sys/mfa/validate",
            reason=data["reason"],
            risk_level="sensitive",
            producer=lambda backend: backend.validate_mfa(data["mfa_request_id"], data["mfa_payload"]).as_dict(),
        )

    @action(detail=True, methods=["get"], url_path="auth-mfa/methods")
    def auth_mfa_methods(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_authentication")
        return self._auth_read(
            request,
            cluster,
            action_name="list-mfa-methods",
            operation_id="mfa-list-methods",
            path_template="/identity/mfa/method",
            producer=lambda backend: backend.list_mfa_methods(),
            method="LIST",
        )

    @action(
        detail=True,
        methods=["get", "post", "delete"],
        url_path=(
            r"auth-mfa/methods/(?P<method_type>totp|duo|okta|pingid)/"
            r"(?P<method_id>[0-9a-fA-F-]{36})"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_method(self, request, pk=None, method_type="", method_id=""):
        method_id = _canonical_uuid(method_id, "method_id")
        if request.method == "GET":
            cluster = self._cluster(request, pk, "view_authentication")
            return self._auth_read(
                request,
                cluster,
                action_name="read-mfa-method",
                operation_id="mfa-read-method-configuration",
                path_template="/identity/mfa/method/{method_id}",
                producer=lambda backend: backend.read_mfa_method(method_id),
            )
        if request.method == "POST":
            cluster = self._cluster(request, pk, "manage_mfa")
            serializer = ReviewedPayloadSerializer(
                data=request.data, context={"fields": mfa_method_fields(method_type)}
            )
            serializer.is_valid(raise_exception=True)
            return self._auth_mutation(
                request,
                cluster,
                action_name="write-mfa-method",
                operation_id=f"mfa-configure-{method_type.replace('pingid', 'ping-id')}-method",
                path_template="/identity/mfa/method/{type}/{method_id}",
                reason=serializer.validated_data["reason"],
                risk_level="sensitive",
                producer=lambda backend: (
                    backend.write_mfa_method(method_type, serializer.validated_data["payload"], method_id=method_id)
                    or {"method_id": method_id, "method_type": method_type}
                ),
            )
        cluster = self._cluster(request, pk, "delete_mfa")
        expected = f"DELETE MFA METHOD {method_id} ON {cluster.slug}"
        serializer = ConfirmAuthenticationActionSerializer(
            data=request.data, context={"expected_confirmation": expected}
        )
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="delete-mfa-method",
            operation_id=f"mfa-delete-{method_type.replace('pingid', 'ping-id')}-method",
            path_template="/identity/mfa/method/{type}/{method_id}",
            reason=serializer.validated_data["reason"],
            risk_level="destructive",
            producer=lambda backend: backend.delete_mfa_method(method_type, method_id) or {"deleted": method_id},
            method="DELETE",
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-mfa/methods/(?P<method_type>totp|duo|okta|pingid)",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_method_create(self, request, pk=None, method_type=""):
        cluster = self._cluster(request, pk, "manage_mfa")
        serializer = ReviewedPayloadSerializer(data=request.data, context={"fields": mfa_method_fields(method_type)})
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="create-mfa-method",
            operation_id=f"mfa-configure-{method_type.replace('pingid', 'ping-id')}-method",
            path_template="/identity/mfa/method/{type}",
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: backend.write_mfa_method(method_type, serializer.validated_data["payload"]),
            status_code=status.HTTP_201_CREATED,
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-mfa/totp/(?P<method_id>[0-9a-fA-F-]{36})/self",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_totp_self(self, request, pk=None, method_id=""):
        method_id = _canonical_uuid(method_id, "method_id")
        cluster = self._cluster(request, pk, "authenticate")
        serializer = TOTPSetupSelfSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        return self._auth_mutation(
            request,
            cluster,
            action_name="generate-self-totp-setup",
            operation_id="mfa-generate-totp-secret",
            path_template="/identity/mfa/method/totp/generate",
            reason=serializer.validated_data["reason"],
            risk_level="sensitive",
            producer=lambda backend: backend.setup_totp(method_id, token=token).as_dict(),
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"auth-mfa/totp/(?P<method_id>[0-9a-fA-F-]{36})/self/reset",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_totp_self_reset(self, request, pk=None, method_id=""):
        method_id = _canonical_uuid(method_id, "method_id")
        cluster = self._cluster(request, pk, "authenticate")
        expected = f"RESET MY TOTP ON {cluster.slug}"
        serializer = TOTPSetupSelfResetSerializer(
            data=request.data,
            context={"expected_confirmation": expected},
        )
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        return self._auth_mutation(
            request,
            cluster,
            action_name="reset-self-totp-setup",
            operation_id="mfa-admin-destroy-totp-secret",
            required_operation_ids=("token-look-up-self-get",),
            path_template="/identity/mfa/method/totp/admin-destroy",
            reason=serializer.validated_data["reason"],
            risk_level="destructive",
            producer=lambda backend: backend.reset_totp_setup(method_id, token),
        )

    @action(
        detail=True,
        methods=["post", "delete"],
        url_path=(
            r"auth-mfa/totp/(?P<method_id>[0-9a-fA-F-]{36})/"
            r"entities/(?P<entity_id>[0-9a-fA-F-]{36})"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_mfa_totp(self, request, pk=None, method_id="", entity_id=""):
        method_id = _canonical_uuid(method_id, "method_id")
        entity_id = _canonical_uuid(entity_id, "entity_id")
        destructive = request.method == "DELETE"
        cluster = self._cluster(request, pk, "delete_mfa" if destructive else "manage_mfa")
        if destructive:
            expected = f"DESTROY TOTP FOR {entity_id} ON {cluster.slug}"
            serializer = ConfirmAuthenticationActionSerializer(
                data=request.data, context={"expected_confirmation": expected}
            )
        else:
            from .authentication_serializers import ReasonSerializer

            serializer = ReasonSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        operation_id = "mfa-admin-destroy-totp-secret" if destructive else "mfa-admin-generate-totp-secret"
        if destructive:

            def producer(backend):
                backend.destroy_totp_setup(method_id, entity_id)
                return {"destroyed": True}

        else:

            def producer(backend):
                return backend.setup_totp(method_id, entity_id=entity_id, administrator=True).as_dict()

        return self._auth_mutation(
            request,
            cluster,
            action_name="destroy-totp-setup" if destructive else "generate-totp-setup",
            operation_id=operation_id,
            path_template=(
                "/identity/mfa/method/totp/admin-destroy" if destructive else "/identity/mfa/method/totp/admin-generate"
            ),
            reason=serializer.validated_data["reason"],
            risk_level="destructive" if destructive else "sensitive",
            producer=producer,
        )

    @action(detail=True, methods=["get"], url_path="auth-mfa/enforcements")
    def auth_mfa_enforcements(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_authentication")
        return self._auth_read(
            request,
            cluster,
            action_name="list-mfa-enforcements",
            operation_id="mfa-list-login-enforcements",
            path_template="/identity/mfa/login-enforcement",
            producer=lambda backend: backend.list_mfa_enforcements(),
            method="LIST",
        )

    @action(
        detail=True,
        methods=["get", "post", "delete"],
        url_path=r"auth-mfa/enforcements/(?P<name>[A-Za-z0-9][A-Za-z0-9_.@-]{0,199})",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def auth_mfa_enforcement(self, request, pk=None, name=""):
        if request.method == "GET":
            cluster = self._cluster(request, pk, "view_authentication")
            return self._auth_read(
                request,
                cluster,
                action_name="read-mfa-enforcement",
                operation_id="mfa-read-login-enforcement",
                path_template="/identity/mfa/login-enforcement/{name}",
                producer=lambda backend: backend.read_mfa_enforcement(name),
            )
        if request.method == "POST":
            cluster = self._cluster(request, pk, "manage_mfa")
            serializer = ReviewedPayloadSerializer(data=request.data, context={"fields": MFA_ENFORCEMENT_FIELDS})
            serializer.is_valid(raise_exception=True)
            return self._auth_mutation(
                request,
                cluster,
                action_name="write-mfa-enforcement",
                operation_id="mfa-write-login-enforcement",
                path_template="/identity/mfa/login-enforcement/{name}",
                reason=serializer.validated_data["reason"],
                risk_level="write",
                producer=lambda backend: (
                    backend.write_mfa_enforcement(name, serializer.validated_data["payload"]) or {"name": name}
                ),
            )
        cluster = self._cluster(request, pk, "delete_mfa")
        expected = f"DELETE MFA ENFORCEMENT {name} ON {cluster.slug}"
        serializer = ConfirmAuthenticationActionSerializer(
            data=request.data, context={"expected_confirmation": expected}
        )
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name="delete-mfa-enforcement",
            operation_id="mfa-delete-login-enforcement",
            path_template="/identity/mfa/login-enforcement/{name}",
            reason=serializer.validated_data["reason"],
            risk_level="destructive",
            producer=lambda backend: backend.delete_mfa_enforcement(name) or {"deleted": name},
            method="DELETE",
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=(
            r"auth-tokens/(?P<operation>lookup-self|renew-self|revoke-self|lookup-accessor|"
            r"renew-accessor|revoke-accessor)"
        ),
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    @sensitive_variables()
    def auth_token(self, request, pk=None, operation=""):
        destructive = operation.startswith("revoke")
        permission = "revoke_tokens" if destructive else "manage_tokens"
        cluster = self._cluster(request, pk, permission)
        expected = f"REVOKE TOKEN ON {cluster.slug}"
        serializer = TokenOperationSerializer(
            data=request.data,
            context={"operation": operation, "expected_confirmation": expected},
        )
        serializer.is_valid(raise_exception=True)
        return self._auth_mutation(
            request,
            cluster,
            action_name=operation,
            operation_id=TOKEN_OPERATION_IDS[operation],
            path_template=TOKEN_OPERATION_PATHS[operation],
            reason=serializer.validated_data["reason"],
            risk_level="destructive" if destructive else "sensitive",
            producer=lambda backend: _result_dict(backend.token_operation(operation, serializer.openbao_payload())),
            method="GET" if operation == "lookup-self" else "POST",
        )
