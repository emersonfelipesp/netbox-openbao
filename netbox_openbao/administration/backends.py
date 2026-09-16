"""Administrative transport boundary for OpenBao discovery and cluster state."""

import json
from abc import ABC, abstractmethod

from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends.broker import BrokerBackend
from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoMutationUnknown,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import BackendChoices

from .access import normalize_access_response
from .authentication import (
    AuthenticationResult,
    AuthMount,
    AuthResourceSpec,
    OIDCStartResult,
    SecretIDResult,
    TOTPSetupResult,
    normalize_auth_mounts,
    normalize_authentication_result,
    normalize_mount_path,
    normalize_oidc_start,
    normalize_public_auth_data,
    normalize_resource_name,
    normalize_role_id,
    normalize_secret_id_result,
    normalize_totp_setup_result,
    validate_direct_oidc_role,
)
from .cluster import (
    MAX_CLUSTER_JSON_BYTES,
    MAX_SNAPSHOT_BYTES,
    BoundedSnapshotReader,
    HAStatus,
    InitializationResult,
    LeaderStatus,
    RaftConfiguration,
    SealStatus,
    SnapshotDownload,
    normalize_ha_status,
    normalize_initialization_result,
    normalize_leader_status,
    normalize_raft_configuration,
    normalize_seal_status,
)
from .engines import (
    SecretEngineMount,
    normalize_migration_id,
    normalize_secret_engine_mounts,
)
from .engines import (
    normalize_mount_path as normalize_engine_mount_path,
)
from .schema import MAX_DOCUMENT_BYTES, CapabilityDocument, CapabilitySchemaError, normalize_openapi_document

__all__ = ("AdministrationBackend", "get_administration_backend")


class AdministrationBackend(ABC):
    """Reviewed administration contract shared by direct and broker transports."""

    def __init__(self, cluster):
        self.cluster = cluster

    @abstractmethod
    def health(self) -> dict:
        """Return safe health metadata."""

    @abstractmethod
    def discover_capabilities(self) -> CapabilityDocument:
        """Return normalized runtime OpenAPI metadata or a fixed safe error."""

    def list_secret_engines(self) -> tuple[SecretEngineMount, ...]:
        raise self._unsupported()

    def read_secret_engine(self, mount_path: str) -> dict:
        del mount_path
        raise self._unsupported()

    def read_secret_engine_tuning(self, mount_path: str) -> dict:
        del mount_path
        raise self._unsupported()

    def enable_secret_engine(self, mount_path: str, payload: dict) -> None:
        del mount_path, payload
        raise self._unsupported()

    def tune_secret_engine(self, mount_path: str, payload: dict) -> None:
        del mount_path, payload
        raise self._unsupported()

    def remount_secret_engine(self, source: str, destination: str) -> dict:
        del source, destination
        raise self._unsupported()

    def secret_engine_remount_status(self, migration_id: str) -> dict:
        del migration_id
        raise self._unsupported()

    def disable_secret_engine(self, mount_path: str) -> None:
        del mount_path
        raise self._unsupported()

    def execute_mounted_operation(
        self,
        method: str,
        path: str,
        *,
        query: dict,
        body: dict,
    ) -> dict:
        del method, path, query, body
        raise self._unsupported()

    def initialization_status(self) -> bool:
        raise self._unsupported()

    def seal_status(self) -> SealStatus:
        raise self._unsupported()

    def leader_status(self) -> LeaderStatus:
        raise self._unsupported()

    def ha_status(self) -> HAStatus:
        raise self._unsupported()

    def raft_configuration(self) -> RaftConfiguration:
        raise self._unsupported()

    def initialize(self, payload: dict) -> InitializationResult:
        del payload
        raise self._unsupported()

    def unseal(self, *, key: str = "", reset: bool = False, migrate: bool = False) -> SealStatus:
        del key, reset, migrate
        raise self._unsupported()

    def seal(self) -> None:
        raise self._unsupported()

    def remove_raft_peer(self, server_id: str) -> None:
        del server_id
        raise self._unsupported()

    def download_raft_snapshot(self) -> SnapshotDownload:
        raise self._unsupported()

    def restore_raft_snapshot(self, stream, size: int, *, force: bool = False) -> None:
        del stream, size, force
        raise self._unsupported()

    def list_auth_methods(self) -> tuple[AuthMount, ...]:
        raise self._unsupported()

    def read_auth_method(self, mount_path: str) -> dict:
        del mount_path
        raise self._unsupported()

    def enable_auth_method(self, mount_path: str, payload: dict) -> None:
        del mount_path, payload
        raise self._unsupported()

    def tune_auth_method(self, mount_path: str, payload: dict) -> None:
        del mount_path, payload
        raise self._unsupported()

    def remount_auth_method(self, source: str, destination: str) -> dict:
        del source, destination
        raise self._unsupported()

    def remount_status(self, migration_id: str) -> dict:
        del migration_id
        raise self._unsupported()

    def disable_auth_method(self, mount_path: str) -> None:
        del mount_path
        raise self._unsupported()

    def read_auth_config(self, mount_path: str) -> dict:
        del mount_path
        raise self._unsupported()

    def write_auth_config(self, mount_path: str, payload: dict) -> None:
        del mount_path, payload
        raise self._unsupported()

    def run_auth_resource(
        self,
        mount_path: str,
        spec: AuthResourceSpec,
        operation: str,
        *,
        name: str = "",
        payload: dict | None = None,
    ) -> dict:
        del mount_path, spec, operation, name, payload
        raise self._unsupported()

    def issue_approle_secret_id(self, mount_path: str, role_name: str, payload: dict) -> SecretIDResult:
        del mount_path, role_name, payload
        raise self._unsupported()

    def read_approle_role_id(self, mount_path: str, role_name: str) -> dict:
        del mount_path, role_name
        raise self._unsupported()

    def write_approle_role_id(self, mount_path: str, role_name: str, role_id: str) -> None:
        del mount_path, role_name, role_id
        raise self._unsupported()

    def lookup_approle_secret_id(self, mount_path: str, role_name: str, accessor: str) -> dict:
        del mount_path, role_name, accessor
        raise self._unsupported()

    def destroy_approle_secret_id(self, mount_path: str, role_name: str, accessor: str) -> None:
        del mount_path, role_name, accessor
        raise self._unsupported()

    def authenticate(self, method_type: str, mount_path: str, payload: dict) -> AuthenticationResult | dict:
        del method_type, mount_path, payload
        raise self._unsupported()

    def oidc_start(self, mount_path: str, role: str, redirect_uri: str, client_nonce: str) -> OIDCStartResult:
        del mount_path, role, redirect_uri, client_nonce
        raise self._unsupported()

    def oidc_poll(self, mount_path: str, state: str, client_nonce: str) -> AuthenticationResult:
        del mount_path, state, client_nonce
        raise self._unsupported()

    def read_direct_oidc_role(self, mount_path: str, role: str) -> dict:
        del mount_path, role
        raise self._unsupported()

    def validate_mfa(self, request_id: str, payload: dict[str, list[str]]) -> AuthenticationResult:
        del request_id, payload
        raise self._unsupported()

    def list_mfa_methods(self) -> dict:
        raise self._unsupported()

    def read_mfa_method(self, method_id: str) -> dict:
        del method_id
        raise self._unsupported()

    def write_mfa_method(self, method_type: str, payload: dict, *, method_id: str = "") -> dict:
        del method_type, payload, method_id
        raise self._unsupported()

    def delete_mfa_method(self, method_type: str, method_id: str) -> None:
        del method_type, method_id
        raise self._unsupported()

    def setup_totp(
        self,
        method_id: str,
        *,
        entity_id: str = "",
        administrator: bool = False,
        token: str = "",
    ) -> TOTPSetupResult:
        del method_id, entity_id, administrator, token
        raise self._unsupported()

    def destroy_totp_setup(self, method_id: str, entity_id: str) -> None:
        del method_id, entity_id
        raise self._unsupported()

    def reset_totp_setup(self, method_id: str, token: str) -> dict:
        del method_id, token
        raise self._unsupported()

    def list_mfa_enforcements(self) -> dict:
        raise self._unsupported()

    def read_mfa_enforcement(self, name: str) -> dict:
        del name
        raise self._unsupported()

    def write_mfa_enforcement(self, name: str, payload: dict) -> None:
        del name, payload
        raise self._unsupported()

    def delete_mfa_enforcement(self, name: str) -> None:
        del name
        raise self._unsupported()

    def token_operation(self, operation: str, payload: dict) -> AuthenticationResult | dict | None:
        del operation, payload
        raise self._unsupported()

    def execute_access_operation(
        self,
        method: str,
        path: str,
        *,
        payload: dict,
        material: bool = False,
    ) -> dict:
        del method, path, payload, material
        raise self._unsupported()

    @staticmethod
    def _unsupported() -> BackendConfigurationError:
        return BackendConfigurationError(
            "The configured transport does not advertise the required administrative contract."
        )


class DirectAdministrationBackend(AdministrationBackend):
    """OpenBao/Vault-compatible direct administrative discovery."""

    def __init__(self, cluster):
        super().__init__(cluster)
        self.backend = OpenBaoBackend(cluster)

    def health(self) -> dict:
        return self.backend.health()

    @property
    def _verify(self):
        return self.cluster.ca_cert_path or self.cluster.tls_verify

    def _headers(self, *, authenticated: bool, token: str = "") -> dict[str, str]:
        headers = {"X-Vault-Request": "true"}
        if self.cluster.namespace:
            headers["X-Vault-Namespace"] = self.cluster.namespace
        if authenticated and not token:
            token = self.backend._get_client().token
        if token:
            headers["X-Vault-Token"] = token
        return headers

    @sensitive_variables()
    def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        expected: tuple[int, ...],
        token: str = "",
        **kwargs,
    ):
        extra_headers = kwargs.pop("headers", None) or {}
        timeout = kwargs.pop("timeout", 30)
        headers = self._headers(authenticated=authenticated, token=token)
        headers.update(extra_headers)
        try:
            response = self.backend._get_session().request(
                method,
                f"{self.cluster.api_url.rstrip('/')}/v1{path}",
                headers=headers,
                verify=self._verify,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                **kwargs,
            )
        except OpenBaoError:
            raise
        except Exception:
            if method.upper() not in {"GET", "HEAD", "LIST", "OPTIONS"}:
                raise OpenBaoMutationUnknown() from None
            raise OpenBaoUnavailable("OpenBao administration request failed.") from None
        if response.status_code in expected:
            return response
        response.close()
        if response.status_code in (401, 403):
            raise OpenBaoAuthError("OpenBao rejected the administrative request.", response.status_code)
        if response.status_code == 404:
            raise OpenBaoNotFound("OpenBao does not support this administrative operation.", 404)
        if response.status_code in (400, 409, 412):
            raise OpenBaoConflict("OpenBao refused the administrative state transition.", response.status_code)
        if response.status_code >= 500 and method.upper() not in {"GET", "HEAD", "LIST", "OPTIONS"}:
            raise OpenBaoMutationUnknown()
        raise OpenBaoUnavailable("OpenBao administration request failed.", response.status_code)

    @sensitive_variables()
    def _request_json(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        expected: tuple[int, ...] = (200,),
        **kwargs,
    ) -> dict:
        response = self._request(method, path, authenticated=authenticated, expected=expected, **kwargs)
        try:
            return self._response_json(response)
        except OpenBaoUnavailable:
            if method.upper() not in {"GET", "HEAD", "LIST", "OPTIONS"}:
                raise OpenBaoMutationUnknown() from None
            raise

    @staticmethod
    def _response_json(response) -> dict:
        try:
            body = response.raw.read(MAX_CLUSTER_JSON_BYTES + 1, decode_content=True)
        except Exception:
            raise OpenBaoUnavailable("OpenBao returned an invalid administrative response.") from None
        finally:
            response.close()
        if len(body) > MAX_CLUSTER_JSON_BYTES:
            raise OpenBaoUnavailable("OpenBao administrative response is too large.")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoUnavailable("OpenBao returned an invalid administrative response.") from None
        if not isinstance(payload, dict):
            raise OpenBaoUnavailable("OpenBao returned an invalid administrative response.")
        return payload

    def _request_list_json(self, path: str) -> dict:
        response = self._request("LIST", path, authenticated=True, expected=(200, 404))
        if response.status_code == 404:
            response.close()
            return {"data": {"keys": [], "key_info": {}}}
        return self._response_json(response)

    def discover_capabilities(self) -> CapabilityDocument:
        response = self._request(
            "GET",
            "/sys/internal/specs/openapi",
            authenticated=True,
            expected=(200,),
            params={"generic_mount_paths": "true"},
        )
        try:
            body = response.raw.read(MAX_DOCUMENT_BYTES + 1, decode_content=True)
        except Exception:
            raise OpenBaoUnavailable("OpenBao returned an invalid capability document.") from None
        finally:
            response.close()

        if len(body) > MAX_DOCUMENT_BYTES:
            raise OpenBaoUnavailable("OpenBao capability discovery response is too large.")
        try:
            document = json.loads(body)
            return normalize_openapi_document(document)
        except (CapabilitySchemaError, json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoUnavailable("OpenBao returned an invalid capability document.") from None

    def initialization_status(self) -> bool:
        payload = self._request_json("GET", "/sys/init", authenticated=False)
        initialized = payload.get("initialized")
        if not isinstance(initialized, bool):
            raise OpenBaoUnavailable("OpenBao returned an invalid initialization status.")
        return initialized

    def seal_status(self) -> SealStatus:
        payload = self._request_json("GET", "/sys/seal-status", authenticated=False)
        return self._normalize(normalize_seal_status, payload)

    def leader_status(self) -> LeaderStatus:
        payload = self._request_json("GET", "/sys/leader", authenticated=True)
        return self._normalize(normalize_leader_status, payload)

    def ha_status(self) -> HAStatus:
        payload = self._request_json("GET", "/sys/ha-status", authenticated=True)
        return self._normalize(normalize_ha_status, payload)

    def raft_configuration(self) -> RaftConfiguration:
        payload = self._request_json("GET", "/sys/storage/raft/configuration", authenticated=True)
        return self._normalize(normalize_raft_configuration, payload)

    def initialize(self, payload: dict) -> InitializationResult:
        result = self._request_json("POST", "/sys/init", authenticated=False, json=payload)
        return self._normalize(normalize_initialization_result, result)

    def unseal(self, *, key: str = "", reset: bool = False, migrate: bool = False) -> SealStatus:
        payload = {"reset": reset, "migrate": migrate}
        if key:
            payload["key"] = key
        result = self._request_json("POST", "/sys/unseal", authenticated=False, json=payload)
        return self._normalize(normalize_seal_status, result)

    def seal(self) -> None:
        response = self._request("POST", "/sys/seal", authenticated=True, expected=(200, 204))
        response.close()

    def remove_raft_peer(self, server_id: str) -> None:
        response = self._request(
            "POST",
            "/sys/storage/raft/remove-peer",
            authenticated=True,
            expected=(200, 204),
            json={"server_id": server_id},
        )
        response.close()

    def download_raft_snapshot(self) -> SnapshotDownload:
        response = self._request(
            "GET",
            "/sys/storage/raft/snapshot",
            authenticated=True,
            expected=(200,),
            timeout=(30, 300),
            headers={"Accept-Encoding": "identity"},
        )
        content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
        if content_encoding not in ("", "identity"):
            response.close()
            raise OpenBaoUnavailable("OpenBao returned an invalid snapshot response.")
        raw_length = response.headers.get("Content-Length")
        declared_size = None
        if raw_length is not None:
            try:
                declared_size = int(raw_length)
            except (TypeError, ValueError):
                response.close()
                raise OpenBaoUnavailable("OpenBao returned an invalid snapshot response.") from None
            if not 0 < declared_size <= MAX_SNAPSHOT_BYTES:
                response.close()
                raise OpenBaoUnavailable("OpenBao returned an invalid snapshot response.")
        return SnapshotDownload(response, declared_size)

    def restore_raft_snapshot(self, stream, size: int, *, force: bool = False) -> None:
        try:
            body = BoundedSnapshotReader(stream, size)
        except ValueError:
            raise OpenBaoConflict("The snapshot upload is outside the allowed size.") from None
        path = "/sys/storage/raft/snapshot-force" if force else "/sys/storage/raft/snapshot"
        response = self._request(
            "POST",
            path,
            authenticated=True,
            expected=(200, 204),
            timeout=(30, 300),
            data=body,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
        )
        response.close()

    def list_auth_methods(self) -> tuple[AuthMount, ...]:
        payload = self._request_json("GET", "/sys/auth", authenticated=True)
        return self._normalize(normalize_auth_mounts, payload)

    def list_secret_engines(self) -> tuple[SecretEngineMount, ...]:
        payload = self._request_json("GET", "/sys/mounts", authenticated=True)
        return self._normalize(normalize_secret_engine_mounts, payload)

    def read_secret_engine(self, mount_path: str) -> dict:
        path = normalize_engine_mount_path(mount_path)
        payload = self._request_json("GET", f"/sys/mounts/{path}", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    def read_secret_engine_tuning(self, mount_path: str) -> dict:
        path = normalize_engine_mount_path(mount_path)
        payload = self._request_json("GET", f"/sys/mounts/{path}/tune", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    def enable_secret_engine(self, mount_path: str, payload: dict) -> None:
        path = normalize_engine_mount_path(mount_path)
        response = self._request("POST", f"/sys/mounts/{path}", authenticated=True, expected=(200, 204), json=payload)
        response.close()

    def tune_secret_engine(self, mount_path: str, payload: dict) -> None:
        path = normalize_engine_mount_path(mount_path)
        response = self._request(
            "POST", f"/sys/mounts/{path}/tune", authenticated=True, expected=(200, 204), json=payload
        )
        response.close()

    def remount_secret_engine(self, source: str, destination: str) -> dict:
        source_path = normalize_engine_mount_path(source)
        destination_path = normalize_engine_mount_path(destination)
        payload = self._request_json(
            "POST",
            "/sys/remount",
            authenticated=True,
            json={"from": f"{source_path}/", "to": f"{destination_path}/"},
        )
        return self._normalize(normalize_public_auth_data, payload)

    def secret_engine_remount_status(self, migration_id: str) -> dict:
        migration = normalize_migration_id(migration_id)
        payload = self._request_json("GET", f"/sys/remount/status/{migration}", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    def disable_secret_engine(self, mount_path: str) -> None:
        path = normalize_engine_mount_path(mount_path)
        response = self._request("DELETE", f"/sys/mounts/{path}", authenticated=True, expected=(200, 204))
        response.close()

    @sensitive_variables()
    def execute_mounted_operation(self, method: str, path: str, *, query: dict, body: dict) -> dict:
        if method not in {"GET", "LIST", "POST", "PUT", "PATCH", "DELETE"} or not path.startswith("/"):
            raise BackendConfigurationError("The mounted operation is outside the reviewed transport contract.")
        kwargs = {"params": query}
        if method not in {"GET", "LIST", "DELETE"}:
            kwargs["json"] = body
        if method == "PATCH":
            kwargs["headers"] = {"Content-Type": "application/merge-patch+json"}
        response = self._request(method, path, authenticated=True, expected=(200, 204), **kwargs)
        if response.status_code == 204:
            response.close()
            return {}
        return self._response_json(response)

    def read_auth_method(self, mount_path: str) -> dict:
        path = normalize_mount_path(mount_path)
        payload = self._request_json("GET", f"/sys/auth/{path}", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    def enable_auth_method(self, mount_path: str, payload: dict) -> None:
        path = normalize_mount_path(mount_path)
        response = self._request("POST", f"/sys/auth/{path}", authenticated=True, expected=(200, 204), json=payload)
        response.close()

    def tune_auth_method(self, mount_path: str, payload: dict) -> None:
        path = normalize_mount_path(mount_path)
        response = self._request(
            "POST",
            f"/sys/auth/{path}/tune",
            authenticated=True,
            expected=(200, 204),
            json=payload,
        )
        response.close()

    def remount_auth_method(self, source: str, destination: str) -> dict:
        source = normalize_mount_path(source)
        destination = normalize_mount_path(destination)
        payload = self._request_json(
            "POST",
            "/sys/remount",
            authenticated=True,
            json={"from": f"auth/{source}/", "to": f"auth/{destination}/"},
        )
        return self._normalize(normalize_public_auth_data, payload)

    def remount_status(self, migration_id: str) -> dict:
        migration_id = normalize_resource_name(migration_id, uuid_only=True)
        payload = self._request_json("GET", f"/sys/remount/status/{migration_id}", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    def disable_auth_method(self, mount_path: str) -> None:
        path = normalize_mount_path(mount_path)
        response = self._request("DELETE", f"/sys/auth/{path}", authenticated=True, expected=(200, 204))
        response.close()

    def read_auth_config(self, mount_path: str) -> dict:
        path = normalize_mount_path(mount_path)
        payload = self._request_json("GET", f"/auth/{path}/config", authenticated=True)
        return self._normalize(normalize_public_auth_data, payload)

    @sensitive_variables()
    def write_auth_config(self, mount_path: str, payload: dict) -> None:
        path = normalize_mount_path(mount_path)
        response = self._request("POST", f"/auth/{path}/config", authenticated=True, expected=(200, 204), json=payload)
        response.close()

    @sensitive_variables()
    def run_auth_resource(
        self,
        mount_path: str,
        spec: AuthResourceSpec,
        operation: str,
        *,
        name: str = "",
        payload: dict | None = None,
    ) -> dict:
        path = spec.path(normalize_mount_path(mount_path), name=normalize_resource_name(name) if name else "")
        method = {"list": "LIST", "read": "GET", "write": "POST", "delete": "DELETE"}[operation]
        kwargs = {"json": payload} if operation == "write" else {}
        if operation == "list":
            response_payload = self._request_list_json(path)
            return self._normalize(normalize_public_auth_data, response_payload)
        if operation == "read":
            response_payload = self._request_json(method, path, authenticated=True, **kwargs)
            return self._normalize(normalize_public_auth_data, response_payload)
        response = self._request(method, path, authenticated=True, expected=(200, 204), **kwargs)
        response.close()
        return {}

    @sensitive_variables()
    def issue_approle_secret_id(self, mount_path: str, role_name: str, payload: dict) -> SecretIDResult:
        mount = normalize_mount_path(mount_path)
        role = normalize_resource_name(role_name)
        result = self._request_json(
            "POST",
            f"/auth/{mount}/role/{role}/secret-id",
            authenticated=True,
            json=payload,
        )
        return self._normalize_mutation(normalize_secret_id_result, result)

    def read_approle_role_id(self, mount_path: str, role_name: str) -> dict:
        mount = normalize_mount_path(mount_path)
        role = normalize_resource_name(role_name)
        result = self._request_json("GET", f"/auth/{mount}/role/{role}/role-id", authenticated=True)
        return self._normalize(normalize_public_auth_data, result)

    @sensitive_variables()
    def write_approle_role_id(self, mount_path: str, role_name: str, role_id: str) -> None:
        mount = normalize_mount_path(mount_path)
        role = normalize_resource_name(role_name)
        role_id = normalize_role_id(role_id)
        response = self._request(
            "POST",
            f"/auth/{mount}/role/{role}/role-id",
            authenticated=True,
            expected=(200, 204),
            json={"role_id": role_id},
        )
        response.close()

    @sensitive_variables()
    def lookup_approle_secret_id(self, mount_path: str, role_name: str, accessor: str) -> dict:
        mount = normalize_mount_path(mount_path)
        role = normalize_resource_name(role_name)
        accessor = normalize_resource_name(accessor, uuid_only=True)
        result = self._request_json(
            "POST",
            f"/auth/{mount}/role/{role}/secret-id-accessor/lookup",
            authenticated=True,
            json={"secret_id_accessor": accessor},
        )
        return self._normalize(normalize_public_auth_data, result)

    @sensitive_variables()
    def destroy_approle_secret_id(self, mount_path: str, role_name: str, accessor: str) -> None:
        mount = normalize_mount_path(mount_path)
        role = normalize_resource_name(role_name)
        accessor = normalize_resource_name(accessor, uuid_only=True)
        response = self._request(
            "POST",
            f"/auth/{mount}/role/{role}/secret-id-accessor/destroy",
            authenticated=True,
            expected=(200, 204),
            json={"secret_id_accessor": accessor},
        )
        response.close()

    @sensitive_variables()
    def authenticate(self, method_type: str, mount_path: str, payload: dict) -> AuthenticationResult | dict:
        mount = normalize_mount_path(mount_path)
        data = dict(payload)
        if method_type == "token":
            token = data.pop("token")
            result = self._request_json("GET", "/auth/token/lookup-self", authenticated=False, token=token)
            return self._normalize(normalize_public_auth_data, result)
        if method_type in {"userpass", "ldap", "radius"}:
            username = normalize_resource_name(data.pop("username"))
            path = f"/auth/{mount}/login/{username}"
        elif method_type in {"jwt", "oidc", "approle", "kubernetes"}:
            path = f"/auth/{mount}/login"
        else:
            raise BackendConfigurationError("The auth method does not support this login flow.")
        result = self._request_json("POST", path, authenticated=False, json=data)
        return self._normalize_mutation(normalize_authentication_result, result)

    @sensitive_variables()
    def oidc_start(self, mount_path: str, role: str, redirect_uri: str, client_nonce: str) -> OIDCStartResult:
        mount = normalize_mount_path(mount_path)
        result = self._request_json(
            "POST",
            f"/auth/{mount}/oidc/auth_url",
            authenticated=False,
            json={"role": normalize_resource_name(role), "redirect_uri": redirect_uri, "client_nonce": client_nonce},
        )
        return self._normalize_mutation(normalize_oidc_start, result)

    @sensitive_variables()
    def oidc_poll(self, mount_path: str, state: str, client_nonce: str) -> AuthenticationResult:
        mount = normalize_mount_path(mount_path)
        result = self._request_json(
            "POST",
            f"/auth/{mount}/oidc/poll",
            authenticated=False,
            json={"state": state, "client_nonce": client_nonce},
        )
        return self._normalize_mutation(normalize_authentication_result, result)

    def read_direct_oidc_role(self, mount_path: str, role: str) -> dict:
        mount = normalize_mount_path(mount_path)
        role_name = normalize_resource_name(role)
        result = self._request_json("GET", f"/auth/{mount}/role/{role_name}", authenticated=True)
        return self._normalize(validate_direct_oidc_role, result)

    @sensitive_variables()
    def validate_mfa(self, request_id: str, payload: dict[str, list[str]]) -> AuthenticationResult:
        result = self._request_json(
            "POST",
            "/sys/mfa/validate",
            authenticated=False,
            json={"mfa_request_id": request_id, "mfa_payload": payload},
        )
        return self._normalize_mutation(normalize_authentication_result, result)

    def list_mfa_methods(self) -> dict:
        result = self._request_list_json("/identity/mfa/method")
        return self._normalize(normalize_public_auth_data, result)

    def read_mfa_method(self, method_id: str) -> dict:
        method_id = normalize_resource_name(method_id, uuid_only=True)
        result = self._request_json("GET", f"/identity/mfa/method/{method_id}", authenticated=True)
        return self._normalize(normalize_public_auth_data, result)

    @sensitive_variables()
    def write_mfa_method(self, method_type: str, payload: dict, *, method_id: str = "") -> dict:
        if method_type not in {"totp", "duo", "okta", "pingid"}:
            raise BackendConfigurationError("The MFA method type is unsupported.")
        suffix = f"/{normalize_resource_name(method_id, uuid_only=True)}" if method_id else ""
        response = self._request(
            "POST",
            f"/identity/mfa/method/{method_type}{suffix}",
            authenticated=True,
            expected=(200, 204),
            json=payload,
        )
        try:
            if response.status_code == 204:
                return {}
            body = response.raw.read(MAX_CLUSTER_JSON_BYTES + 1, decode_content=True)
        except Exception:
            raise OpenBaoMutationUnknown() from None
        finally:
            response.close()
        if len(body) > MAX_CLUSTER_JSON_BYTES:
            raise OpenBaoMutationUnknown() from None
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoMutationUnknown() from None
        if not isinstance(result, dict):
            raise OpenBaoMutationUnknown()
        return self._normalize_mutation(normalize_public_auth_data, result)

    def delete_mfa_method(self, method_type: str, method_id: str) -> None:
        if method_type not in {"totp", "duo", "okta", "pingid"}:
            raise BackendConfigurationError("The MFA method type is unsupported.")
        method_id = normalize_resource_name(method_id, uuid_only=True)
        response = self._request(
            "DELETE",
            f"/identity/mfa/method/{method_type}/{method_id}",
            authenticated=True,
            expected=(200, 204),
        )
        response.close()

    @sensitive_variables()
    def setup_totp(
        self,
        method_id: str,
        *,
        entity_id: str = "",
        administrator: bool = False,
        token: str = "",
    ) -> TOTPSetupResult:
        method_id = normalize_resource_name(method_id, uuid_only=True)
        if administrator:
            entity_id = normalize_resource_name(entity_id, uuid_only=True)
            path = "/identity/mfa/method/totp/admin-generate"
            payload = {"method_id": method_id, "entity_id": entity_id}
        else:
            if not token:
                raise BackendConfigurationError("A request-scoped token is required for TOTP self-setup.")
            path = "/identity/mfa/method/totp/generate"
            payload = {"method_id": method_id}
        result = self._request_json(
            "POST",
            path,
            authenticated=administrator,
            token="" if administrator else token,
            json=payload,
        )
        return self._normalize_mutation(normalize_totp_setup_result, result)

    def destroy_totp_setup(self, method_id: str, entity_id: str) -> None:
        method_id = normalize_resource_name(method_id, uuid_only=True)
        entity_id = normalize_resource_name(entity_id, uuid_only=True)
        response = self._request(
            "POST",
            "/identity/mfa/method/totp/admin-destroy",
            authenticated=True,
            expected=(200, 204),
            json={"method_id": method_id, "entity_id": entity_id},
        )
        response.close()

    @sensitive_variables()
    def reset_totp_setup(self, method_id: str, token: str) -> dict:
        method_id = normalize_resource_name(method_id, uuid_only=True)
        if not token:
            raise BackendConfigurationError("A request-scoped token is required for TOTP reset.")
        result = self._request_json(
            "GET",
            "/auth/token/lookup-self",
            authenticated=False,
            token=token,
        )
        data = self._normalize(normalize_public_auth_data, result)
        entity_id = normalize_resource_name(data.get("entity_id"), uuid_only=True)
        self.destroy_totp_setup(method_id, entity_id)
        return {"reset": True}

    def list_mfa_enforcements(self) -> dict:
        result = self._request_list_json("/identity/mfa/login-enforcement")
        return self._normalize(normalize_public_auth_data, result)

    def read_mfa_enforcement(self, name: str) -> dict:
        name = normalize_resource_name(name)
        result = self._request_json("GET", f"/identity/mfa/login-enforcement/{name}", authenticated=True)
        return self._normalize(normalize_public_auth_data, result)

    def write_mfa_enforcement(self, name: str, payload: dict) -> None:
        name = normalize_resource_name(name)
        response = self._request(
            "POST",
            f"/identity/mfa/login-enforcement/{name}",
            authenticated=True,
            expected=(200, 204),
            json=payload,
        )
        response.close()

    def delete_mfa_enforcement(self, name: str) -> None:
        name = normalize_resource_name(name)
        response = self._request(
            "DELETE",
            f"/identity/mfa/login-enforcement/{name}",
            authenticated=True,
            expected=(200, 204),
        )
        response.close()

    @sensitive_variables()
    def token_operation(self, operation: str, payload: dict) -> AuthenticationResult | dict | None:
        data = dict(payload)
        if operation == "lookup-self":
            token = data.pop("token")
            result = self._request_json("GET", "/auth/token/lookup-self", authenticated=False, token=token)
            return self._normalize(normalize_public_auth_data, result)
        if operation == "renew-self":
            token = data.pop("token")
            result = self._request_json("POST", "/auth/token/renew-self", authenticated=False, token=token, json=data)
            return self._normalize_mutation(normalize_authentication_result, result)
        if operation == "revoke-self":
            token = data.pop("token")
            response = self._request(
                "POST", "/auth/token/revoke-self", authenticated=False, token=token, expected=(200, 204)
            )
            response.close()
            return None
        accessor = normalize_resource_name(data.pop("accessor"), uuid_only=True)
        action = operation.split("-", 1)[0]
        path = f"/auth/token/{action}-accessor"
        if operation == "lookup-accessor":
            result = self._request_json("POST", path, authenticated=True, json={"accessor": accessor})
            return self._normalize(normalize_public_auth_data, result)
        if operation == "renew-accessor":
            request_payload = {"accessor": accessor, **data}
            result = self._request_json("POST", path, authenticated=True, json=request_payload)
            return self._normalize_mutation(normalize_authentication_result, result)
        if operation == "revoke-accessor":
            response = self._request("POST", path, authenticated=True, expected=(200, 204), json={"accessor": accessor})
            response.close()
            return None
        raise BackendConfigurationError("The token operation is unsupported.")

    @sensitive_variables()
    def execute_access_operation(
        self,
        method: str,
        path: str,
        *,
        payload: dict,
        material: bool = False,
    ) -> dict:
        if method not in {"GET", "LIST", "POST", "DELETE"} or not path.startswith(
            ("/sys/policies/", "/identity/", "/sys/namespaces")
        ):
            raise BackendConfigurationError("The access-control operation is outside the reviewed contract.")

        def normalizer(value):
            return normalize_access_response(value, material=material)

        if method == "LIST":
            return self._normalize(normalizer, self._request_list_json(path))
        kwargs = {}
        if method == "POST":
            kwargs["json"] = payload
        response = self._request(method, path, authenticated=True, expected=(200, 204), **kwargs)
        if method in {"POST", "DELETE"}:
            try:
                if response.status_code == 204:
                    response.close()
                    return {}
                result = self._response_json(response)
                return self._normalize_mutation(normalizer, result)
            except OpenBaoMutationUnknown:
                raise
            except (CapabilitySchemaError, OpenBaoUnavailable):
                raise OpenBaoMutationUnknown() from None
        if response.status_code == 204:
            response.close()
            return {}
        result = self._response_json(response)
        return self._normalize(normalizer, result)

    @staticmethod
    def _normalize(normalizer, payload):
        try:
            return normalizer(payload)
        except CapabilitySchemaError:
            raise OpenBaoUnavailable("OpenBao returned an invalid administrative response.") from None

    @classmethod
    def _normalize_mutation(cls, normalizer, payload):
        try:
            return cls._normalize(normalizer, payload)
        except OpenBaoUnavailable:
            raise OpenBaoMutationUnknown() from None


class BrokerAdministrationBackend(AdministrationBackend):
    """Broker health is supported; discovery fails closed until the broker opts in."""

    def __init__(self, cluster):
        super().__init__(cluster)
        self.backend = BrokerBackend(cluster)

    def health(self) -> dict:
        return self.backend.health()

    def discover_capabilities(self) -> CapabilityDocument:
        raise BackendConfigurationError(
            "The configured broker does not advertise the administrative capability contract."
        )


def get_administration_backend(cluster) -> AdministrationBackend:
    """Return the reviewed administration transport for a cluster."""
    if cluster.backend == BackendChoices.BACKEND_BROKER:
        return BrokerAdministrationBackend(cluster)
    if cluster.backend in {BackendChoices.BACKEND_OPENBAO, BackendChoices.BACKEND_VAULT}:
        return DirectAdministrationBackend(cluster)
    raise BackendConfigurationError("Unsupported OpenBao administration backend.")
