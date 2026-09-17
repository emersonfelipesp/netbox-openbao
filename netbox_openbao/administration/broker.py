"""Pinned, bounded client for the broker administration contract."""

from __future__ import annotations

import io
import json
import logging
from dataclasses import dataclass
from typing import Any

from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoMutationUnknown,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)

from .cluster import MAX_CLUSTER_JSON_BYTES

logger = logging.getLogger("netbox.plugins.netbox_openbao.administration")

CONTRACT_VERSION = "1"
CONTRACT_DIGEST = "d3eff0f2202d7531181b51bb22e29d7ef5640c4a1257af1c2fe9ce8472bd4cf6"
REQUEST_TIMEOUT = 30

EXPECTED_OPERATIONS = frozenset(
    {
        ("discover_capabilities", "cluster", "json"),
        ("initialization_status", "cluster", "json"),
        ("seal_status", "cluster", "json"),
        ("leader_status", "cluster", "json"),
        ("ha_status", "cluster", "json"),
        ("raft_configuration", "cluster", "json"),
        ("initialize", "cluster", "json"),
        ("join_raft", "cluster", "json"),
        ("unseal", "cluster", "json"),
        ("seal", "cluster", "json"),
        ("remove_raft_peer", "cluster", "json"),
        ("download_raft_snapshot", "cluster", "stream-download"),
        ("restore_raft_snapshot", "cluster", "stream-upload"),
        ("execute_secret_engine_operation", "secret-engines", "json"),
        ("execute_mounted_operation", "mounted-secrets", "json"),
        ("execute_authentication_operation", "authentication", "json"),
        ("execute_access_operation", "access", "json"),
        ("execute_final_operation", "finalization", "json"),
    }
)
EXPECTED_FAMILIES = frozenset(item[1] for item in EXPECTED_OPERATIONS)


class _RawBytes:
    def __init__(self, body: bytes):
        self._body = io.BytesIO(body)

    def read(self, amount: int = -1, *, decode_content: bool = False) -> bytes:
        del decode_content
        return self._body.read(amount)

    def stream(self, amount: int, *, decode_content: bool = False):
        del decode_content
        while chunk := self._body.read(amount):
            yield chunk


@dataclass
class MemoryResponse:
    """Minimal requests-compatible response containing broker-decoded data."""

    data: Any
    status_code: int = 200

    def __post_init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.raw = _RawBytes(json.dumps(self.data, separators=(",", ":")).encode())

    def close(self) -> None:
        return None


class BrokerAdministrationClient:
    """Negotiate and execute only the pinned broker administration contract."""

    def __init__(self, backend):
        self.backend = backend
        self._contract_verified = False

    def _session(self):
        return self.backend._get_session()

    def _url(self, path: str) -> str:
        return f"{self.backend.engine.api_url.rstrip('/')}{path}"

    def verify_contract(self) -> None:
        if self._contract_verified:
            return
        response = self._send("GET", "/v1/administration/contract", mutation=False)
        document = self._decode_json(response, mutation=False)
        self._validate_contract(document)
        self._contract_verified = True

    @staticmethod
    def _validate_contract(document: Any) -> None:
        if not isinstance(document, dict) or set(document) != {"version", "digest", "families", "operations"}:
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        if document["version"] != CONTRACT_VERSION or document["digest"] != CONTRACT_DIGEST:
            raise BackendConfigurationError("The broker administration contract is incompatible.")
        families = BrokerAdministrationClient._contract_families(document["families"])
        operations = BrokerAdministrationClient._contract_operations(document["operations"])
        operation_set = {(item["name"], item["family"], item["framing"]) for item in operations}
        if families != EXPECTED_FAMILIES or operation_set != EXPECTED_OPERATIONS:
            raise BackendConfigurationError("The broker administration contract is incomplete.")

    @staticmethod
    def _contract_families(families: Any) -> frozenset[str]:
        if not isinstance(families, list) or not all(isinstance(item, str) for item in families):
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        result = frozenset(families)
        if len(families) != len(result):
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        return result

    @staticmethod
    def _contract_operations(operations: Any) -> list[dict[str, str]]:
        if not isinstance(operations, list) or not all(isinstance(item, dict) for item in operations):
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        if not all(BrokerAdministrationClient._valid_contract_operation(item) for item in operations):
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        operation_set = {(item["name"], item["family"], item["framing"]) for item in operations}
        if len(operations) != len(operation_set):
            raise BackendConfigurationError("The broker returned a malformed administration contract.")
        return operations

    @staticmethod
    def _valid_contract_operation(operation: dict) -> bool:
        return set(operation) == {"name", "family", "framing"} and all(
            isinstance(value, str) for value in operation.values()
        )

    @sensitive_variables()
    def execute(self, operation: str, arguments: dict, *, mutation: bool) -> Any:
        if operation not in {item[0] for item in EXPECTED_OPERATIONS if item[2] == "json"}:
            raise BackendConfigurationError("The administration operation is outside the pinned broker contract.")
        self.verify_contract()
        response = self._send(
            "POST",
            "/v1/administration/request",
            mutation=mutation,
            json={"contract_digest": CONTRACT_DIGEST, "operation": operation, "arguments": arguments},
        )
        envelope = self._decode_json(response, mutation=mutation)
        if not isinstance(envelope, dict) or set(envelope) != {"data"}:
            self._invalid_response(mutation)
        data = envelope["data"]
        if not isinstance(data, dict):
            self._invalid_response(mutation)
        return data

    def snapshot_headers(self) -> dict[str, str]:
        self.verify_contract()
        return {"X-Administration-Contract-Digest": CONTRACT_DIGEST}

    @sensitive_variables()
    def _send(self, method: str, path: str, *, mutation: bool, **kwargs):
        try:
            response = self._session().request(
                method,
                self._url(path),
                timeout=kwargs.pop("timeout", REQUEST_TIMEOUT),
                allow_redirects=False,
                stream=True,
                **kwargs,
            )
        except BackendConfigurationError:
            raise
        except Exception:
            if mutation:
                raise OpenBaoMutationUnknown() from None
            raise OpenBaoUnavailable("The broker is unreachable.") from None
        if getattr(response, "is_redirect", False):
            response.close()
            self._invalid_response(mutation)
        if response.status_code >= 400:
            error = self._status_error(response, mutation)
            response.close()
            raise error
        if response.status_code != 200:
            response.close()
            self._invalid_response(mutation)
        return response

    @staticmethod
    def _status_error(response, mutation: bool):
        status = response.status_code
        if response.headers.get("X-OpenBao-Outcome", "").lower() == "unknown":
            return OpenBaoMutationUnknown()
        if status in {401, 403}:
            return OpenBaoAuthError("The broker refused the administrative request.", status)
        if status == 404:
            return OpenBaoNotFound("The administrative resource was not found.", 404)
        if status in {400, 409, 412}:
            return OpenBaoConflict("The administrative state transition was refused.", status)
        if status == 422:
            return BackendConfigurationError("The broker rejected the administration contract request.")
        if mutation and status >= 500:
            return OpenBaoMutationUnknown()
        return OpenBaoUnavailable("The broker administration request failed.", status)

    @classmethod
    def _decode_json(cls, response, *, mutation: bool) -> Any:
        try:
            body = response.raw.read(MAX_CLUSTER_JSON_BYTES + 1, decode_content=True)
        except Exception:
            cls._invalid_response(mutation)
        finally:
            response.close()
        if len(body) > MAX_CLUSTER_JSON_BYTES:
            cls._invalid_response(mutation)
        try:
            return json.loads(body)
        except (TypeError, ValueError, UnicodeDecodeError):
            cls._invalid_response(mutation)

    @staticmethod
    def _invalid_response(mutation: bool):
        if mutation:
            raise OpenBaoMutationUnknown() from None
        raise OpenBaoUnavailable("The broker returned an invalid administrative response.") from None
