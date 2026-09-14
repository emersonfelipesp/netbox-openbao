"""Administrative transport boundary for OpenBao discovery and cluster state."""

import json
from abc import ABC, abstractmethod

from netbox_openbao.backends.broker import BrokerBackend
from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import BackendChoices

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
from .schema import MAX_DOCUMENT_BYTES, CapabilityDocument, CapabilitySchemaError, normalize_openapi_document

__all__ = ('AdministrationBackend', 'get_administration_backend')


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

    def unseal(self, *, key: str = '', reset: bool = False, migrate: bool = False) -> SealStatus:
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

    @staticmethod
    def _unsupported() -> BackendConfigurationError:
        return BackendConfigurationError(
            'The configured transport does not advertise the required administrative contract.'
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

    def _headers(self, *, authenticated: bool) -> dict[str, str]:
        headers = {'X-Vault-Request': 'true'}
        if self.cluster.namespace:
            headers['X-Vault-Namespace'] = self.cluster.namespace
        if authenticated:
            token = self.backend._get_client().token
            if token:
                headers['X-Vault-Token'] = token
        return headers

    def _request(self, method: str, path: str, *, authenticated: bool, expected: tuple[int, ...], **kwargs):
        extra_headers = kwargs.pop('headers', None) or {}
        timeout = kwargs.pop('timeout', 30)
        headers = self._headers(authenticated=authenticated)
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
            raise OpenBaoUnavailable('OpenBao administration request failed.') from None
        if response.status_code in expected:
            return response
        response.close()
        if response.status_code in (401, 403):
            raise OpenBaoAuthError('OpenBao rejected the administrative request.', response.status_code)
        if response.status_code == 404:
            raise OpenBaoNotFound('OpenBao does not support this administrative operation.', 404)
        if response.status_code in (400, 409, 412):
            raise OpenBaoConflict('OpenBao refused the administrative state transition.', response.status_code)
        raise OpenBaoUnavailable('OpenBao administration request failed.', response.status_code)

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
            body = response.raw.read(MAX_CLUSTER_JSON_BYTES + 1, decode_content=True)
        except Exception:
            raise OpenBaoUnavailable('OpenBao returned an invalid administrative response.') from None
        finally:
            response.close()
        if len(body) > MAX_CLUSTER_JSON_BYTES:
            raise OpenBaoUnavailable('OpenBao administrative response is too large.')
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoUnavailable('OpenBao returned an invalid administrative response.') from None
        if not isinstance(payload, dict):
            raise OpenBaoUnavailable('OpenBao returned an invalid administrative response.')
        return payload

    def discover_capabilities(self) -> CapabilityDocument:
        response = self._request(
            'GET',
            '/sys/internal/specs/openapi',
            authenticated=True,
            expected=(200,),
            params={'generic_mount_paths': 'true'},
        )
        try:
            body = response.raw.read(MAX_DOCUMENT_BYTES + 1, decode_content=True)
        except Exception:
            raise OpenBaoUnavailable('OpenBao returned an invalid capability document.') from None
        finally:
            response.close()

        if len(body) > MAX_DOCUMENT_BYTES:
            raise OpenBaoUnavailable('OpenBao capability discovery response is too large.')
        try:
            document = json.loads(body)
            return normalize_openapi_document(document)
        except (CapabilitySchemaError, json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoUnavailable('OpenBao returned an invalid capability document.') from None

    def initialization_status(self) -> bool:
        payload = self._request_json('GET', '/sys/init', authenticated=False)
        initialized = payload.get('initialized')
        if not isinstance(initialized, bool):
            raise OpenBaoUnavailable('OpenBao returned an invalid initialization status.')
        return initialized

    def seal_status(self) -> SealStatus:
        payload = self._request_json('GET', '/sys/seal-status', authenticated=False)
        return self._normalize(normalize_seal_status, payload)

    def leader_status(self) -> LeaderStatus:
        payload = self._request_json('GET', '/sys/leader', authenticated=True)
        return self._normalize(normalize_leader_status, payload)

    def ha_status(self) -> HAStatus:
        payload = self._request_json('GET', '/sys/ha-status', authenticated=True)
        return self._normalize(normalize_ha_status, payload)

    def raft_configuration(self) -> RaftConfiguration:
        payload = self._request_json('GET', '/sys/storage/raft/configuration', authenticated=True)
        return self._normalize(normalize_raft_configuration, payload)

    def initialize(self, payload: dict) -> InitializationResult:
        result = self._request_json('POST', '/sys/init', authenticated=False, json=payload)
        return self._normalize(normalize_initialization_result, result)

    def unseal(self, *, key: str = '', reset: bool = False, migrate: bool = False) -> SealStatus:
        payload = {'reset': reset, 'migrate': migrate}
        if key:
            payload['key'] = key
        result = self._request_json('POST', '/sys/unseal', authenticated=False, json=payload)
        return self._normalize(normalize_seal_status, result)

    def seal(self) -> None:
        response = self._request('POST', '/sys/seal', authenticated=True, expected=(200, 204))
        response.close()

    def remove_raft_peer(self, server_id: str) -> None:
        response = self._request(
            'POST',
            '/sys/storage/raft/remove-peer',
            authenticated=True,
            expected=(200, 204),
            json={'server_id': server_id},
        )
        response.close()

    def download_raft_snapshot(self) -> SnapshotDownload:
        response = self._request(
            'GET',
            '/sys/storage/raft/snapshot',
            authenticated=True,
            expected=(200,),
            timeout=(30, 300),
            headers={'Accept-Encoding': 'identity'},
        )
        content_encoding = response.headers.get('Content-Encoding', '').strip().lower()
        if content_encoding not in ('', 'identity'):
            response.close()
            raise OpenBaoUnavailable('OpenBao returned an invalid snapshot response.')
        raw_length = response.headers.get('Content-Length')
        declared_size = None
        if raw_length is not None:
            try:
                declared_size = int(raw_length)
            except (TypeError, ValueError):
                response.close()
                raise OpenBaoUnavailable('OpenBao returned an invalid snapshot response.') from None
            if not 0 < declared_size <= MAX_SNAPSHOT_BYTES:
                response.close()
                raise OpenBaoUnavailable('OpenBao returned an invalid snapshot response.')
        return SnapshotDownload(response, declared_size)

    def restore_raft_snapshot(self, stream, size: int, *, force: bool = False) -> None:
        try:
            body = BoundedSnapshotReader(stream, size)
        except ValueError:
            raise OpenBaoConflict('The snapshot upload is outside the allowed size.') from None
        path = '/sys/storage/raft/snapshot-force' if force else '/sys/storage/raft/snapshot'
        response = self._request(
            'POST',
            path,
            authenticated=True,
            expected=(200, 204),
            timeout=(30, 300),
            data=body,
            headers={
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(size),
            },
        )
        response.close()

    @staticmethod
    def _normalize(normalizer, payload):
        try:
            return normalizer(payload)
        except CapabilitySchemaError:
            raise OpenBaoUnavailable('OpenBao returned an invalid administrative response.') from None


class BrokerAdministrationBackend(AdministrationBackend):
    """Broker health is supported; discovery fails closed until the broker opts in."""

    def __init__(self, cluster):
        super().__init__(cluster)
        self.backend = BrokerBackend(cluster)

    def health(self) -> dict:
        return self.backend.health()

    def discover_capabilities(self) -> CapabilityDocument:
        raise BackendConfigurationError(
            'The configured broker does not advertise the administrative capability contract.'
        )


def get_administration_backend(cluster) -> AdministrationBackend:
    """Return the reviewed administration transport for a cluster."""
    if cluster.backend == BackendChoices.BACKEND_BROKER:
        return BrokerAdministrationBackend(cluster)
    if cluster.backend in {BackendChoices.BACKEND_OPENBAO, BackendChoices.BACKEND_VAULT}:
        return DirectAdministrationBackend(cluster)
    raise BackendConfigurationError('Unsupported OpenBao administration backend.')
