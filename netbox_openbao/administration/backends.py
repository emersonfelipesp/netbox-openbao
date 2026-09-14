"""Administrative transport boundary for OpenBao capability discovery."""

import json
from abc import ABC, abstractmethod

from netbox_openbao.backends.broker import BrokerBackend
from netbox_openbao.backends.exceptions import BackendConfigurationError, OpenBaoError, OpenBaoUnavailable
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import BackendChoices

from .schema import MAX_DOCUMENT_BYTES, CapabilityDocument, CapabilitySchemaError, normalize_openapi_document

__all__ = ('AdministrationBackend', 'get_administration_backend')


class AdministrationBackend(ABC):
    """Read-only foundation shared by direct and broker administration transports."""

    def __init__(self, cluster):
        self.cluster = cluster

    @abstractmethod
    def health(self) -> dict:
        """Return safe health metadata."""

    @abstractmethod
    def discover_capabilities(self) -> CapabilityDocument:
        """Return normalized runtime OpenAPI metadata or a fixed safe error."""


class DirectAdministrationBackend(AdministrationBackend):
    """OpenBao/Vault-compatible direct administrative discovery."""

    def __init__(self, cluster):
        super().__init__(cluster)
        self.backend = OpenBaoBackend(cluster)

    def health(self) -> dict:
        return self.backend.health()

    def discover_capabilities(self) -> CapabilityDocument:
        client = self.backend._get_client()
        verify = self.cluster.ca_cert_path or self.cluster.tls_verify
        headers = {'X-Vault-Request': 'true'}
        if client.token:
            headers['X-Vault-Token'] = client.token
        if self.cluster.namespace:
            headers['X-Vault-Namespace'] = self.cluster.namespace
        url = f"{self.cluster.api_url.rstrip('/')}/v1/sys/internal/specs/openapi"
        try:
            response = self.backend._get_session().get(
                url,
                headers=headers,
                params={'generic_mount_paths': 'true'},
                verify=verify,
                timeout=30,
                allow_redirects=False,
                stream=True,
            )
            if response.status_code != 200:
                raise OpenBaoUnavailable('OpenBao capability discovery failed.', status_code=response.status_code)
            body = response.raw.read(MAX_DOCUMENT_BYTES + 1, decode_content=True)
        except OpenBaoError:
            raise
        except Exception:
            raise OpenBaoUnavailable('OpenBao capability discovery failed.') from None
        finally:
            if 'response' in locals():
                response.close()

        if len(body) > MAX_DOCUMENT_BYTES:
            raise OpenBaoUnavailable('OpenBao capability discovery response is too large.')
        try:
            document = json.loads(body)
            return normalize_openapi_document(document)
        except (CapabilitySchemaError, json.JSONDecodeError, UnicodeDecodeError):
            raise OpenBaoUnavailable('OpenBao returned an invalid capability document.') from None


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
