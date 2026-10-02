"""
The backend contract.

An ABC sits between the plugin and OpenBao from day one so the plugin never
imports a vendor client directly. HashiCorp Vault is API-compatible with
OpenBao and reduces to a near-empty subclass; Infisical or a cloud KMS become
community contributions rather than forks. That costs roughly two hundred lines
and roughly doubles the addressable user base.

Implementations must honour two rules that the rest of the plugin depends on:

1. Never raise a vendor exception. Catch it and raise a
   `netbox_openbao.backends.exceptions` type, which carries no server text.
2. Never log, format, or attach secret material to an exception, a span, or a
   metric. `read()` returns it; nothing else may retain it.
"""

from abc import ABC, abstractmethod

__all__ = ('SecretBackend',)


class SecretBackend(ABC):
    """Read/write access to one KV mount on one secret store."""

    def __init__(self, engine, auth_material=None):
        """
        Args:
            engine (SecretEngine): Describes the instance and the KV mount.
            auth_material (EngineAuthMaterial | None): Encrypted database row
                resolved for the engine or policy tier.
        """
        self.engine = engine
        self.auth_material = auth_material

    def refresh_auth_material(self):
        """Refresh a rotated database identity before reusing local auth state."""
        material = self.auth_material
        if material is None or not getattr(material, '_state', None) or not material.pk:
            return False
        revision = (
            type(material).objects.filter(pk=material.pk)
            .values_list('revision', flat=True)
            .first()
        )
        if revision == material.revision:
            return False
        if revision is None:
            self.auth_material = None
        else:
            material.refresh_from_db()
        return True

    @abstractmethod
    def read(self, path, version=None):
        """
        Return the secret payload at `path` as a dict.

        Raises `OpenBaoNotFound` if the path or version does not exist.
        """

    @abstractmethod
    def write(self, path, data, cas=None):
        """
        Write `data` at `path` and return the resulting version number.

        `cas` is the check-and-set precondition: pass `0` to require that the
        path does not yet exist, or the expected current version to require
        that nothing has changed since it was read. Raises `OpenBaoConflict`
        when the precondition fails.
        """

    @abstractmethod
    def delete(self, path, versions=None):
        """
        Delete specific `versions` at `path`, or destroy the path entirely
        (metadata and every version) when `versions` is None.
        """

    @abstractmethod
    def list_versions(self, path):
        """Return version metadata for `path`, newest first. Never values."""

    @abstractmethod
    def read_metadata(self, path):
        """
        Return the KV metadata for `path` as a dict. Never a secret value.

        Carries at least `current_version` and `custom_metadata`; a backend
        whose store exposes more may include it. Raises `OpenBaoNotFound` if
        the path does not exist.

        Abstract because `CredentialVerifyJob` calls it on every credential.
        It was omitted from this contract at first while all three shipped
        backends happened to implement it, which meant a conforming third-party
        backend — the whole reason this ABC exists — would import, instantiate,
        and pass every abstract-method check, then fail inside a background job
        long after the change that introduced it.
        """

    @abstractmethod
    def set_metadata(self, path, metadata):
        """Replace the custom metadata at `path` with `metadata`."""

    @abstractmethod
    def health(self):
        """
        Return a dict describing instance health.

        Must not raise for an unhealthy-but-reachable instance; report it in
        the return value instead, so the health job can distinguish "sealed"
        from "unreachable".
        """

    @abstractmethod
    def authenticate(self):
        """Authenticate without reading or writing secret material."""
