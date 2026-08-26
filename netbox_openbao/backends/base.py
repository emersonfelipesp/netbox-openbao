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

    def __init__(self, engine, env_prefix=None):
        """
        Args:
            engine (SecretEngine): Describes the instance and the KV mount.
            env_prefix (str | None): Overrides the engine's environment prefix, so a
                `CredentialPolicy` tier can authenticate with its own AppRole
                rather than the engine-wide one.
        """
        self.engine = engine
        self.env_prefix = env_prefix or engine.env_prefix

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
