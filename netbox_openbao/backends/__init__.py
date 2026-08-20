"""Secret backend registry and factory."""

from .base import SecretBackend
from .exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)
from .openbao import OpenBaoBackend
from .vault import VaultBackend

__all__ = (
    'BackendConfigurationError',
    'OpenBaoAuthError',
    'OpenBaoBackend',
    'OpenBaoConflict',
    'OpenBaoError',
    'OpenBaoNotFound',
    'OpenBaoUnavailable',
    'SecretBackend',
    'VaultBackend',
    'get_backend',
)

# Keyed by SecretEngine.backend. Values must match BackendChoices.
BACKENDS = {
    'openbao': OpenBaoBackend,
    'vault': VaultBackend,
}

DEFAULT_BACKEND = 'openbao'


def get_backend(engine, policy=None):
    """
    Return a backend for `engine`, authenticated as `policy`'s tier when given.

    Routing through the policy's AppRole rather than an engine-wide one is what
    makes the OpenBao policy an independent authorization layer: a NetBox-side
    permission bug on a tier's credentials still cannot read them unless the
    request also carries that tier's AppRole.
    """
    # Fall back rather than raise on an unknown value: an engine row written by
    # a newer version of the plugin should degrade to the compatible default,
    # not take every credential on it offline.
    backend_class = BACKENDS.get(getattr(engine, 'backend', None) or DEFAULT_BACKEND, OpenBaoBackend)
    env_prefix = policy.env_prefix if policy is not None else None
    return backend_class(engine, env_prefix=env_prefix)
