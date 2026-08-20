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

__all__ = (
    'BackendConfigurationError',
    'OpenBaoAuthError',
    'OpenBaoBackend',
    'OpenBaoConflict',
    'OpenBaoError',
    'OpenBaoNotFound',
    'OpenBaoUnavailable',
    'SecretBackend',
    'get_backend',
)

# Keyed by SecretEngine.backend_class in a future release; a single entry today.
BACKENDS = {
    'openbao': OpenBaoBackend,
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
    backend_class = BACKENDS[DEFAULT_BACKEND]
    env_prefix = policy.env_prefix if policy is not None else None
    return backend_class(engine, env_prefix=env_prefix)
