"""Secret backend registry and factory."""

from .base import SecretBackend
from .broker import BrokerBackend
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
    'BrokerBackend',
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
    'broker': BrokerBackend,
}

DEFAULT_BACKEND = 'openbao'


def get_backend(engine, policy=None):
    """
    Return a backend for `engine`, authenticated as `policy`'s tier when given.

    Routing through the policy's AppRole rather than an engine-wide one bounds
    blast radius: a leaked SecretID reaches only its own tier, and a tier whose
    SecretID was never delivered to this instance cannot be read from it.

    Note what it is *not*. The AppRole is chosen from the credential's own
    policy, so a NetBox-side permission bug that yields a `prod-core`
    credential produces a read carrying the `prod-core` AppRole — the identity
    authorized for that path. OpenBao does not re-check the NetBox user and
    will allow it. Do not describe this as a layer that contains a NetBox
    authorization failure; `docs/security.md` states the honest version.
    """
    # Fall back rather than raise on an unknown value: an engine row written by
    # a newer version of the plugin should degrade to the compatible default,
    # not take every credential on it offline.
    backend_class = BACKENDS.get(getattr(engine, 'backend', None) or DEFAULT_BACKEND, OpenBaoBackend)
    env_prefix = policy.env_prefix if policy is not None else None
    return backend_class(engine, env_prefix=env_prefix)
