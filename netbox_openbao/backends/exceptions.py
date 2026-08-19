"""
Scrubbed backend exceptions.

Every exception raised out of a backend is constructed here from a fixed
message plus, at most, an HTTP status code. Upstream client libraries embed the
server's response body in their exception text, and an OpenBao 403 body can
contain a full policy dump. Letting that propagate puts the contents of your
authorization model into Sentry, into `logging`, and into any DRF error
response — so backends catch the library exception and re-raise one of these
instead. The original is never chained with `from` for the same reason.
"""

__all__ = (
    'BackendConfigurationError',
    'OpenBaoAuthError',
    'OpenBaoConflict',
    'OpenBaoError',
    'OpenBaoNotFound',
    'OpenBaoUnavailable',
)


class OpenBaoError(Exception):
    """Base for every backend failure. Carries no server-supplied text."""

    default_message = 'OpenBao request failed.'

    def __init__(self, message=None, status_code=None):
        self.status_code = status_code
        super().__init__(message or self.default_message)


class BackendConfigurationError(OpenBaoError):
    """The engine or its environment is misconfigured; the request never ran."""

    default_message = 'Secret backend is not correctly configured.'


class OpenBaoAuthError(OpenBaoError):
    """Authentication or authorization was rejected."""

    default_message = 'OpenBao rejected the plugin credentials for this engine.'


class OpenBaoNotFound(OpenBaoError):
    """No secret exists at the requested path or version."""

    default_message = 'No secret exists at the requested path.'


class OpenBaoConflict(OpenBaoError):
    """A check-and-set write lost a race against a concurrent writer."""

    default_message = 'The secret was modified concurrently; the write was refused.'


class OpenBaoUnavailable(OpenBaoError):
    """The instance is unreachable, sealed, or failed TLS verification."""

    default_message = 'OpenBao is unreachable or sealed.'
