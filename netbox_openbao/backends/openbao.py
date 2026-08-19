"""
The OpenBao reference backend, built on `hvac`.

OpenBao is API-compatible with HashiCorp Vault, which is why `hvac` works
against it unmodified and why `VaultBackend` can later be a near-empty
subclass of this class.

Three behaviours here are load-bearing for security and are covered by
`tests/test_backends.py`:

* **No server text escapes.** Every `hvac` exception is caught and translated
  into a `netbox_openbao.backends.exceptions` type built from a fixed string.
  A Forbidden response body from OpenBao can enumerate policy rules; that must
  not reach a log, a traceback, or an API error payload.
* **No auth material touches the database or disk.** RoleIDs and SecretIDs are
  read from the process environment (or a file the environment points at, for
  Docker/Kubernetes secret mounts) at the moment of login.
* **Tokens are cached only in Django's cache.** They expire ahead of their
  lease and are never written to a model field.
"""

import logging
import os
import threading

from django.core.cache import cache

from netbox_openbao.choices import AuthMethodChoices, EngineStatusChoices
from netbox_openbao.config import get_config

from .base import SecretBackend
from .exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)

__all__ = ('OpenBaoBackend',)

logger = logging.getLogger('netbox.plugins.netbox_openbao.backends')

# One pooled HTTP session per engine endpoint. Building a fresh TLS connection
# for every reveal would dominate the latency budget of an operation that is
# otherwise a single round-trip.
_sessions = {}
_sessions_lock = threading.Lock()

# Fraction of the token lease after which the cached token is discarded, so a
# token is never presented to OpenBao at the moment it expires.
TOKEN_CACHE_LEASE_FRACTION = 0.8


def _read_env(name):
    """
    Return the value of `name`, or of the file `name`_FILE points at.

    The `_FILE` indirection is what lets a deployment mount a Docker or
    Kubernetes secret instead of exporting the value into the process
    environment, where it would be visible in `/proc/<pid>/environ`.
    """
    if (value := os.environ.get(name)):
        return value.strip()
    if (path := os.environ.get(f'{name}_FILE')):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            # The path itself is operator-supplied configuration, not a
            # secret, so naming it is safe and makes the misconfiguration
            # diagnosable.
            raise BackendConfigurationError(
                f'Unable to read secret material from {name}_FILE ({path}).'
            ) from None
    return None


class OpenBaoBackend(SecretBackend):
    """Read/write access to one KV mount on one OpenBao instance."""

    def __init__(self, engine, env_prefix=None):
        super().__init__(engine, env_prefix=env_prefix)
        self._client = None

    # ------------------------------------------------------------------
    # Connection and authentication
    # ------------------------------------------------------------------

    @property
    def _cache_key(self):
        return f'netbox_openbao:token:{self.engine.slug}:{self.env_prefix}'

    def _get_session(self):
        key = (self.engine.api_url, self.engine.tls_verify, self.engine.ca_cert_path)
        with _sessions_lock:
            if key not in _sessions:
                import requests

                session = requests.Session()
                _sessions[key] = session
            return _sessions[key]

    def _build_client(self, token=None):
        try:
            import hvac
        except ImportError:
            raise BackendConfigurationError('The hvac package is required but is not installed.') from None

        verify = self.engine.ca_cert_path or self.engine.tls_verify
        client = hvac.Client(
            url=self.engine.api_url,
            namespace=self.engine.namespace or None,
            verify=verify,
            session=self._get_session(),
            timeout=30,
        )
        if token:
            client.token = token
        return client

    def _login(self, client):
        """
        Authenticate and return `(token, lease_duration_seconds)`.

        Raises `BackendConfigurationError` when the material is absent — that
        is an operator error, distinct from OpenBao rejecting valid-looking
        material, which is `OpenBaoAuthError`.
        """
        method = self.engine.auth_method
        prefix = self.env_prefix

        try:
            if method == AuthMethodChoices.METHOD_APPROLE:
                role_id = _read_env(f'{prefix}_ROLE_ID')
                secret_id = _read_env(f'{prefix}_SECRET_ID')
                if not role_id or not secret_id:
                    raise BackendConfigurationError(
                        f'AppRole authentication requires {prefix}_ROLE_ID and {prefix}_SECRET_ID '
                        f'in the environment.'
                    )
                response = client.auth.approle.login(role_id=role_id, secret_id=secret_id)

            elif method == AuthMethodChoices.METHOD_TOKEN:
                token = _read_env(f'{prefix}_TOKEN')
                if not token:
                    raise BackendConfigurationError(
                        f'Token authentication requires {prefix}_TOKEN in the environment.'
                    )
                # A static token has no login response to read a lease from;
                # fall back to the configured cache TTL.
                return token, int(get_config('token_cache_ttl') or 3600)

            elif method == AuthMethodChoices.METHOD_KUBERNETES:
                role = _read_env(f'{prefix}_K8S_ROLE')
                jwt_path = os.environ.get(
                    f'{prefix}_K8S_JWT_PATH',
                    '/var/run/secrets/kubernetes.io/serviceaccount/token',
                )
                if not role:
                    raise BackendConfigurationError(
                        f'Kubernetes authentication requires {prefix}_K8S_ROLE in the environment.'
                    )
                try:
                    with open(jwt_path) as f:
                        jwt = f.read().strip()
                except OSError:
                    raise BackendConfigurationError(
                        f'Unable to read the service account token at {jwt_path}.'
                    ) from None
                response = client.auth.kubernetes.login(role=role, jwt=jwt)

            elif method == AuthMethodChoices.METHOD_CERT:
                # Client certificate material is presented by the session's TLS
                # configuration, so there is nothing to read from the
                # environment here.
                response = client.auth.cert.login()

            else:
                raise BackendConfigurationError(f'Unsupported authentication method: {method}.')

        except BackendConfigurationError:
            raise
        except Exception as exc:
            raise self._translate(exc, context='authentication') from None

        auth = (response or {}).get('auth') or {}
        token = auth.get('client_token')
        if not token:
            raise OpenBaoAuthError('OpenBao returned no client token.')
        lease = int(auth.get('lease_duration') or get_config('token_cache_ttl') or 3600)
        return token, lease

    def _get_client(self):
        """Return an authenticated client, reusing a cached token when valid."""
        if self._client is not None:
            return self._client

        token = cache.get(self._cache_key)
        if token:
            self._client = self._build_client(token=token)
            return self._client

        client = self._build_client()
        token, lease = self._login(client)
        client.token = token

        ttl = max(int(lease * TOKEN_CACHE_LEASE_FRACTION), 1)
        cache.set(self._cache_key, token, ttl)

        self._client = client
        return client

    def invalidate_token(self):
        """Drop the cached token so the next call re-authenticates."""
        cache.delete(self._cache_key)
        self._client = None

    # ------------------------------------------------------------------
    # Error translation
    # ------------------------------------------------------------------

    def _translate(self, exc, context=''):
        """
        Map a client exception onto a scrubbed backend exception.

        The incoming message *is* inspected here — that is how a check-and-set
        conflict is distinguished from any other 400 — but it is never carried
        into the returned exception, logged, or chained. Everything downstream
        sees only a fixed string and, at most, a status code.
        """
        try:
            import hvac.exceptions as hvac_exc
        except ImportError:
            return OpenBaoError('OpenBao request failed.')

        status = getattr(exc, 'status_code', None)
        name = type(exc).__name__

        if isinstance(exc, (hvac_exc.Forbidden, hvac_exc.Unauthorized)):
            logger.warning('OpenBao denied a %s request on engine %s (%s)', context, self.engine.slug, name)
            return OpenBaoAuthError(status_code=403)

        if isinstance(exc, hvac_exc.InvalidPath):
            return OpenBaoNotFound(status_code=404)

        if isinstance(exc, hvac_exc.InvalidRequest):
            # OpenBao reports a failed check-and-set as a 400. Read the text to
            # classify it, then discard it.
            text = str(exc).lower()
            if 'check-and-set' in text or 'cas' in text.split():
                return OpenBaoConflict(status_code=409)
            logger.warning('OpenBao rejected a %s request on engine %s', context, self.engine.slug)
            return OpenBaoError('OpenBao rejected the request.', status_code=400)

        if isinstance(exc, (hvac_exc.VaultDown, hvac_exc.VaultNotInitialized)):
            return OpenBaoUnavailable(status_code=503)

        logger.warning(
            'OpenBao %s request failed on engine %s (%s)', context or 'API', self.engine.slug, name
        )
        return OpenBaoUnavailable(status_code=status)

    def _require_kv2(self, operation):
        if self.engine.kv_version != 2:
            raise BackendConfigurationError(
                f'{operation} requires a KV version 2 mount; engine {self.engine.slug} is configured for '
                f'version {self.engine.kv_version}.'
            )

    # ------------------------------------------------------------------
    # SecretBackend implementation
    # ------------------------------------------------------------------

    def read(self, path, version=None):
        client = self._get_client()
        mount = self.engine.kv_mount
        try:
            if self.engine.kv_version == 2:
                response = client.secrets.kv.v2.read_secret_version(
                    path=path,
                    version=version,
                    mount_point=mount,
                    raise_on_deleted_version=True,
                )
                return response['data']['data']
            response = client.secrets.kv.v1.read_secret(path=path, mount_point=mount)
            return response['data']
        except Exception as exc:
            raise self._translate(exc, context='read') from None

    def write(self, path, data, cas=None):
        client = self._get_client()
        mount = self.engine.kv_mount
        try:
            if self.engine.kv_version == 2:
                response = client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=data,
                    cas=cas,
                    mount_point=mount,
                )
                return response['data']['version']
            client.secrets.kv.v1.create_or_update_secret(path=path, secret=data, mount_point=mount)
            return 1
        except Exception as exc:
            raise self._translate(exc, context='write') from None

    def delete(self, path, versions=None):
        client = self._get_client()
        mount = self.engine.kv_mount
        try:
            if self.engine.kv_version == 2:
                if versions:
                    client.secrets.kv.v2.delete_secret_versions(
                        path=path, versions=versions, mount_point=mount
                    )
                else:
                    client.secrets.kv.v2.delete_metadata_and_all_versions(path=path, mount_point=mount)
                return
            client.secrets.kv.v1.delete_secret(path=path, mount_point=mount)
        except Exception as exc:
            raise self._translate(exc, context='delete') from None

    def list_versions(self, path):
        self._require_kv2('Listing versions')
        client = self._get_client()
        try:
            response = client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point=self.engine.kv_mount
            )
        except Exception as exc:
            raise self._translate(exc, context='metadata read') from None

        data = response.get('data') or {}
        versions = []
        for number, meta in (data.get('versions') or {}).items():
            versions.append({
                'version': int(number),
                'created_time': meta.get('created_time'),
                'deletion_time': meta.get('deletion_time') or None,
                'destroyed': bool(meta.get('destroyed')),
            })
        versions.sort(key=lambda v: v['version'], reverse=True)
        return versions

    def read_metadata(self, path):
        """Return the KV v2 metadata envelope at `path`, values excluded."""
        self._require_kv2('Reading metadata')
        client = self._get_client()
        try:
            response = client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point=self.engine.kv_mount
            )
        except Exception as exc:
            raise self._translate(exc, context='metadata read') from None
        return response.get('data') or {}

    def set_metadata(self, path, metadata):
        self._require_kv2('Setting custom metadata')
        client = self._get_client()
        try:
            client.secrets.kv.v2.update_metadata(
                path=path,
                custom_metadata=metadata,
                mount_point=self.engine.kv_mount,
            )
        except Exception as exc:
            raise self._translate(exc, context='metadata write') from None

    def health(self):
        """
        Probe `sys/health`.

        Returns a status rather than raising for a reachable-but-unhealthy
        instance, so the health job can tell "sealed" from "unreachable" — the
        two demand different operator responses.
        """
        client = self._build_client()
        try:
            response = client.sys.read_health_status(method='GET')
        except Exception as exc:
            translated = self._translate(exc, context='health')
            status = (
                EngineStatusChoices.STATUS_UNAUTHORIZED
                if isinstance(translated, OpenBaoAuthError)
                else EngineStatusChoices.STATUS_UNREACHABLE
            )
            return {'status': status, 'message': str(translated), 'raw': None}

        # hvac returns a parsed dict for most health states, but a bare
        # requests.Response for the standby/sealed status codes it does not
        # treat as success.
        if hasattr(response, 'json'):
            try:
                payload = response.json()
            except ValueError:
                payload = {}
        else:
            payload = response or {}

        if not payload.get('initialized', True):
            status = EngineStatusChoices.STATUS_UNREACHABLE
            message = 'Instance is not initialized.'
        elif payload.get('sealed'):
            status = EngineStatusChoices.STATUS_SEALED
            message = 'Instance is sealed.'
        elif payload.get('standby'):
            status = EngineStatusChoices.STATUS_STANDBY
            message = 'Standby node.'
        else:
            status = EngineStatusChoices.STATUS_HEALTHY
            message = f"Version {payload.get('version', 'unknown')}."

        return {'status': status, 'message': message, 'raw': payload}
