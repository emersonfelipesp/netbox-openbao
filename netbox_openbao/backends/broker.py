"""
Broker mode: talk to a service that holds the AppRole, instead of holding it.

The plugin normally authenticates to OpenBao directly, which means the NetBox
host possesses credentials able to read production secret material. In broker
mode it instead presents a **client certificate** to
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
which holds the AppRole and answers on NetBox's behalf. NetBox keeps something
that lets it *ask*; the broker keeps the thing that can actually *read*.

That the `SecretBackend` ABC already existed is what makes this an addition
rather than a rewrite — nothing above this layer changes.

**What it buys, stated honestly**, because it is easy to oversell and an
operator might relax controls elsewhere on the strength of it:

> It does not make "NetBox compromise ≠ secret compromise" true. An attacker
> with code execution in NetBox can still ask the broker for material, and the
> broker will answer for anything NetBox is authorized to request.

What it does buy is that stealing NetBox's database or configuration no longer
yields credentials that read the vault directly, that the broker's audit log
sits outside NetBox's blast radius, and that the AppRole's SecretID never
exists on the NetBox host at all.

Three things move to the broker's side of the boundary and are therefore
**ignored** on a broker engine — deliberately, because letting NetBox choose
them would widen what a compromised NetBox can address:

* `kv_mount` — the broker reads its own.
* `namespace` — likewise.
* `auth_method` — the client certificate *is* the authentication.

The engine's `api_url` points at the broker, and `ca_cert_path` / `tls_verify`
verify the **broker's** server certificate.
"""

import logging
import os
import threading

from netbox_openbao.choices import EngineStatusChoices

from .base import SecretBackend
from .exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)

__all__ = ('BrokerBackend',)

logger = logging.getLogger('netbox.plugins.netbox_openbao.backends')

# One pooled session per (url, client certificate, verification) triple.
#
# The client certificate is part of the key on purpose. Two policy tiers can
# present *different* certificates to the same broker and therefore resolve to
# different broker instances with different path prefixes — which is the whole
# reason the certificate is keyed on `env_prefix` below. Sharing a session
# across tiers would silently collapse that distinction into whichever
# certificate happened to connect first.
_sessions = {}
_sessions_lock = threading.Lock()

REQUEST_TIMEOUT = 30


class BrokerBackend(SecretBackend):
    """Read/write access to one KV mount, mediated by the broker service."""

    def __init__(self, engine, env_prefix=None):
        super().__init__(engine, env_prefix=env_prefix)
        self._session = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _client_certificate(self):
        """
        Return `(cert_path, key_path)` for this engine's broker identity.

        These are **paths on the NetBox host, not material**, which is why they
        are read straight from the environment rather than through the `_FILE`
        indirection the AppRole uses — there is no value here to keep out of
        `/proc/<pid>/environ`.

        Keying them on `env_prefix` is what lets a `CredentialPolicy` tier
        present its own certificate: the broker identifies callers by the
        subject CN, so a different certificate is a different instance with a
        different set of permitted path prefixes. The tiering that AppRoles
        give you in direct mode is preserved rather than flattened.
        """
        prefix = self.env_prefix
        cert = os.environ.get(f'{prefix}_CLIENT_CERT')
        key = os.environ.get(f'{prefix}_CLIENT_KEY')

        if not cert or not key:
            raise BackendConfigurationError(
                f'Broker mode requires {prefix}_CLIENT_CERT and {prefix}_CLIENT_KEY in the '
                f'environment, each naming a file on the NetBox host.'
            )

        for label, path in (('certificate', cert), ('private key', key)):
            if not os.path.isfile(path):
                # The path is operator configuration, not a secret, so naming
                # it is safe and makes the misconfiguration diagnosable.
                raise BackendConfigurationError(
                    f'The broker client {label} at {path} does not exist or is not a file.'
                )

        return cert, key

    def _get_session(self):
        if self._session is not None:
            return self._session

        try:
            import requests
        except ImportError:
            raise BackendConfigurationError(
                'The requests package is required but is not installed.'
            ) from None

        cert = self._client_certificate()
        verify = self.engine.ca_cert_path or self.engine.tls_verify

        if not verify:
            # Direct mode tolerates `tls_verify = False`, and the cost there is
            # a short-lived token presented to whoever answers. Here the client
            # certificate *is* the credential and it is long-lived, so an
            # unverified peer is a credential handed to a man in the middle.
            # A self-signed broker certificate is served by pointing
            # `ca_cert_path` at it, so this refuses nothing legitimate.
            raise BackendConfigurationError(
                f'Broker mode requires TLS verification: the client certificate is the credential, '
                f'and presenting it to an unverified peer hands it over. Set a CA certificate path '
                f'on engine {self.engine.slug}, or re-enable TLS verification.'
            )

        key = (self.engine.api_url, cert, verify)

        with _sessions_lock:
            if key not in _sessions:
                session = requests.Session()
                session.cert = cert
                session.verify = verify
                _sessions[key] = session
            self._session = _sessions[key]

        return self._session

    def invalidate_token(self):
        """
        Drop the pooled session.

        There is no token to invalidate — that is the point of broker mode —
        but the rest of the plugin calls this after an auth failure, and
        rebuilding the connection is the only useful thing to do here. It also
        picks up a rotated client certificate without a NetBox restart.
        """
        session = self._session
        self._session = None
        if session is None:
            return
        with _sessions_lock:
            for key, pooled in list(_sessions.items()):
                if pooled is session:
                    del _sessions[key]
        session.close()

    # ------------------------------------------------------------------
    # Requests and error translation
    # ------------------------------------------------------------------

    def _post(self, endpoint, payload, context):
        """
        Call one broker endpoint and return its decoded body.

        The broker's own error text is discarded rather than relayed. It is
        written not to leak policy, but the plugin cannot verify that from
        here, and a backend that forwards a remote string has given up the
        guarantee that `exceptions.py` exists to provide.
        """
        session = self._get_session()
        url = f"{self.engine.api_url.rstrip('/')}{endpoint}"

        try:
            response = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            logger.warning(
                'Broker %s request failed on engine %s (%s)',
                context, self.engine.slug, type(exc).__name__,
            )
            raise OpenBaoUnavailable('The broker is unreachable.') from None

        if response.status_code >= 400:
            raise self._translate_status(response.status_code, context)

        try:
            return response.json()
        except ValueError:
            logger.warning('Broker returned an undecodable body for %s on engine %s',
                           context, self.engine.slug)
            raise OpenBaoError('The broker returned an unreadable response.') from None

    def _field(self, payload, name, context):
        """
        Pull one expected field out of a broker response.

        Indexing directly would turn a broker that answered 200 with an
        unexpected shape — a version skew, a proxy that rewrote the body — into
        a `KeyError` escaping the backend, which is precisely the vendor-shaped
        exception the ABC forbids and which the reveal path is not written to
        catch.
        """
        if not isinstance(payload, dict) or name not in payload:
            logger.warning(
                'Broker response for %s on engine %s has no %r field',
                context, self.engine.slug, name,
            )
            raise OpenBaoError('The broker returned an unreadable response.')
        return payload[name]

    def _translate_status(self, status, context):
        """Map a broker status onto the same exceptions the direct backend raises."""
        if status == 404:
            return OpenBaoNotFound(status_code=404)

        if status == 409:
            return OpenBaoConflict(status_code=409)

        if status in (401, 403):
            # Same exception type either way, so nothing above SecretBackend
            # behaves differently — but the two are entirely different operator
            # problems and sending someone to check the wrong one costs an
            # afternoon. Neither message reveals what the broker *would* have
            # allowed, which is the part that had to stay on its side.
            logger.warning(
                'Broker denied a %s request on engine %s (HTTP %s)',
                context, self.engine.slug, status,
            )
            if status == 401:
                return OpenBaoAuthError(
                    'The broker did not accept this NetBox instance\'s client certificate.',
                    status_code=401,
                )
            return OpenBaoAuthError(
                'The broker refused this request for this NetBox instance. Check the instance\'s '
                'permitted path prefixes and whether it may write or delete.',
                status_code=403,
            )

        if status in (502, 503, 504):
            return OpenBaoUnavailable(status_code=status)

        logger.warning(
            'Broker rejected a %s request on engine %s (HTTP %s)',
            context, self.engine.slug, status,
        )
        return OpenBaoError('The broker rejected the request.', status_code=status)

    def _require_kv2(self, operation):
        # The broker speaks KV v2 only, and its mount is its own configuration.
        # A v1 engine pointed at it would fail per-operation and confusingly;
        # saying so here is cheaper than debugging that.
        if self.engine.kv_version != 2:
            raise BackendConfigurationError(
                f'{operation} requires a KV version 2 mount; engine {self.engine.slug} is '
                f'configured for version {self.engine.kv_version}, which the broker does not serve.'
            )

    # ------------------------------------------------------------------
    # SecretBackend implementation
    # ------------------------------------------------------------------

    def read(self, path, version=None):
        self._require_kv2('Reading a secret through the broker')
        payload = {'path': path}
        if version is not None:
            payload['version'] = version
        return self._field(self._post('/v1/secret/read', payload, 'read'), 'data', 'read')

    def write(self, path, data, cas=None):
        self._require_kv2('Writing a secret through the broker')
        payload = {'path': path, 'data': data}
        if cas is not None:
            payload['cas'] = cas
        return self._field(self._post('/v1/secret/write', payload, 'write'), 'version', 'write')

    def delete(self, path, versions=None):
        self._require_kv2('Deleting a secret through the broker')
        payload = {'path': path}
        if versions:
            payload['versions'] = list(versions)
        self._post('/v1/secret/delete', payload, 'delete')

    def list_versions(self, path):
        self._require_kv2('Listing versions through the broker')
        return self._field(
            self._post('/v1/secret/versions', {'path': path}, 'versions'), 'versions', 'versions')

    def read_metadata(self, path):
        self._require_kv2('Reading metadata through the broker')
        return self._field(
            self._post('/v1/secret/metadata/read', {'path': path}, 'metadata read'),
            'metadata', 'metadata read')

    def set_metadata(self, path, metadata):
        self._require_kv2('Setting custom metadata through the broker')
        self._post(
            '/v1/secret/metadata/write',
            {'path': path, 'custom_metadata': metadata},
            'metadata write',
        )

    def health(self):
        """
        Report the health of the OpenBao instance *behind* the broker.

        The broker's `/healthz` is deliberately uninformative — reachability and
        sealed state, nothing about instances, paths, or policy — so this maps
        the little it says onto the same statuses the direct backend produces.
        An unreachable broker and an unreachable OpenBao are different problems
        and the message says which.
        """
        try:
            session = self._get_session()
        except BackendConfigurationError as exc:
            return {
                'status': EngineStatusChoices.STATUS_UNREACHABLE,
                'message': str(exc),
                'raw': None,
            }

        url = f"{self.engine.api_url.rstrip('/')}/healthz"
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            logger.warning(
                'Broker health probe failed on engine %s (%s)',
                self.engine.slug, type(exc).__name__,
            )
            return {
                'status': EngineStatusChoices.STATUS_UNREACHABLE,
                'message': 'The broker is unreachable.',
                'raw': None,
            }

        if response.status_code in (401, 403):
            # `/healthz` needs no application authentication, so a refusal here
            # is the TLS layer: the client certificate is missing, expired, or
            # not signed by the CA the broker trusts.
            return {
                'status': EngineStatusChoices.STATUS_UNAUTHORIZED,
                'message': 'The broker refused this NetBox instance\'s client certificate.',
                'raw': None,
            }

        if response.status_code >= 400:
            return {
                'status': EngineStatusChoices.STATUS_UNREACHABLE,
                'message': f'The broker returned HTTP {response.status_code}.',
                'raw': None,
            }

        try:
            payload = response.json() or {}
        except ValueError:
            payload = {}

        bao = payload.get('openbao') or {}
        if not bao.get('reachable'):
            return {
                'status': EngineStatusChoices.STATUS_UNREACHABLE,
                'message': 'The broker is up, but cannot reach OpenBao.',
                'raw': payload,
            }
        if bao.get('sealed'):
            return {
                'status': EngineStatusChoices.STATUS_SEALED,
                'message': 'Instance is sealed.',
                'raw': payload,
            }

        return {
            'status': EngineStatusChoices.STATUS_HEALTHY,
            'message': f"Version {bao.get('version') or 'unknown'}, through the broker.",
            'raw': payload,
        }
