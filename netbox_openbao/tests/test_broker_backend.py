"""
Broker mode.

Two halves, for the same reason `test_backends.py` is split. The unit tests pin
the contract that matters in isolation — that nothing the broker says reaches a
caller, and that the same exceptions come out as in direct mode, so nothing
above `SecretBackend` can tell which mode it is in. The integration test runs
against a **real broker in front of a real OpenBao** when its address is set,
because the useful question is not whether a mock returns what the code expects
but whether the two services actually agree on the wire.

Set `NETBOX_OPENBAO_BROKER_ADDR` plus `NETBOX_OPENBAO_BROKER_CERT`,
`NETBOX_OPENBAO_BROKER_KEY`, and `NETBOX_OPENBAO_BROKER_CA` to run it.
"""

import os
import tempfile
import unittest
import uuid

from django.test import TestCase

from netbox_openbao.backends import BACKENDS, get_backend
from netbox_openbao.backends.broker import BrokerBackend
from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)
from netbox_openbao.choices import BackendChoices, EngineStatusChoices
from netbox_openbao.models import SecretEngine

BROKER_ADDR = os.environ.get('NETBOX_OPENBAO_BROKER_ADDR')
BROKER_CERT = os.environ.get('NETBOX_OPENBAO_BROKER_CERT')
BROKER_KEY = os.environ.get('NETBOX_OPENBAO_BROKER_KEY')
BROKER_CA = os.environ.get('NETBOX_OPENBAO_BROKER_CA')


class FakeResponse:
    def __init__(self, status_code=200, payload=None, undecodable=False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._undecodable = undecodable

    def json(self):
        if self._undecodable:
            raise ValueError('not json')
        return self._payload


class FakeSession:
    """Records requests so a test can assert what was — and was not — sent."""

    def __init__(self, response=None, raises=None):
        self.response = response or FakeResponse()
        self.raises = raises
        self.posts = []
        self.gets = []
        self.closed = False

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        if self.raises:
            raise self.raises
        return self.response

    def get(self, url, timeout=None):
        self.gets.append(url)
        if self.raises:
            raise self.raises
        return self.response

    def close(self):
        self.closed = True


def engine(**overrides):
    values = {
        'name': 'Broker', 'slug': 'broker', 'backend': BackendChoices.BACKEND_BROKER,
        'api_url': 'https://broker.invalid:8201', 'kv_mount': 'secret', 'kv_version': 2,
    }
    values.update(overrides)
    return SecretEngine(**values)


def backend(session=None, **overrides):
    instance = BrokerBackend(engine(**overrides))
    if session is not None:
        instance._session = session
    return instance


class BackendSelectionTest(TestCase):

    def test_the_registry_routes_broker_engines_to_the_broker_backend(self):
        self.assertIs(BACKENDS[BackendChoices.BACKEND_BROKER], BrokerBackend)
        self.assertIsInstance(get_backend(engine()), BrokerBackend)

    def test_broker_mode_is_opt_in(self):
        """
        The default deployment must be unchanged — that was an explicit
        acceptance criterion. An engine that says nothing about a backend is
        still a direct OpenBao engine.
        """
        self.assertNotEqual(SecretEngine._meta.get_field('backend').default,
                            BackendChoices.BACKEND_BROKER)


class ClientCertificateTest(TestCase):
    """
    The certificate is the credential. Everything here is about failing loudly
    when it is absent, rather than falling back to something weaker.
    """

    def setUp(self):
        for suffix in ('CLIENT_CERT', 'CLIENT_KEY'):
            os.environ.pop(f'NETBOX_BAO_BROKER_{suffix}', None)

    def test_a_missing_certificate_is_a_configuration_error(self):
        with self.assertRaises(BackendConfigurationError) as caught:
            backend()._client_certificate()

        self.assertIn('CLIENT_CERT', str(caught.exception))

    def test_a_certificate_path_that_does_not_exist_is_refused(self):
        """
        `requests` reports a missing client certificate as an opaque SSLError
        at connection time. Checking first turns that into a sentence naming
        the file — and the path is operator configuration, not material, so
        naming it is safe.
        """
        os.environ['NETBOX_BAO_BROKER_CLIENT_CERT'] = '/nonexistent/broker.pem'
        os.environ['NETBOX_BAO_BROKER_CLIENT_KEY'] = '/nonexistent/broker.key'
        try:
            with self.assertRaises(BackendConfigurationError) as caught:
                backend()._client_certificate()
        finally:
            del os.environ['NETBOX_BAO_BROKER_CLIENT_CERT']
            del os.environ['NETBOX_BAO_BROKER_CLIENT_KEY']

        self.assertIn('/nonexistent/broker.pem', str(caught.exception))

    def test_a_policy_tier_uses_its_own_certificate(self):
        """
        The broker identifies callers by certificate CN, so keying the
        certificate on `env_prefix` is what preserves per-tier separation: a
        tier presents a different certificate and therefore resolves to a
        different broker instance with different path prefixes. Flattening this
        to one certificate would silently give every tier the same access.
        """
        tiered = BrokerBackend(engine(), env_prefix='TIER_PROD')

        with self.assertRaises(BackendConfigurationError) as caught:
            tiered._client_certificate()

        self.assertIn('TIER_PROD_CLIENT_CERT', str(caught.exception))


class TlsVerificationTest(TestCase):
    """
    Direct mode tolerates `tls_verify = False` and the cost is a short-lived
    token presented to whoever answers. Here the client certificate *is* the
    credential and it is long-lived, so an unverified peer is a credential
    handed to a man in the middle.
    """

    def setUp(self):
        self.cert = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        self.key = tempfile.NamedTemporaryFile(suffix='.key', delete=False)
        self.cert.close()
        self.key.close()
        os.environ['NETBOX_BAO_BROKER_CLIENT_CERT'] = self.cert.name
        os.environ['NETBOX_BAO_BROKER_CLIENT_KEY'] = self.key.name

    def tearDown(self):
        for handle in (self.cert, self.key):
            os.unlink(handle.name)
        for name in ('NETBOX_BAO_BROKER_CLIENT_CERT', 'NETBOX_BAO_BROKER_CLIENT_KEY'):
            os.environ.pop(name, None)

    def test_verification_cannot_be_turned_off(self):
        with self.assertRaises(BackendConfigurationError) as caught:
            BrokerBackend(engine(tls_verify=False, ca_cert_path=''))._get_session()

        self.assertIn('TLS verification', str(caught.exception))

    def test_a_ca_path_satisfies_it(self):
        """
        Which is how a self-signed broker certificate is served — so the rule
        above refuses nothing legitimate.
        """
        instance = BrokerBackend(engine(tls_verify=False, ca_cert_path='/etc/ssl/broker-ca.pem'))
        session = instance._get_session()

        self.assertEqual(session.verify, '/etc/ssl/broker-ca.pem')
        self.assertEqual(session.cert, (self.cert.name, self.key.name))


class MalformedResponseTest(TestCase):
    """
    A broker that answers 200 with an unexpected shape — a version skew, a
    proxy that rewrote the body — must not put a `KeyError` through the reveal
    path, which is not written to catch one.
    """

    def test_a_missing_field_is_a_scrubbed_error(self):
        cases = [
            ('read', lambda b: b.read('a/b'), {'wrong': 'shape'}),
            ('write', lambda b: b.write('a/b', {'p': 'x'}), {}),
            ('versions', lambda b: b.list_versions('a/b'), {'data': []}),
            ('metadata', lambda b: b.read_metadata('a/b'), {'data': {}}),
        ]
        for label, call, payload in cases:
            with self.subTest(operation=label):
                with self.assertRaises(OpenBaoError) as caught:
                    call(backend(FakeSession(FakeResponse(200, payload))))
                self.assertNotIsInstance(caught.exception, KeyError)

    def test_a_non_dict_body_is_a_scrubbed_error(self):
        with self.assertRaises(OpenBaoError):
            backend(FakeSession(FakeResponse(200, ['not', 'a', 'dict']))).read('a/b')


class ErrorTranslationTest(TestCase):
    """
    Broker mode must be indistinguishable from direct mode to everything above
    `SecretBackend` — the same exception types for the same conditions.
    """

    def test_status_codes_map_to_the_same_exceptions_as_direct_mode(self):
        cases = [
            (404, OpenBaoNotFound),
            (409, OpenBaoConflict),
            (401, OpenBaoAuthError),
            (403, OpenBaoAuthError),
            (503, OpenBaoUnavailable),
            (502, OpenBaoUnavailable),
            (400, OpenBaoError),
            (418, OpenBaoError),
        ]
        for status, expected in cases:
            with self.subTest(status=status):
                self.assertIsInstance(
                    backend()._translate_status(status, 'read'), expected)

    def test_the_brokers_own_error_text_is_never_relayed(self):
        """
        The broker is written not to leak policy, but the plugin cannot verify
        that from here — and a backend that forwards a remote string has given
        up the guarantee `exceptions.py` exists to provide.
        """
        leaky = FakeResponse(403, {'detail': 'denied on path "secret/data/prod/*"'})

        with self.assertRaises(OpenBaoAuthError) as caught:
            backend(FakeSession(leaky)).read('netbox/credentials/abc')

        self.assertNotIn('secret/data/prod', str(caught.exception))
        self.assertNotIn('denied on path', str(caught.exception))

    def test_a_transport_failure_becomes_unavailable_not_a_traceback(self):
        broken = FakeSession(raises=OSError('connection reset by peer'))

        with self.assertRaises(OpenBaoUnavailable) as caught:
            backend(broken).read('netbox/credentials/abc')

        self.assertNotIn('connection reset', str(caught.exception))

    def test_an_undecodable_body_is_an_error_not_a_crash(self):
        with self.assertRaises(OpenBaoError):
            backend(FakeSession(FakeResponse(200, undecodable=True))).read('a/b')

    def test_a_v1_engine_is_refused_before_any_request(self):
        session = FakeSession()

        with self.assertRaises(BackendConfigurationError):
            backend(session, kv_version=1).read('netbox/credentials/abc')

        self.assertEqual(session.posts, [], 'a refused call still contacted the broker')


class RequestShapeTest(TestCase):
    """
    What actually goes on the wire. The broker validates strictly, so an
    optional field sent as null is a 422 rather than a default.
    """

    def test_read_omits_version_when_none(self):
        session = FakeSession(FakeResponse(200, {'data': {'password': 'x'}}))
        self.assertEqual(backend(session).read('netbox/credentials/abc'),
                         {'password': 'x'})

        url, body = session.posts[0]
        self.assertEqual(url, 'https://broker.invalid:8201/v1/secret/read')
        self.assertEqual(body, {'path': 'netbox/credentials/abc'})

    def test_write_sends_cas_when_given_and_omits_it_when_not(self):
        session = FakeSession(FakeResponse(200, {'version': 3}))
        instance = backend(session)

        self.assertEqual(instance.write('a/b', {'p': 'x'}, cas=0), 3)
        self.assertEqual(session.posts[-1][1]['cas'], 0)

        instance.write('a/b', {'p': 'x'})
        self.assertNotIn('cas', session.posts[-1][1])

    def test_delete_distinguishes_versions_from_the_whole_path(self):
        """
        The distinction this plugin's rotation path depends on: deleting
        specific versions, versus destroying every version at a path.
        """
        session = FakeSession(FakeResponse(200, {'deleted': True}))
        instance = backend(session)

        instance.delete('a/b', versions=[1, 2])
        self.assertEqual(session.posts[-1][1]['versions'], [1, 2])

        instance.delete('a/b')
        self.assertNotIn('versions', session.posts[-1][1])

    def test_the_mount_is_never_sent(self):
        """
        The mount is the broker's own configuration. Sending it would let a
        compromised NetBox address mounts the operator never granted, which is
        the opposite of what this mode is for.
        """
        session = FakeSession(FakeResponse(200, {'data': {}}))
        backend(session, kv_mount='some-other-mount').read('a/b')

        self.assertNotIn('mount', str(session.posts[-1][1]))
        self.assertNotIn('some-other-mount', str(session.posts[-1][1]))


class HealthTest(TestCase):

    def test_a_healthy_broker_reports_the_version_behind_it(self):
        session = FakeSession(FakeResponse(200, {
            'ok': True, 'openbao': {'reachable': True, 'sealed': False, 'version': '2.6.0'}}))

        result = backend(session).health()

        self.assertEqual(result['status'], EngineStatusChoices.STATUS_HEALTHY)
        self.assertIn('2.6.0', result['message'])

    def test_a_sealed_instance_behind_a_healthy_broker(self):
        session = FakeSession(FakeResponse(200, {
            'ok': True, 'openbao': {'reachable': True, 'sealed': True}}))

        self.assertEqual(backend(session).health()['status'],
                         EngineStatusChoices.STATUS_SEALED)

    def test_a_reachable_broker_that_cannot_reach_openbao_says_so(self):
        """
        Two different problems with two different fixes. Collapsing them into
        "unreachable" sends an operator to restart the wrong service.
        """
        session = FakeSession(FakeResponse(200, {
            'ok': True, 'openbao': {'reachable': False, 'sealed': None}}))

        result = backend(session).health()

        self.assertEqual(result['status'], EngineStatusChoices.STATUS_UNREACHABLE)
        self.assertIn('cannot reach OpenBao', result['message'])

    def test_a_refused_certificate_is_unauthorized_not_unreachable(self):
        session = FakeSession(FakeResponse(403))

        self.assertEqual(backend(session).health()['status'],
                         EngineStatusChoices.STATUS_UNAUTHORIZED)

    def test_a_misconfigured_engine_reports_rather_than_raising(self):
        """
        `health()` is called by a background job that distinguishes states by
        return value. A configuration error — no client certificate, or TLS
        verification disabled — must come back as a status with a message
        naming the fix, not as an exception the job has to catch.
        """
        for suffix in ('CLIENT_CERT', 'CLIENT_KEY'):
            os.environ.pop(f'NETBOX_BAO_BROKER_{suffix}', None)

        result = BrokerBackend(engine()).health()

        self.assertEqual(result['status'], EngineStatusChoices.STATUS_UNREACHABLE)
        self.assertIn('CLIENT_CERT', result['message'])

    def test_an_unreachable_broker_does_not_raise(self):
        """
        The health job distinguishes states by return value, so this must
        report rather than raise however badly it fails.
        """
        session = FakeSession(raises=OSError('no route to host'))
        result = backend(session).health()

        self.assertEqual(result['status'], EngineStatusChoices.STATUS_UNREACHABLE)
        self.assertNotIn('no route to host', result['message'])


@unittest.skipUnless(
    BROKER_ADDR and BROKER_CERT and BROKER_KEY,
    'Set NETBOX_OPENBAO_BROKER_ADDR/_CERT/_KEY to run broker integration tests',
)
class BrokerIntegrationTest(TestCase):
    """
    The plugin, a real broker, and a real OpenBao, over real mTLS.

    A mock proves that the code sends what its author thought the broker wanted.
    This proves the two agree.
    """

    def setUp(self):
        os.environ['NETBOX_BAO_BROKER_CLIENT_CERT'] = BROKER_CERT
        os.environ['NETBOX_BAO_BROKER_CLIENT_KEY'] = BROKER_KEY
        self.engine = engine(api_url=BROKER_ADDR, ca_cert_path=BROKER_CA or '')
        self.backend = BrokerBackend(self.engine)
        # A fresh path per test, because `cas=0` means "must not already
        # exist". A shared path only works if cleanup does, and a broker
        # instance configured `may_delete = false` is a perfectly reasonable
        # production posture — the first run of this suite against one failed
        # exactly that way.
        self.path = f'netbox/credentials/integration-{uuid.uuid4()}'

    def tearDown(self):
        try:
            self.backend.delete(self.path)
        except OpenBaoError:
            # Best effort. The instance may not be permitted to delete.
            pass
        for name in ('NETBOX_BAO_BROKER_CLIENT_CERT', 'NETBOX_BAO_BROKER_CLIENT_KEY'):
            os.environ.pop(name, None)

    def test_the_full_round_trip(self):
        version = self.backend.write(self.path, {'username': 'admin', 'password': 'hunter2'}, cas=0)
        self.assertEqual(version, 1)

        self.assertEqual(
            self.backend.read(self.path), {'username': 'admin', 'password': 'hunter2'})

        second = self.backend.write(self.path, {'username': 'admin', 'password': 'rotated'}, cas=1)
        self.assertEqual(second, 2)

        # The version-scoped read the rotation path depends on.
        self.assertEqual(self.backend.read(self.path, version=1)['password'], 'hunter2')

        versions = self.backend.list_versions(self.path)
        self.assertEqual([v['version'] for v in versions], [2, 1])

        self.backend.set_metadata(self.path, {'netbox_object': 'dcim.device:1'})
        self.assertEqual(
            self.backend.read_metadata(self.path)['custom_metadata'],
            {'netbox_object': 'dcim.device:1'},
        )

    def test_a_stale_check_and_set_is_a_conflict(self):
        self.backend.write(self.path, {'password': 'first'}, cas=0)
        with self.assertRaises(OpenBaoConflict):
            self.backend.write(self.path, {'password': 'second'}, cas=0)

    def test_a_missing_path_is_not_found(self):
        with self.assertRaises(OpenBaoNotFound):
            self.backend.read('netbox/credentials/definitely-absent')

    def test_a_path_outside_the_brokers_policy_is_refused(self):
        """
        The point of the whole mode. NetBox asks for something the broker was
        never configured to serve this instance, and is refused *by the broker*
        — the plugin's own permission model is not involved.
        """
        with self.assertRaises(OpenBaoAuthError):
            self.backend.read('production/root')

    def test_health_reports_through_the_broker(self):
        result = self.backend.health()
        self.assertEqual(result['status'], EngineStatusChoices.STATUS_HEALTHY)
