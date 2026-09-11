"""
Backend behaviour.

Split in two. The unit tests assert the error-translation contract without a
server, because that contract is about what *doesn't* escape and is easiest to
verify in isolation. The integration tests run against real servers when their
addresses are set, because a mock of a secret store proves nothing about
whether `hvac` and the server actually agree on check-and-set semantics,
custom metadata, or version handling.

The integration contract is shared between OpenBao and Vault on purpose: a
Vault backend tested only against OpenBao would prove exactly nothing about
Vault.
"""

import ast
import os
import unittest
from pathlib import Path

from django.test import TestCase, TransactionTestCase

import netbox_openbao
from netbox_openbao.backends import BACKENDS, SecretBackend, get_backend
from netbox_openbao.backends.exceptions import (
    OpenBaoAuthError,
    OpenBaoConflict,
    OpenBaoError,
    OpenBaoNotFound,
    OpenBaoUnavailable,
)
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import AuthMethodChoices, EngineStatusChoices
from netbox_openbao.models import SecretEngine

TEST_ADDR = os.environ.get('NETBOX_OPENBAO_TEST_ADDR')
TEST_TOKEN = os.environ.get('NETBOX_OPENBAO_TEST_TOKEN')

VAULT_TEST_ADDR = os.environ.get('NETBOX_VAULT_TEST_ADDR')
VAULT_TEST_TOKEN = os.environ.get('NETBOX_VAULT_TEST_TOKEN')


class ErrorTranslationTest(TestCase):
    """
    Every client exception must become a scrubbed plugin exception.

    Uses the real `hvac.exceptions` classes so the mapping cannot silently rot
    if hvac reorganises its hierarchy.
    """

    def setUp(self):
        self.engine = SecretEngine(
            name='Test', slug='test', api_url='https://bao.invalid:8200', kv_mount='secret',
        )
        self.backend = OpenBaoBackend(self.engine)

    def test_forbidden_becomes_scrubbed_auth_error(self):
        import hvac.exceptions as hvac_exc

        # A real Forbidden body can enumerate policy rules; simulate one.
        original = hvac_exc.Forbidden('1 error occurred: permission denied on path "secret/data/prod/*"')
        translated = self.backend._translate(original, context='read')

        self.assertIsInstance(translated, OpenBaoAuthError)
        self.assertNotIn('secret/data/prod', str(translated))
        self.assertNotIn('permission denied', str(translated))

    def test_invalid_path_becomes_not_found(self):
        import hvac.exceptions as hvac_exc

        translated = self.backend._translate(hvac_exc.InvalidPath('nope'), context='read')
        self.assertIsInstance(translated, OpenBaoNotFound)

    def test_check_and_set_failure_becomes_conflict(self):
        import hvac.exceptions as hvac_exc

        original = hvac_exc.InvalidRequest('check-and-set parameter did not match the current version')
        translated = self.backend._translate(original, context='write')

        self.assertIsInstance(translated, OpenBaoConflict)
        self.assertEqual(translated.status_code, 409)

    def test_other_bad_request_is_not_a_conflict(self):
        import hvac.exceptions as hvac_exc

        translated = self.backend._translate(hvac_exc.InvalidRequest('missing client token'), context='write')
        self.assertNotIsInstance(translated, OpenBaoConflict)
        self.assertIsInstance(translated, OpenBaoError)
        self.assertNotIn('client token', str(translated))

    def test_vault_down_becomes_unavailable(self):
        import hvac.exceptions as hvac_exc

        translated = self.backend._translate(hvac_exc.VaultDown('sealed'), context='health')
        self.assertIsInstance(translated, OpenBaoUnavailable)

    def test_unknown_exception_is_still_scrubbed(self):
        translated = self.backend._translate(RuntimeError('connection to 10.0.0.5 refused'), context='read')
        self.assertIsInstance(translated, OpenBaoError)
        self.assertNotIn('10.0.0.5', str(translated))


class BackendSelectionTest(TestCase):
    """`SecretEngine.backend` decides which implementation is used."""

    def _engine(self, backend):
        return SecretEngine(
            name=f'E-{backend}', slug=f'e-{backend}', backend=backend,
            api_url='https://bao.invalid:8200',
        )

    def test_openbao_is_the_default(self):
        engine = SecretEngine(name='D', slug='d', api_url='https://bao.invalid:8200')
        self.assertIsInstance(get_backend(engine), BACKENDS['openbao'])

    def test_vault_engine_resolves_to_the_vault_backend(self):
        self.assertIsInstance(get_backend(self._engine('vault')), BACKENDS['vault'])

    def test_unknown_backend_degrades_to_the_default(self):
        """
        An engine row written by a newer plugin version must not take every
        credential on it offline; the two implementations are compatible.
        """
        engine = self._engine('something-newer')
        self.assertIsInstance(get_backend(engine), OpenBaoBackend)


class _BackendCallScanner(ast.NodeVisitor):
    """
    Collects every attribute called on something that is a backend.

    A backend is recognised two ways, and both are needed:

    * a local name bound from `get_backend(...)`, whatever it is called;
    * a name literally spelled `backend`, which covers parameters and
      attributes the assignment scan cannot see.

    The first is what makes the guard survive a rename. Scanning only for the
    literal name `backend` meant `store = get_backend(...)` followed by
    `store.read_metadata(...)` was invisible — so a routine variable rename
    would have quietly disarmed the contract check while every test still
    passed.

    It is deliberately syntactic and its limits are honest ones: a backend
    reached through `getattr`, stored on an object and called through a long
    attribute chain, or passed through a collection is not seen. None of those
    patterns exists in this package, and `BackendContractTest` fails if the
    scanner stops finding the call sites that do.
    """

    def __init__(self):
        self.aliases = {'backend'}
        self.methods = set()

    def visit_Assign(self, node):
        if self._is_get_backend(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self._is_get_backend(node.value):
            if isinstance(node.target, ast.Name):
                self.aliases.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in self.aliases:
                self.methods.add(func.attr)
        self.generic_visit(node)

    @staticmethod
    def _is_get_backend(value):
        if not isinstance(value, ast.Call):
            return False
        func = value.func
        if isinstance(func, ast.Name):
            return func.id == 'get_backend'
        return isinstance(func, ast.Attribute) and func.attr == 'get_backend'


def _scan_source(source):
    """Run the scanner over one module's source. Separated so it is testable."""
    scanner = _BackendCallScanner()
    # Two passes: assignments anywhere in the module must be known before the
    # calls are matched, and a call can precede its own assignment lexically
    # only in code the scanner would not understand anyway — but a second walk
    # costs nothing and removes the ordering question entirely.
    tree = ast.parse(source)
    scanner.visit(tree)
    scanner.methods.clear()
    scanner.visit(tree)
    return scanner.methods


def _methods_called_on_backends():
    """
    Every method the plugin calls on a `SecretBackend`, read from the source.

    Derived rather than transcribed, because a hand-maintained list is a second
    place to forget: adding `backend.some_method()` while omitting the abstract
    declaration would leave a transcribed test green and reproduce exactly the
    deferred failure this contract exists to prevent.
    """
    package = Path(netbox_openbao.__file__).parent
    found = set()

    for path in package.rglob('*.py'):
        if 'tests' in path.relative_to(package).parts:
            continue
        found |= _scan_source(path.read_text())

    return found


class BackendContractTest(TestCase):
    """
    The ABC has to enumerate everything the plugin calls on a backend.

    Its whole reason for existing is that a third party can implement it
    without forking — so a method the plugin depends on but does not declare is
    a trap: the subclass imports, instantiates, passes every abstract-method
    check, and fails later inside a background job. `read_metadata` was exactly
    that, called by `CredentialVerifyJob` and satisfied only by the coincidence
    that all three shipped backends happened to implement it.
    """

    def test_every_method_the_plugin_calls_is_abstract(self):
        """
        The guard that would have caught the original defect.

        Scanned from the package source, so it cannot be defeated by the same
        omission it exists to detect.
        """
        called = _methods_called_on_backends()
        undeclared = called - set(SecretBackend.__abstractmethods__)

        self.assertEqual(
            undeclared, set(),
            f'The plugin calls {sorted(undeclared)} on a backend, but SecretBackend does not '
            f'declare them. A third-party backend would import, instantiate, pass every '
            f'abstract-method check, and then fail at the call site. Add @abstractmethod.',
        )

    def test_the_scan_finds_known_call_sites(self):
        """
        The scanner itself must fail when it stops seeing anything.

        A source scan that silently matches nothing passes the test above
        vacuously — the failure mode where a guard reports success because it
        could not evaluate the property at all.
        """
        called = _methods_called_on_backends()
        for known in ('read', 'write', 'delete', 'read_metadata', 'set_metadata'):
            self.assertIn(
                known, called,
                f'The call-site scan no longer sees backend.{known}(), so it is not '
                f'checking anything. Fix the scan before trusting the test above.',
            )

    def test_the_scan_survives_a_renamed_backend_variable(self):
        """
        The mutation that would otherwise disarm this guard silently.

        Matching only a receiver literally named `backend` meant a routine
        rename — `store = get_backend(...)` — hid every call on it while the
        known-call-site test above still passed on the remaining ones.
        """
        source = (
            'def verify(credential):\n'
            '    store = get_backend(credential.engine, credential.policy)\n'
            '    return store.read_metadata(credential.path)\n'
        )
        self.assertIn('read_metadata', _scan_source(source))

    def test_the_scan_still_sees_a_plainly_named_backend(self):
        """A parameter or attribute the assignment scan cannot reach."""
        source = (
            'def use(backend, path):\n'
            '    return backend.list_versions(path)\n'
        )
        self.assertIn('list_versions', _scan_source(source))

    def test_the_scan_ignores_unrelated_receivers(self):
        """
        The scan must not be so eager that it manufactures requirements.

        A method on something that is not a backend appearing in
        `__abstractmethods__` would be a different kind of wrong.
        """
        source = (
            'def unrelated(credential):\n'
            '    credential.save()\n'
            '    other = build_something()\n'
            '    other.frobnicate()\n'
        )
        self.assertEqual(_scan_source(source), set())

    def test_subclass_missing_a_required_method_cannot_be_instantiated(self):
        required = sorted(SecretBackend.__abstractmethods__)
        for omitted in required:
            with self.subTest(omitted=omitted):
                namespace = {
                    name: (lambda self, *a, **kw: None)
                    for name in required if name != omitted
                }
                partial = type('PartialBackend', (SecretBackend,), namespace)
                with self.assertRaises(TypeError):
                    partial(SecretEngine(name='P', slug='p', api_url='https://bao.invalid:8200'))

    def test_shipped_backends_satisfy_the_contract(self):
        engine = SecretEngine(name='S', slug='s', api_url='https://bao.invalid:8200')
        for name, backend_class in BACKENDS.items():
            with self.subTest(backend=name):
                # Instantiation alone — no connection is opened here, so this
                # stays a contract check rather than an integration test.
                self.assertIsInstance(backend_class(engine), SecretBackend)


class ConfigurationTest(TestCase):

    def test_kv_v1_engine_rejects_version_specific_operations(self):
        engine = SecretEngine(name='V1', slug='v1', api_url='https://bao.invalid:8200', kv_version=1)
        backend = OpenBaoBackend(engine)

        with self.assertRaises(Exception) as ctx:
            backend.list_versions('netbox/credentials/x')
        self.assertIn('version 2', str(ctx.exception))

    def test_missing_approle_material_is_a_configuration_error(self):
        """
        Absent environment material is an operator error, reported distinctly
        from OpenBao rejecting material that looked valid.
        """
        from netbox_openbao.backends.exceptions import BackendConfigurationError

        engine = SecretEngine(
            name='NoEnv', slug='no-env-here', api_url='https://bao.invalid:8200',
            auth_method=AuthMethodChoices.METHOD_APPROLE,
        )
        backend = OpenBaoBackend(engine)

        with self.assertRaises(BackendConfigurationError) as ctx:
            backend._login(backend._build_client())
        self.assertIn('NETBOX_BAO_NO_ENV_HERE_ROLE_ID', str(ctx.exception))


class _KVIntegrationTests:
    """
    The wire-protocol contract, run against a real server.

    Subclasses supply `server_addr`, `server_token`, `backend_value`, and
    `engine_slug`. If a subclass ever needs to override one of these tests, the
    divergence belongs in that backend class with a comment explaining what
    actually differs — not papered over here.
    """

    server_addr = None
    server_token = None
    backend_value = None
    engine_slug = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        prefix = f"NETBOX_BAO_{cls.engine_slug.upper().replace('-', '_')}"
        os.environ[f'{prefix}_TOKEN'] = cls.server_token or 'devroot'

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name=f'Integration {self.backend_value}',
            slug=self.engine_slug,
            backend=self.backend_value,
            api_url=self.server_addr,
            kv_mount='secret',
            kv_version=2,
            auth_method=AuthMethodChoices.METHOD_TOKEN,
            tls_verify=False,
        )
        # Resolved through the registry, so the engine's `backend` value is
        # part of what is under test rather than bypassed.
        self.backend = get_backend(self.engine)
        self.path = f'netbox-itest/{self.backend_value}/{self.id().rsplit(".", 1)[-1]}'
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        try:
            self.backend.delete(self.path)
        except OpenBaoError:
            pass

    def test_backend_class_matches_the_engine(self):
        self.assertIsInstance(self.backend, BACKENDS[self.backend_value])

    def test_health_reports_unsealed(self):
        result = self.backend.health()
        self.assertEqual(result['status'], EngineStatusChoices.STATUS_HEALTHY)
        # Both servers must expose every field the base parser reads.
        for field in ('initialized', 'sealed', 'standby', 'version'):
            self.assertIn(field, result['raw'])

    def test_write_then_read_roundtrip(self):
        version = self.backend.write(self.path, {'password': 'hunter2'}, cas=0)
        self.assertEqual(version, 1)
        self.assertEqual(self.backend.read(self.path), {'password': 'hunter2'})

    def test_cas_zero_refuses_to_overwrite(self):
        """The guarantee the create path relies on."""
        self.backend.write(self.path, {'password': 'first'}, cas=0)
        with self.assertRaises(OpenBaoConflict):
            self.backend.write(self.path, {'password': 'second'}, cas=0)
        self.assertEqual(self.backend.read(self.path), {'password': 'first'})

    def test_cas_stale_version_refuses(self):
        """The guarantee the rotation path relies on."""
        self.backend.write(self.path, {'password': 'v1'}, cas=0)
        self.backend.write(self.path, {'password': 'v2'}, cas=1)
        with self.assertRaises(OpenBaoConflict):
            self.backend.write(self.path, {'password': 'v3'}, cas=1)

    def test_versions_are_listed_newest_first(self):
        self.backend.write(self.path, {'password': 'v1'}, cas=0)
        self.backend.write(self.path, {'password': 'v2'}, cas=1)

        versions = self.backend.list_versions(self.path)
        self.assertEqual([v['version'] for v in versions], [2, 1])

    def test_specific_version_can_be_read(self):
        self.backend.write(self.path, {'password': 'v1'}, cas=0)
        self.backend.write(self.path, {'password': 'v2'}, cas=1)

        self.assertEqual(self.backend.read(self.path, version=1), {'password': 'v1'})
        self.assertEqual(self.backend.read(self.path, version=2), {'password': 'v2'})

    def test_version_scoped_delete_leaves_the_others(self):
        """
        What staged rotation's discard depends on, and what the write-path
        compensator depends on for a rotation.
        """
        self.backend.write(self.path, {'password': 'v1'}, cas=0)
        self.backend.write(self.path, {'password': 'v2'}, cas=1)

        self.backend.delete(self.path, versions=[2])

        self.assertEqual(self.backend.read(self.path, version=1), {'password': 'v1'})
        listed = {v['version']: v for v in self.backend.list_versions(self.path)}
        self.assertTrue(listed[2]['deletion_time'] or listed[2]['destroyed'])

    def test_custom_metadata_roundtrips(self):
        self.backend.write(self.path, {'password': 'x'}, cas=0)
        self.backend.set_metadata(self.path, {
            'managed_by': 'netbox-openbao',
            'netbox_credential_id': '42',
        })

        metadata = self.backend.read_metadata(self.path)
        self.assertEqual(metadata['custom_metadata']['managed_by'], 'netbox-openbao')
        self.assertEqual(metadata['current_version'], 1)

    def test_missing_path_raises_not_found(self):
        with self.assertRaises(OpenBaoNotFound):
            self.backend.read('netbox-itest/definitely-absent')

    def test_delete_destroys_every_version(self):
        self.backend.write(self.path, {'password': 'v1'}, cas=0)
        self.backend.write(self.path, {'password': 'v2'}, cas=1)

        self.backend.delete(self.path)
        with self.assertRaises(OpenBaoNotFound):
            self.backend.read(self.path)

    def test_full_write_path_against_a_real_server(self):
        """
        `store_credential` end to end, not just `set_metadata` in isolation.

        Every other integration test here calls one backend method with values
        chosen by the test. This one lets the plugin build its own
        custom_metadata and send it, which is how an empty value reached a real
        server unnoticed while 200-odd unit tests stayed green.
        """
        from netbox_openbao.choices import CredentialTypeChoices
        from netbox_openbao.models import Credential, CredentialPolicy
        from netbox_openbao.services import write_material

        policy = CredentialPolicy.objects.create(
            name=f'ITest {self.backend_value}', slug=f'{self.engine_slug}-policy',
            engine=self.engine, openbao_policy='netbox-itest',
        )
        credential = Credential(
            name=f'itest {self.backend_value}',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=policy, engine=self.engine,
        )
        # A brand-new credential has no assignments, which is exactly the case
        # that produced an empty custom_metadata value.
        credential, version = write_material(credential, {'password': 'hunter2'})
        self.addCleanup(lambda: self._safe_delete(credential.path))

        self.assertEqual(version, 1)
        self.assertEqual(self.backend.read(credential.path), {'password': 'hunter2'})

        metadata = self.backend.read_metadata(credential.path)['custom_metadata'] or {}
        self.assertEqual(metadata.get('managed_by'), 'netbox-openbao')
        for key, value in metadata.items():
            self.assertTrue(value, f'custom_metadata["{key}"] is empty')

    def _safe_delete(self, path):
        try:
            self.backend.delete(path)
        except OpenBaoError:
            pass

    def test_bad_token_is_scrubbed_auth_error(self):
        slug = f'{self.engine_slug}-bad'
        engine = SecretEngine.objects.create(
            name=f'BadToken {self.backend_value}', slug=slug,
            backend=self.backend_value, api_url=self.server_addr,
            auth_method=AuthMethodChoices.METHOD_TOKEN, tls_verify=False,
        )
        os.environ[f"NETBOX_BAO_{slug.upper().replace('-', '_')}_TOKEN"] = 'not-a-real-token'
        backend = get_backend(engine)

        with self.assertRaises(OpenBaoError) as ctx:
            backend.read('netbox-itest/anything')
        self.assertNotIn('not-a-real-token', str(ctx.exception))


@unittest.skipUnless(TEST_ADDR, 'Set NETBOX_OPENBAO_TEST_ADDR to run OpenBao integration tests')
class OpenBaoIntegrationTest(_KVIntegrationTests, TransactionTestCase):
    server_addr = TEST_ADDR
    server_token = TEST_TOKEN
    backend_value = 'openbao'
    engine_slug = 'itest-openbao'


@unittest.skipUnless(VAULT_TEST_ADDR, 'Set NETBOX_VAULT_TEST_ADDR to run Vault integration tests')
class VaultIntegrationTest(_KVIntegrationTests, TransactionTestCase):
    """
    The same contract, against HashiCorp Vault.

    Vault's `sys/health` returns a strict superset of OpenBao's payload, so no
    override is needed for it here. Any behaviour that does diverge should fail
    one of these and be handled in `backends/vault.py`.
    """

    server_addr = VAULT_TEST_ADDR
    server_token = VAULT_TEST_TOKEN
    backend_value = 'vault'
    engine_slug = 'itest-vault'
