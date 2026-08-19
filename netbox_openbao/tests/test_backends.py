"""
Backend behaviour.

Split in two. The unit tests below assert the error-translation contract
without a server, because that contract is about what *doesn't* escape and is
easiest to verify in isolation. The integration tests run against a real
OpenBao dev server when `NETBOX_OPENBAO_TEST_ADDR` is set, because a mock of a
secret store proves nothing about whether `hvac` and OpenBao actually agree on
check-and-set semantics, custom metadata, or version handling.
"""

import os
import unittest

from django.test import TestCase

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


@unittest.skipUnless(TEST_ADDR, 'Set NETBOX_OPENBAO_TEST_ADDR to run OpenBao integration tests')
class OpenBaoIntegrationTest(TestCase):
    """
    Exercises the real wire protocol against a live OpenBao.

    A fake cannot tell you whether hvac and OpenBao agree on what `cas` means,
    or whether `custom_metadata` round-trips — which are precisely the
    behaviours this plugin's correctness depends on.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.environ['NETBOX_BAO_ITEST_TOKEN'] = TEST_TOKEN or 'devroot'

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='Integration',
            slug='itest',
            api_url=TEST_ADDR,
            kv_mount='secret',
            kv_version=2,
            auth_method=AuthMethodChoices.METHOD_TOKEN,
            tls_verify=False,
        )
        self.backend = OpenBaoBackend(self.engine)
        self.path = f'netbox-itest/{self.id().rsplit(".", 1)[-1]}'
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        try:
            self.backend.delete(self.path)
        except OpenBaoError:
            pass

    def test_health_reports_unsealed(self):
        result = self.backend.health()
        self.assertEqual(result['status'], EngineStatusChoices.STATUS_HEALTHY)

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

    def test_bad_token_is_scrubbed_auth_error(self):
        engine = SecretEngine.objects.create(
            name='BadToken', slug='itest-bad', api_url=TEST_ADDR,
            auth_method=AuthMethodChoices.METHOD_TOKEN, tls_verify=False,
        )
        os.environ['NETBOX_BAO_ITEST_BAD_TOKEN'] = 'not-a-real-token'
        backend = OpenBaoBackend(engine)

        with self.assertRaises(OpenBaoError) as ctx:
            backend.read('netbox-itest/anything')
        self.assertNotIn('not-a-real-token', str(ctx.exception))
