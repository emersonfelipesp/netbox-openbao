import json
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.core.management import call_command
from django.db import IntegrityError, close_old_connections, connection

from netbox_openbao.management.commands.openbao_import_nms_credentials import IMPORT_STARTED_RECORD, Command
from netbox_openbao.models import Credential

from .base import OpenBaoTransactionTestCase, seed_nms_credential_schemas
from .fakes import FakeBackend

EMPTY_ID_MAP = {
    'netbox_nms.DeviceCredential': {},
    'netbox_network.DeviceService': {},
    'netbox_network.UserSSHKey': {},
    'netbox_nms.ProxmoxEndpointSSHBinding': {},
    'netbox_nms.CloudVMCredential': {},
    'netbox_nms.ObservabilitySecret': {},
}


class NMSImportCommandTest(OpenBaoTransactionTestCase):
    def setUp(self):
        super().setUp()
        # A TransactionTestCase flushes data after every test, including the
        # CredentialTypeSchema rows migration 0024 seeds once when the test
        # database is built. The import command's non-built-in credential
        # types ('ssh_password', 'ssh_key') depend on those rows existing.
        seed_nms_credential_schemas()

    def test_missing_source_plugins_is_a_clean_no_op(self):
        output = StringIO()
        with patch(
            'netbox_openbao.management.commands.openbao_import_nms_credentials.apps.is_installed',
            return_value=False,
        ):
            call_command('openbao_import_nms_credentials', stdout=output)
        self.assertEqual(Credential.objects.count(), 0)
        rendered = output.getvalue()
        self.assertEqual(rendered.splitlines(keepends=True)[0], IMPORT_STARTED_RECORD)
        self.assertEqual(rendered.count(IMPORT_STARTED_RECORD), 1)
        self.assertIn('not installed', rendered)
        summary = json.loads(rendered.splitlines()[-1])
        self.assertEqual(summary, EMPTY_ID_MAP)
        self.assertEqual(len(summary), 6)

    def test_dry_run_never_writes_database_or_backend(self):
        output = StringIO()
        fake_model = SimpleNamespace(objects=SimpleNamespace(count=lambda: 3))
        with patch.object(Command, '_available_models', return_value={'netbox_nms.DeviceCredential': fake_model}):
            call_command('openbao_import_nms_credentials', '--dry-run', stdout=output)
        rendered = output.getvalue()
        self.assertEqual(rendered.splitlines(keepends=True)[0], IMPORT_STARTED_RECORD)
        self.assertEqual(rendered.count(IMPORT_STARTED_RECORD), 1)
        summary = json.loads(rendered.splitlines()[-1])
        self.assertEqual(summary, EMPTY_ID_MAP)
        self.assertEqual(len(summary), 6)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(FakeBackend.store, {})

    def test_device_credential_import_is_idempotent(self):
        source_type = type('DeviceCredential', (), {})
        source = source_type()
        source.pk = 17
        source._meta = SimpleNamespace(app_label='netbox_nms')
        source.name = 'router login'
        source.username = 'admin'
        source.ssh_private_key_encrypted = ''
        source.ssh_private_key_passphrase_encrypted = ''
        source.password_encrypted = 'configured'
        source.get_password = lambda: 'import-command-canary'
        source.services = SimpleNamespace(all=lambda: [])

        command = Command()
        first = command._device_credential(source, self.policy)
        second = command._device_credential(source, self.policy)

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(Credential.objects.count(), 1)
        self.assertEqual(FakeBackend.store[first.path], [{'password': 'import-command-canary'}])

    @staticmethod
    def _device_credential_source(pk, *, material='concurrent-import-canary'):
        source_type = type('DeviceCredential', (), {})
        source = source_type()
        source.pk = pk
        source._meta = SimpleNamespace(app_label='netbox_nms')
        source.name = f'router {pk} login'
        source.username = 'admin'
        source.ssh_private_key_encrypted = ''
        source.ssh_private_key_passphrase_encrypted = ''
        source.password_encrypted = 'configured'
        source.get_password = lambda: material
        source.services = SimpleNamespace(all=lambda: [])
        return source

    def test_integrity_error_recovery_never_writes_a_second_backend_path(self):
        """Directly exercise the `IntegrityError` branch of `_create_credential`
        without relying on `_existing_credential` mocking to reach it."""
        source = self._device_credential_source(pk=202)
        command = Command()
        winner = command._device_credential(source, self.policy)
        stored_before = dict(FakeBackend.store)

        with (
            patch.object(Command, '_existing_credential', return_value=None),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials.store_credential',
                side_effect=IntegrityError('duplicate key value violates unique constraint'),
            ),
        ):
            result = command._create_credential(
                source, self.policy, 'ssh_password', {'password': 'must-never-be-written'},
                username=source.username, name=source.name,
            )

        self.assertEqual(result.pk, winner.pk)
        self.assertEqual(Credential.objects.count(), 1)
        self.assertEqual(FakeBackend.store, stored_before)

    def test_concurrent_import_of_the_same_source_row_creates_exactly_one_credential(self):
        """Two threads racing `_create_credential` for the same source row
        must be serialized by the advisory lock down to one committed row
        and one OpenBao path, not two."""
        source = self._device_credential_source(pk=303, material='thread-race-canary')

        def worker():
            close_old_connections()
            try:
                connection.ensure_connection()
                return Command()._device_credential(source, self.policy)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            results = [future.result(timeout=30) for future in futures]

        self.assertEqual(results[0].pk, results[1].pk)
        self.assertEqual(Credential.objects.count(), 1)
        winner = Credential.objects.get(import_source='netbox_nms.DeviceCredential:303')
        self.assertEqual(FakeBackend.store[winner.path], [{'password': 'thread-race-canary'}])


class DeviceServiceReconciliationTest(OpenBaoTransactionTestCase):
    """A re-import must update an existing `ServiceEndpoint`, not merely
    return it unchanged — most importantly the credential, which is commonly
    still null on the run that first creates the endpoint."""

    def setUp(self):
        super().setUp()
        seed_nms_credential_schemas()
        site = Site.objects.create(name='Site', slug='site')
        manufacturer = Manufacturer.objects.create(name='Maker', slug='maker')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Model', slug='model')
        role = DeviceRole.objects.create(name='Role', slug='role')
        self.device = Device.objects.create(name='router', site=site, device_type=device_type, role=role)

    @staticmethod
    def _device_service_source(device, *, pk=555, port=22, host='10.0.0.1', credential_id=None):
        source_type = type('DeviceService', (), {})
        source = source_type()
        source.pk = pk
        source.service_type = 'ssh'
        source.assigned_object = device
        source.device = device
        source.port = port
        source.get_management_address = lambda: host
        source.ssh_known_hosts_entry = ''
        source.ssh_strict_host_key_checking = True
        source.credential_id = credential_id
        return source

    def test_reconciles_credential_host_and_port_added_on_a_later_run(self):
        source = self._device_service_source(self.device)
        command = Command()

        first = command._device_service(source, self.policy)
        self.assertIsNone(first.credential)
        self.assertEqual(first.host, '10.0.0.1')

        credential_source = NMSImportCommandTest._device_credential_source(pk=17)
        credential = command._device_credential(credential_source, self.policy)

        # A later run: the source row itself has picked up the new
        # credential and a corrected host, exactly as a re-scrape of the
        # legacy system would.
        source.credential_id = credential_source.pk
        source.get_management_address = lambda: '10.0.0.2'

        second = command._device_service(source, self.policy)

        self.assertEqual(second.pk, first.pk)
        second.refresh_from_db()
        self.assertEqual(second.credential_id, credential.pk)
        self.assertEqual(second.host, '10.0.0.2')
