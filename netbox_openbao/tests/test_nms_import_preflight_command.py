import json
from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection
from django.test.utils import CaptureQueriesContext

from netbox_openbao.management.commands.openbao_import_nms_credentials_preflight import Command
from netbox_openbao.models import Credential

from .base import OpenBaoTestCase
from .fakes import FakeBackend


class NMSImportPreflightCommandTest(OpenBaoTestCase):
    @staticmethod
    def _plugin_model_counts():
        return {
            model._meta.label: model._default_manager.count()
            for model in apps.get_app_config('netbox_openbao').get_models()
            if model._meta.managed and not model._meta.proxy
        }

    def _call(self):
        output = StringIO()
        call_command('openbao_import_nms_credentials_preflight', stdout=output)
        return output.getvalue()

    @staticmethod
    def _record(output):
        if isinstance(output, StringIO):
            output = output.getvalue()
        lines = output.splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert set(record) == {
            'version', 'action', 'category', 'process_started', 'summary',
        }
        return record

    def test_success_is_one_compact_closed_record_and_performs_only_bounded_reads(self):
        model_counts = self._plugin_model_counts()
        backend_before = dict(FakeBackend.store)

        with CaptureQueriesContext(connection) as queries:
            output = self._call()

        self.assertNotIn(' ', output.strip())
        self.assertEqual(self._record(output), {
            'version': 1,
            'action': 'preflight',
            'category': 'complete',
            'process_started': True,
            'summary': None,
        })
        self.assertTrue(queries.captured_queries)
        self.assertTrue(all(query['sql'].lstrip().upper().startswith('SELECT') for query in queries.captured_queries))
        self.assertEqual(self._plugin_model_counts(), model_counts)
        self.assertEqual(FakeBackend.store, backend_before)

    def test_missing_policy_is_a_closed_configuration_failure_without_writes(self):
        self.policy.delete()
        model_counts = self._plugin_model_counts()
        output = StringIO()

        with (
            CaptureQueriesContext(connection) as queries,
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            call_command('openbao_import_nms_credentials_preflight', stdout=output)

        self.assertEqual(self._record(output)['category'], 'configuration')
        self.assertTrue(all(query['sql'].lstrip().upper().startswith('SELECT') for query in queries.captured_queries))
        self.assertEqual(self._plugin_model_counts(), model_counts)
        self.assertEqual(FakeBackend.store, {})

    def test_invalid_configuration_never_reflects_value_or_exception(self):
        output = StringIO()
        hostile = 'https://user:secret@example.invalid/private/path'

        with (
            patch.object(Command, '_static_configuration_is_ready', side_effect=RuntimeError(hostile)),
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            call_command('openbao_import_nms_credentials_preflight', stdout=output)

        rendered = output.getvalue()
        self.assertEqual(self._record(rendered)['category'], 'configuration')
        self.assertNotIn(hostile, rendered)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(FakeBackend.store, {})

    def test_database_failure_never_reflects_exception_or_attempts_model_reads(self):
        output = StringIO()
        hostile = 'postgres://user:secret@example.invalid/private'

        with (
            patch.object(Command, '_database_is_ready', side_effect=DatabaseError(hostile)),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.'
                'CredentialPolicy.objects.exists',
            ) as policy_exists,
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            call_command('openbao_import_nms_credentials_preflight', stdout=output)

        rendered = output.getvalue()
        self.assertEqual(self._record(rendered)['category'], 'database')
        self.assertNotIn(hostile, rendered)
        policy_exists.assert_not_called()
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(FakeBackend.store, {})

    def test_startup_failure_is_closed_and_stops_before_configuration_or_database(self):
        output = StringIO()

        with (
            patch.object(Command, '_startup_is_ready', return_value=False),
            patch.object(Command, '_static_configuration_is_ready') as configuration,
            patch.object(Command, '_database_is_ready') as database,
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            call_command('openbao_import_nms_credentials_preflight', stdout=output)

        self.assertEqual(self._record(output.getvalue())['category'], 'startup')
        configuration.assert_not_called()
        database.assert_not_called()
