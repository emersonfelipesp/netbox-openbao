import json
from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError, OutputWrapper, SystemCheckError
from django.db import DatabaseError
from django.test import SimpleTestCase

from netbox_openbao.management.commands.openbao_import_nms_credentials import (
    IMPORT_STARTED_RECORD,
)
from netbox_openbao.management.commands.openbao_import_nms_credentials import (
    Command as ImportCommand,
)
from netbox_openbao.management.commands.openbao_import_nms_credentials_preflight import (
    Command as PreflightCommand,
)


class RecordingStream(StringIO):
    def __init__(self):
        super().__init__()
        self.flush_count = 0

    def flush(self):
        self.flush_count += 1
        super().flush()


class ImportStartMarkerContractTest(SimpleTestCase):
    def _assert_marker_precedes_model_discovery(self, *, dry_run):
        stream = RecordingStream()
        command = ImportCommand(stdout=stream)
        self.assertIsInstance(command.stdout, OutputWrapper)

        def available_models():
            self.assertEqual(stream.getvalue(), IMPORT_STARTED_RECORD)
            self.assertEqual(stream.flush_count, 1)
            return {}

        policy_query = MagicMock()
        policy_query.select_related.return_value.order_by.return_value.first.return_value = None
        with (
            patch.object(command, '_available_models', side_effect=available_models),
            patch.object(command, '_import_all') as import_all,
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials.'
                'CredentialPolicy.objects',
                policy_query,
            ),
        ):
            command.handle(dry_run=dry_run, id_map=None)

        self.assertTrue(stream.getvalue().startswith(IMPORT_STARTED_RECORD))
        self.assertEqual(stream.getvalue().count(IMPORT_STARTED_RECORD), 1)
        self.assertEqual(stream.flush_count, 1)
        if dry_run:
            import_all.assert_not_called()
        else:
            import_all.assert_called_once()

    def test_marker_is_first_flushed_output_before_dry_run_discovery(self):
        self._assert_marker_precedes_model_discovery(dry_run=True)

    def test_marker_is_first_flushed_output_before_apply_discovery(self):
        self._assert_marker_precedes_model_discovery(dry_run=False)

    def test_discovery_failure_leaves_exactly_one_complete_marker(self):
        stream = RecordingStream()
        command = ImportCommand(stdout=stream)

        with (
            patch.object(command, '_available_models', side_effect=RuntimeError('hostile discovery detail')),
            self.assertRaisesRegex(RuntimeError, 'hostile discovery detail'),
        ):
            command.handle(dry_run=True, id_map=None)

        self.assertEqual(stream.getvalue(), IMPORT_STARTED_RECORD)
        self.assertEqual(stream.flush_count, 1)

    def test_system_check_failure_before_handle_emits_no_marker(self):
        stream = RecordingStream()
        command = ImportCommand(stdout=stream)

        with (
            patch.object(command, 'check', side_effect=SystemCheckError('startup failed')),
            patch.object(command, 'handle') as handle,
            self.assertRaisesRegex(SystemCheckError, 'startup failed'),
        ):
            command.execute(force_color=False, no_color=False, skip_checks=False)

        handle.assert_not_called()
        self.assertEqual(stream.getvalue(), '')
        self.assertEqual(stream.flush_count, 0)

    def test_unknown_command_emits_no_marker(self):
        stream = RecordingStream()

        with self.assertRaisesRegex(CommandError, 'Unknown command'):
            call_command('openbao_import_command_that_does_not_exist', stdout=stream)

        self.assertEqual(stream.getvalue(), '')
        self.assertEqual(stream.flush_count, 0)


class PreflightContractTest(SimpleTestCase):
    maxDiff = None

    @staticmethod
    def _record(output):
        lines = output.splitlines()
        if len(lines) != 1:
            raise AssertionError(f'expected exactly one record, got {lines!r}')
        return json.loads(lines[0])

    def test_effective_database_backed_path_prefix_is_validated(self):
        with (
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.get_config',
                return_value='database/prefix',
            ) as get_config,
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.validate_path_prefix',
            ) as validate,
        ):
            self.assertTrue(PreflightCommand._static_configuration_is_ready())

        get_config.assert_called_once_with('path_prefix', 'netbox')
        validate.assert_called_once_with('database/prefix')

    def test_invalid_effective_prefix_fails_closed(self):
        with patch(
            'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.get_config',
            return_value='../static-prefix-was-valid',
        ):
            self.assertFalse(PreflightCommand._static_configuration_is_ready())

    def test_effective_configuration_exception_fails_closed(self):
        with patch(
            'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.get_config',
            side_effect=RuntimeError('postgres://user:secret@example.invalid/private'),
        ):
            self.assertFalse(PreflightCommand._static_configuration_is_ready())

    def test_success_is_one_bounded_closed_scalar_record(self):
        stream = RecordingStream()
        command = PreflightCommand(stdout=stream)
        policy = MagicMock()
        policy.objects.exists.return_value = True

        with (
            patch.object(command, '_startup_is_ready', return_value=True),
            patch.object(command, '_static_configuration_is_ready', return_value=True),
            patch.object(command, '_database_is_ready', return_value=True),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.CredentialPolicy',
                policy,
            ),
        ):
            command.handle()

        rendered = stream.getvalue()
        self.assertLessEqual(len(rendered.encode()), 128)
        self.assertEqual(rendered.count('\n'), 1)
        self.assertEqual(self._record(rendered), {
            'version': 1,
            'action': 'preflight',
            'category': 'complete',
            'process_started': True,
            'summary': None,
        })
        scalar_values = self._record(rendered).values()
        self.assertTrue(all(value is None or type(value) in (bool, int, str) for value in scalar_values))

    def test_success_stage_order_is_startup_database_configuration_policy(self):
        stream = RecordingStream()
        command = PreflightCommand(stdout=stream)
        stages = []
        policy = MagicMock()
        policy.objects.exists.side_effect = lambda: stages.append('policy') or True

        with (
            patch.object(command, '_startup_is_ready', side_effect=lambda: stages.append('startup') or True),
            patch.object(command, '_database_is_ready', side_effect=lambda: stages.append('database') or True),
            patch.object(
                command,
                '_static_configuration_is_ready',
                side_effect=lambda: stages.append('configuration') or True,
            ),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.CredentialPolicy',
                policy,
            ),
        ):
            command.handle()

        self.assertEqual(stages, ['startup', 'database', 'configuration', 'policy'])
        self.assertEqual(self._record(stream.getvalue())['category'], 'complete')

    def test_startup_failure_stops_and_uses_fixed_stderr(self):
        stdout = RecordingStream()
        stderr = RecordingStream()
        command = PreflightCommand(stdout=stdout, stderr=stderr)

        with (
            patch.object(command, '_startup_is_ready', side_effect=RuntimeError('hostile startup secret')),
            patch.object(command, '_static_configuration_is_ready') as configuration,
            patch.object(command, '_database_is_ready') as database,
            self.assertRaises(SystemExit) as raised,
        ):
            command.run_from_argv([
                'manage.py', 'openbao_import_nms_credentials_preflight', '--skip-checks',
            ])

        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(self._record(stdout.getvalue())['category'], 'startup')
        self.assertEqual(stderr.getvalue(), 'CommandError: netbox-openbao importer preflight failed.\n')
        self.assertNotIn('hostile startup secret', stdout.getvalue() + stderr.getvalue())
        configuration.assert_not_called()
        database.assert_not_called()

    def test_configuration_failure_occurs_after_database_and_stops_before_policy(self):
        stream = RecordingStream()
        command = PreflightCommand(stdout=stream)
        policy = MagicMock()

        with (
            patch.object(command, '_startup_is_ready', return_value=True),
            patch.object(command, '_static_configuration_is_ready', return_value=False),
            patch.object(command, '_database_is_ready', return_value=True) as database,
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.CredentialPolicy',
                policy,
            ),
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            command.handle()

        self.assertEqual(self._record(stream.getvalue())['category'], 'configuration')
        database.assert_called_once_with()
        policy.objects.exists.assert_not_called()

    def test_database_error_from_effective_config_is_a_database_failure(self):
        stream = RecordingStream()
        command = PreflightCommand(stdout=stream)
        policy = MagicMock()
        hostile = 'postgres://user:secret@example.invalid/private'

        with (
            patch.object(command, '_startup_is_ready', return_value=True),
            patch.object(command, '_database_is_ready', return_value=True),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.get_config',
                side_effect=DatabaseError(hostile),
            ),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.CredentialPolicy',
                policy,
            ),
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            command.handle()

        rendered = stream.getvalue()
        self.assertEqual(self._record(rendered)['category'], 'database')
        self.assertNotIn(hostile, rendered)
        policy.objects.exists.assert_not_called()

    def test_database_failure_stops_before_policy_read(self):
        stream = RecordingStream()
        command = PreflightCommand(stdout=stream)
        policy = MagicMock()

        with (
            patch.object(command, '_startup_is_ready', return_value=True),
            patch.object(command, '_static_configuration_is_ready') as configuration,
            patch.object(command, '_database_is_ready', return_value=False),
            patch(
                'netbox_openbao.management.commands.openbao_import_nms_credentials_preflight.CredentialPolicy',
                policy,
            ),
            self.assertRaisesMessage(CommandError, 'netbox-openbao importer preflight failed.'),
        ):
            command.handle()

        self.assertEqual(self._record(stream.getvalue())['category'], 'database')
        configuration.assert_not_called()
        policy.objects.exists.assert_not_called()
