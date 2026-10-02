"""Encrypted service-identity and leak-surface contract."""

import io
import json
import os
import stat
import tempfile
import threading
from queue import Queue
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.events import OBJECT_UPDATED
from core.models import ObjectType
from django.conf import settings
from django.contrib.auth import get_permission_codename
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.db import close_old_connections, transaction
from django.db.models.signals import post_save
from django.http import HttpResponse
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from extras.choices import EventRuleActionChoices
from extras.events import serialize_for_event
from extras.models import EventRule, ExportTemplate, Webhook
from extras.webhooks import send_webhook
from users.models import ObjectPermission
from utilities.testing import APITestCase, ModelViewTestCase

from netbox_openbao.api.serializers import EngineAuthMaterialSerializer
from netbox_openbao.backends import get_backend
from netbox_openbao.backends.broker import BrokerBackend
from netbox_openbao.backends.exceptions import BackendConfigurationError
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.backends.tls import _cleanup_private_files
from netbox_openbao.config import clear_config, get_config
from netbox_openbao.forms import EngineAuthMaterialForm
from netbox_openbao.models import (
    CredentialPolicy,
    EngineAuthMaterial,
    OpenBaoAdministrationLog,
    OpenBaoSettings,
    SecretEngine,
)
from netbox_openbao.models.auth import AUTH_MATERIAL_FIELDS, AuthMaterialDecryptionError
from netbox_openbao.search import SecretEngineIndex
from netbox_openbao.tables import EngineAuthMaterialTable


class AuthMaterialFixture(APITestCase):

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='Encrypted engine',
            slug='encrypted-engine',
            api_url='https://bao.invalid:8200',
        )
        self.material = EngineAuthMaterial(engine=self.engine)
        self.material.set_secret('role_id', 'role-value')
        self.material.set_secret('secret_id', 'secret-value')
        self.material.save()


class EncryptionTest(AuthMaterialFixture):

    def test_round_trip_uses_versioned_ciphertext(self):
        self.assertEqual(self.material.get_secret('role_id'), 'role-value')
        self.assertTrue(self.material.role_id_ciphertext.startswith('v1:'))
        self.assertNotIn('role-value', self.material.role_id_ciphertext)
        self.assertEqual(self.material.ciphertext_version, 'v1')

    @override_settings(SECRET_KEY='a-different-root-of-trust')
    def test_wrong_key_fails_without_exposing_material(self):
        with self.assertRaises(AuthMaterialDecryptionError) as caught:
            self.material.get_secret('role_id')
        self.assertNotIn('role-value', str(caught.exception))
        self.assertNotIn(self.material.role_id_ciphertext, str(caught.exception))

    def test_rotation_invalidates_the_previous_token_cache_key(self):
        old_key = self.material.token_cache_key(self.engine.slug)
        cache.set(old_key, 'cached-token', 60)
        self.material.set_secret('secret_id', 'rotated-value')
        with self.captureOnCommitCallbacks(execute=True):
            self.material.save()
        self.assertIsNone(cache.get(old_key))
        self.assertNotEqual(old_key, self.material.token_cache_key(self.engine.slug))

    def test_queryset_delete_invalidates_the_token_cache_key(self):
        cache_key = self.material.token_cache_key(self.engine.slug)
        cache.set(cache_key, 'cached-token', 60)

        with self.captureOnCommitCallbacks(execute=True):
            EngineAuthMaterial.objects.filter(pk=self.material.pk).delete()

        self.assertIsNone(cache.get(cache_key))


class WriteOnlySurfaceTest(AuthMaterialFixture):

    def test_legacy_policy_prefix_is_migration_metadata_only(self):
        from netbox_openbao.api.serializers import CredentialPolicySerializer
        from netbox_openbao.forms import CredentialPolicyForm
        from netbox_openbao.models import CredentialPolicy
        from netbox_openbao.tables import CredentialPolicyTable

        field = CredentialPolicy._meta.get_field('legacy_approle_env_prefix')
        self.assertFalse(field.editable)
        self.assertNotIn('legacy_approle_env_prefix', CredentialPolicyForm.Meta.fields)
        self.assertNotIn('legacy_approle_env_prefix', CredentialPolicySerializer.Meta.fields)
        self.assertNotIn('legacy_approle_env_prefix', CredentialPolicyTable.Meta.fields)

    def test_rest_output_contains_only_configured_status(self):
        data = EngineAuthMaterialSerializer(self.material).data
        rendered = repr(data)
        self.assertTrue(data['role_id_configured'])
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)
        for name in AUTH_MATERIAL_FIELDS:
            self.assertNotIn(name, data)

    def test_form_blank_keeps_value_and_clear_is_explicit(self):
        keep = EngineAuthMaterialForm(
            data={'engine': self.engine.pk},
            instance=self.material,
        )
        self.assertTrue(keep.is_valid(), keep.errors)
        keep.save()
        self.material.refresh_from_db()
        self.assertEqual(self.material.get_secret('role_id'), 'role-value')

        clear = EngineAuthMaterialForm(
            data={'engine': self.engine.pk, 'clear_role_id': True},
            instance=self.material,
        )
        self.assertTrue(clear.is_valid(), clear.errors)
        clear.save()
        self.material.refresh_from_db()
        self.assertFalse(self.material.is_configured('role_id'))

    def test_changelog_snapshot_excludes_ciphertext(self):
        snapshot = self.material.serialize_object()
        self.assertNotIn('role-value', repr(snapshot))
        self.assertNotIn(self.material.role_id_ciphertext, repr(snapshot))
        self.assertFalse(hasattr(self.material, 'to_objectchange'))

    def test_event_and_webhook_snapshot_excludes_ciphertext(self):
        snapshot = serialize_for_event(self.material)
        self.assertEqual(snapshot['role_id_configured'], True)
        self.assertFalse(any(key.endswith('_ciphertext') for key in snapshot))

        webhook = Webhook.objects.create(
            name='Auth material leak test',
            payload_url='https://webhook.invalid/',
        )
        event_rule = EventRule.objects.create(
            name='Auth material event rule',
            event_types=[OBJECT_UPDATED],
            action_type=EventRuleActionChoices.WEBHOOK,
            action_object_type=ObjectType.objects.get_for_model(Webhook),
            action_object_id=webhook.pk,
        )
        event_rule.object_types.set([ObjectType.objects.get_for_model(EngineAuthMaterial)])

        def capture_request(_session, request, **kwargs):
            del kwargs
            rendered = request.body.decode()
            self.assertNotIn('role-value', rendered)
            self.assertNotIn(self.material.role_id_ciphertext, rendered)
            self.assertNotIn('role_id_ciphertext', rendered)
            return HttpResponse()

        with patch('requests.Session.send', capture_request):
            send_webhook(
                event_rule=event_rule,
                object_type=ObjectType.objects.get_for_model(EngineAuthMaterial),
                event_type=OBJECT_UPDATED,
                data=snapshot,
                timestamp=timezone.now().isoformat(),
                snapshots={'postchange': snapshot},
            )

    @override_settings(LOGIN_REQUIRED=False)
    def test_graphql_surface_is_absent(self):
        query = '{ __schema { types { name fields { name } } } }'
        response = self.client.post(
            reverse('graphql'), json.dumps({'query': query}), content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        rendered = response.content.decode()
        self.assertNotIn('EngineAuthMaterial', rendered)
        self.assertNotIn('role_id_ciphertext', rendered)
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)

        forbidden = self.client.post(
            reverse('graphql'),
            json.dumps({'query': '{ engine_auth_material_list { id } }'}),
            content_type='application/json',
        )
        self.assertEqual(forbidden.status_code, 200)
        self.assertIn('errors', forbidden.json())
        self.assertNotIn('role-value', forbidden.content.decode())

    def test_clone_fields_are_absent(self):
        self.assertFalse(hasattr(EngineAuthMaterial, 'clone_fields'))

    def test_table_has_status_columns_only(self):
        fields = set(EngineAuthMaterialTable.Meta.fields)
        self.assertFalse(any(field.endswith('_ciphertext') for field in fields))
        self.assertTrue(all(f'{name}_configured' in fields for name in AUTH_MATERIAL_FIELDS))

    def test_filterset_excludes_material(self):
        from netbox_openbao.filtersets import EngineAuthMaterialFilterSet

        filter_fields = set(EngineAuthMaterialFilterSet.Meta.fields)
        self.assertFalse(any(name in filter_fields for name in AUTH_MATERIAL_FIELDS))
        self.assertFalse(any(name.endswith('_ciphertext') for name in filter_fields))

    def test_search_index_excludes_auth_material(self):
        self.assertIsNot(SecretEngineIndex.model, EngineAuthMaterial)

    def test_actual_table_and_custom_exports_exclude_material(self):
        self.add_permissions(
            'netbox_openbao.view_engineauthmaterial',
            'extras.view_exporttemplate',
        )
        self.client.force_login(self.user)
        url = reverse('plugins:netbox_openbao:engineauthmaterial_list')
        table = self.client.get(f'{url}?export=table')
        self.assertEqual(table.status_code, 200)
        rendered = table.content.decode()
        self.assertIn('Role ID', rendered)
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)
        self.assertNotIn('role_id_ciphertext', rendered)

        export = ExportTemplate.objects.create(
            name='Auth status export',
            template_code=(
                '{% for obj in queryset %}'
                '{{ obj.role_id_configured }}|{{ obj.role_id_ciphertext }}'
                '{% endfor %}'
            ),
            mime_type='text/plain',
            file_extension='txt',
        )
        export.object_types.set([ObjectType.objects.get_for_model(EngineAuthMaterial)])
        custom = self.client.get(f'{url}?export={export.name}')
        self.assertEqual(custom.status_code, 200)
        rendered = custom.content.decode()
        self.assertIn('True|', rendered)
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)

    def test_administration_audit_has_no_auth_material_target(self):
        fields = {field.name for field in OpenBaoAdministrationLog._meta.get_fields()}
        self.assertFalse(fields.intersection(AUTH_MATERIAL_FIELDS))
        self.assertFalse(any(name.endswith('_ciphertext') for name in fields))

    def test_standard_change_permission_is_dedicated_to_auth_material(self):
        permission = get_permission_codename('change', EngineAuthMaterial._meta)
        self.assertEqual(permission, 'change_engineauthmaterial')


class BackendStoredMaterialTest(AuthMaterialFixture):

    def test_approle_login_uses_decrypted_database_values(self):
        client = Mock()
        client.auth.approle.login.return_value = {
            'auth': {'client_token': 'issued-token', 'lease_duration': 60}
        }
        token, lease = get_backend(self.engine)._login(client)
        client.auth.approle.login.assert_called_once_with(
            role_id='role-value',
            secret_id='secret-value',
        )
        self.assertEqual((token, lease), ('issued-token', 60))

    def test_broker_files_are_0600_and_removed_on_invalidation(self):
        broker = SecretEngine.objects.create(
            name='Broker engine',
            slug='broker-engine',
            backend='broker',
            api_url='https://broker.invalid:8201',
            ca_cert_path='/etc/ssl/certs/ca-certificates.crt',
        )
        material = EngineAuthMaterial(engine=broker)
        material.set_secret('client_cert', '-----BEGIN CERTIFICATE-----\ncertificate\n')
        material.set_secret('client_key', '-----BEGIN PRIVATE KEY-----\nprivate\n')
        material.save()
        backend = BrokerBackend(broker, auth_material=material)
        session = backend._get_session()
        paths = session.cert
        for path in paths:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        material.set_secret('client_key', '-----BEGIN PRIVATE KEY-----\nrotated\n')
        with self.captureOnCommitCallbacks(execute=True):
            material.save()
        self.assertTrue(all(not os.path.exists(path) for path in paths))

        refreshed = EngineAuthMaterial.objects.get(pk=material.pk)
        process_backend = BrokerBackend(broker, auth_material=refreshed)
        process_paths = process_backend._get_session().cert
        _cleanup_private_files()
        self.assertTrue(all(not os.path.exists(path) for path in process_paths))

    def test_kubernetes_path_never_appears_in_an_exception(self):
        self.engine.auth_method = 'kubernetes'
        self.engine.save()
        self.material.set_secret('k8s_role', 'login-role')
        self.material.set_secret('k8s_jwt_path', '/secret/canary/jwt-path')
        self.material.save()

        with patch('builtins.open', side_effect=OSError), self.assertRaises(
            BackendConfigurationError
        ) as caught:
            get_backend(self.engine)._login(Mock())

        self.assertNotIn('/secret/canary/jwt-path', str(caught.exception))

    @override_settings(SECRET_KEY='a-different-root-of-trust')
    def test_warm_cache_cannot_mask_wrong_key_after_forced_reauthentication(self):
        self.engine.auth_method = 'token'
        self.engine.save()
        cache.clear()
        cache.set(self.material.token_cache_key(), 'warm-cached-token', 60)
        client = SimpleNamespace(token=None)
        backend = OpenBaoBackend(self.engine, auth_material=self.material)
        with patch.object(backend, '_build_client', return_value=client) as build_client:
            self.assertIs(backend._get_client(), client)
            build_client.assert_called_once_with(token='warm-cached-token')
            backend.invalidate_token()
            with self.assertRaises(BackendConfigurationError) as caught:
                backend._get_client()
        rendered = str(caught.exception)
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)
        self.assertNotIn('warm-cached-token', rendered)

    def test_backend_exception_and_warning_log_exclude_material(self):
        client = Mock()
        client.auth.approle.login.side_effect = RuntimeError(
            f'upstream included role-value and {self.material.role_id_ciphertext}'
        )
        with self.assertLogs('netbox.plugins.netbox_openbao', level='WARNING') as logs:
            with self.assertRaises(Exception) as caught:
                get_backend(self.engine)._login(client)
        rendered = f'{caught.exception!s} {logs.output!r}'
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)


class ConfigurationCommandTest(AuthMaterialFixture):

    def test_auth_command_reads_secret_from_file(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('new-token')
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        call_command(
            'openbao_configure', 'auth', '--engine', self.engine.slug,
            '--set', 'token', '--file', path, stdout=io.StringIO(),
        )
        self.material.refresh_from_db()
        self.assertEqual(self.material.get_secret('token'), 'new-token')

    def test_reencrypt_command_moves_rows_to_current_secret_key(self):
        old_key = 'old-django-secret-key'
        for name in ('role_id', 'secret_id'):
            self.material.set_secret(name, self.material.get_secret(name), secret_key=old_key)
        self.material.save()
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write(old_key)
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        call_command(
            'openbao_configure', 'reencrypt', '--old-secret-key-file', path,
            stdout=io.StringIO(),
        )
        self.material.refresh_from_db()
        self.assertEqual(self.material.get_secret('secret_id'), 'secret-value')

    def test_import_env_is_an_explicit_one_time_command(self):
        variable = 'NETBOX_BAO_ENCRYPTED_ENGINE_TOKEN'
        with patch.dict(os.environ, {variable: 'legacy-token'}, clear=False):
            call_command(
                'openbao_configure', 'import-env', '--engine', self.engine.slug,
                stdout=io.StringIO(),
            )
        self.material.refresh_from_db()
        self.assertEqual(self.material.get_secret('token'), 'legacy-token')
        self.assertNotIn('legacy-token', self.material.token_ciphertext)

    def test_import_legacy_settings_preserves_nondefault_security_controls(self):
        legacy = {
            'allow_generation': False,
            'assignable_models': ['dcim.site'],
            'assignable_models_deny': ['dcim.device'],
            'reveal_rate_limit': '2/hour',
            'reveal_ttl': 41,
            'token_cache_ttl': 43,
            'audit_retention_days': 47,
            'path_prefix': 'legacy/estate',
            'default_ssh_key_type': 'ecdsa-p256',
            'expiry_warning_days': [21, 3],
            'engine_health_interval': 11,
            'expiry_scan_interval': 12,
            'credential_verify_interval': 13,
            'rotation_due_interval': 14,
            'access_log_prune_interval': 15,
        }
        configured = {**settings.PLUGINS_CONFIG, 'netbox_openbao': legacy}
        output = io.StringIO()
        with override_settings(PLUGINS_CONFIG=configured):
            call_command('openbao_configure', 'import-legacy-settings', stdout=output)
        clear_config()
        self.addCleanup(clear_config)
        for name, value in legacy.items():
            with self.subTest(name=name):
                self.assertEqual(get_config(name), value)
                self.assertIn(f'  {name}: {json.dumps(value)}', output.getvalue())

    def test_import_legacy_settings_dry_run_changes_nothing(self):
        configured = {
            **settings.PLUGINS_CONFIG,
            'netbox_openbao': {'allow_generation': False, 'reveal_ttl': 41},
        }
        with override_settings(PLUGINS_CONFIG=configured):
            call_command(
                'openbao_configure', 'import-legacy-settings', '--dry-run',
                stdout=io.StringIO(),
            )
        self.assertFalse(OpenBaoSettings.objects.exists())

    def _cleanup(self):
        call_command(
            'openbao_configure',
            'cleanup-legacy-prefixes',
            '--confirm-imports-verified',
            stdout=io.StringIO(),
        )

    def _legacy_policy(self):
        return CredentialPolicy.objects.create(
            name='Legacy cleanup policy',
            slug='legacy-cleanup-policy',
            engine=self.engine,
            openbao_policy='legacy-cleanup-policy',
            legacy_approle_env_prefix='CUSTOM_LEGACY_POLICY',
        )

    def test_cleanup_refuses_missing_empty_and_partial_identities(self):
        policy = self._legacy_policy()
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()

        material = EngineAuthMaterial.objects.create(policy=policy)
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()

        material.set_secret('role_id', 'only-half-of-an-approle')
        material.save()
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()

        policy.refresh_from_db()
        self.assertEqual(policy.legacy_approle_env_prefix, 'CUSTOM_LEGACY_POLICY')

    def test_cleanup_accepts_a_complete_identity(self):
        policy = self._legacy_policy()
        material = EngineAuthMaterial.objects.create(policy=policy)
        material.set_secret('role_id', 'role')
        material.set_secret('secret_id', 'secret')
        material.save()
        self._cleanup()
        policy.refresh_from_db()
        self.assertEqual(policy.legacy_approle_env_prefix, '')

    def _policy_on(self, engine, slug):
        return CredentialPolicy.objects.create(
            name=slug, slug=slug, engine=engine, openbao_policy=slug,
            legacy_approle_env_prefix=f'LEGACY_{slug.upper().replace("-", "_")}',
        )

    def test_cleanup_requires_the_identity_for_the_engines_auth_method(self):
        approle_policy = self._legacy_policy()
        wrong = EngineAuthMaterial.objects.create(policy=approle_policy)
        wrong.set_secret('token', 'a-token-is-not-an-approle')
        wrong.save()
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()
        approle_policy.refresh_from_db()
        self.assertEqual(approle_policy.legacy_approle_env_prefix, 'CUSTOM_LEGACY_POLICY')
        approle_policy.delete()

        broker = SecretEngine.objects.create(
            name='Broker engine', slug='broker-engine', api_url='https://broker.example.net',
            backend='broker', auth_method='cert',
        )
        broker_policy = self._policy_on(broker, 'broker-tier')
        wrong = EngineAuthMaterial.objects.create(policy=broker_policy)
        wrong.set_secret('role_id', 'role')
        wrong.set_secret('secret_id', 'secret')
        wrong.save()
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()
        wrong.set_secret('client_cert', 'cert')
        wrong.save()
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()
        wrong.set_secret('client_key', 'key')
        wrong.save()
        self._cleanup()
        broker_policy.refresh_from_db()
        self.assertEqual(broker_policy.legacy_approle_env_prefix, '')

    def test_cleanup_accepts_token_and_kubernetes_identities_for_their_methods(self):
        for method, field, value in (
            ('token', 'token', 'a-token'),
            ('kubernetes', 'k8s_role', 'a-role'),
        ):
            engine = SecretEngine.objects.create(
                name=f'{method} engine', slug=f'{method}-engine',
                api_url=f'https://{method}.example.net', auth_method=method,
            )
            policy = self._policy_on(engine, f'{method}-tier')
            material = EngineAuthMaterial.objects.create(policy=policy)
            material.set_secret(field, value)
            material.save()
        self._cleanup()
        self.assertFalse(
            CredentialPolicy.objects.filter(slug__in=['token-tier', 'kubernetes-tier'])
            .exclude(legacy_approle_env_prefix='').exists()
        )

    def test_failed_import_leaves_no_row_so_cleanup_cannot_be_authorized(self):
        policy = self._legacy_policy()
        env = {k: v for k, v in os.environ.items() if not k.startswith('CUSTOM_LEGACY_POLICY_')}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesMessage(CommandError, 'No legacy variables were found'):
                call_command(
                    'openbao_configure', 'import-env', '--policy', policy.slug,
                    stdout=io.StringIO(),
                )
        self.assertFalse(EngineAuthMaterial.objects.filter(policy=policy).exists())
        with self.assertRaisesMessage(CommandError, 'no complete imported identity'):
            self._cleanup()
        policy.refresh_from_db()
        self.assertEqual(policy.legacy_approle_env_prefix, 'CUSTOM_LEGACY_POLICY')

    def test_show_prints_status_not_plaintext_or_ciphertext(self):
        output = io.StringIO()
        call_command('openbao_configure', 'show', stdout=output)
        rendered = output.getvalue()
        self.assertIn('role_id=configured', rendered)
        self.assertNotIn('role-value', rendered)
        self.assertNotIn(self.material.role_id_ciphertext, rendered)

    def test_settings_and_engine_commands_persist_models(self):
        call_command(
            'openbao_configure', 'settings', '--set', 'reveal_ttl=777',
            stdout=io.StringIO(),
        )
        call_command(
            'openbao_configure', 'engine', '--slug', self.engine.slug,
            '--api-url', 'https://rotated.invalid:8200', stdout=io.StringIO(),
        )
        self.engine.refresh_from_db()
        self.assertEqual(OpenBaoSettings.objects.get().reveal_ttl, 777)
        self.assertEqual(self.engine.api_url, 'https://rotated.invalid:8200')

    def test_connection_command_performs_login_only(self):
        backend = Mock()
        with patch(
            'netbox_openbao.management.commands.openbao_configure.get_backend',
            return_value=backend,
        ):
            call_command(
                'openbao_configure', 'test', '--engine', self.engine.slug,
                stdout=io.StringIO(),
            )
        backend.authenticate.assert_called_once_with()

    def test_legacy_import_session_key_reads_a_protected_file(self):
        from netbox_openbao.management.commands.openbao_import_secrets import Command

        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('legacy-session-key')
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        self.assertEqual(Command()._resolve_session_key(path), 'legacy-session-key')


class PluginsConfigIgnoredMutationTest(TestCase):

    def test_plugins_config_cannot_mutate_a_missing_settings_row(self):
        from netbox_openbao.config import clear_config, get_config

        configured = {**settings.PLUGINS_CONFIG, 'netbox_openbao': {'reveal_ttl': 9999}}
        with override_settings(PLUGINS_CONFIG=configured):
            clear_config()
            self.addCleanup(clear_config)
            self.assertFalse(OpenBaoSettings.objects.exists())
            self.assertEqual(get_config('reveal_ttl'), 300)


class AuthMaterialPermissionTest(APITestCase):

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='Permission engine', slug='permission-engine', api_url='https://bao.invalid:8200',
        )

    def test_create_requires_the_dedicated_auth_material_permission(self):
        url = reverse('plugins-api:netbox_openbao-api:engineauthmaterial-list')
        payload = {'engine': self.engine.pk, 'role_id': 'write-only-role'}

        denied = self.client.post(url, payload, format='json', **self.header)
        self.assertEqual(denied.status_code, 403)

        self.add_permissions(
            'netbox_openbao.add_engineauthmaterial',
            'netbox_openbao.view_secretengine',
        )
        created = self.client.post(url, payload, format='json', **self.header)
        self.assertEqual(created.status_code, 201, created.data)
        self.assertNotIn('role_id', created.data)

    def test_update_requires_change_engineauthmaterial(self):
        material = EngineAuthMaterial(engine=self.engine)
        material.set_secret('role_id', 'first-role')
        material.save()
        url = reverse(
            'plugins-api:netbox_openbao-api:engineauthmaterial-detail',
            kwargs={'pk': material.pk},
        )

        self.add_permissions(
            'netbox_openbao.view_engineauthmaterial',
            'netbox_openbao.view_secretengine',
        )
        denied = self.client.patch(url, {'role_id': 'second-role'}, format='json', **self.header)
        self.assertEqual(denied.status_code, 403)

        self.add_permissions('netbox_openbao.change_engineauthmaterial')
        updated = self.client.patch(url, {'role_id': 'second-role'}, format='json', **self.header)
        self.assertEqual(updated.status_code, 200, updated.data)
        material.refresh_from_db()
        self.assertEqual(material.get_secret('role_id'), 'second-role')


class AuthMaterialUIViewTest(ModelViewTestCase):
    model = EngineAuthMaterial

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='UI auth engine', slug='ui-auth-engine', api_url='https://bao.invalid:8200',
        )

    def test_create_writes_material_without_echoing_it(self):
        self.add_permissions(
            'netbox_openbao.add_engineauthmaterial',
            'netbox_openbao.view_secretengine',
        )
        response = self.client.post(
            reverse('plugins:netbox_openbao:engineauthmaterial_add'),
            {'engine': self.engine.pk, 'role_id': 'ui-write-only-role'},
        )

        form = response.context.get('form') if response.context else None
        self.assertEqual(response.status_code, 302, getattr(form, 'errors', None))
        material = EngineAuthMaterial.objects.get(engine=self.engine)
        self.assertEqual(material.get_secret('role_id'), 'ui-write-only-role')
        self.assertNotIn('ui-write-only-role', response.content.decode())

    def test_edit_page_exposes_neither_plaintext_nor_ciphertext(self):
        material = EngineAuthMaterial(engine=self.engine)
        material.set_secret('role_id', 'ui-hidden-role')
        material.save()
        self.add_permissions(
            'netbox_openbao.view_engineauthmaterial',
            'netbox_openbao.change_engineauthmaterial',
        )

        response = self.client.get(reverse(
            'plugins:netbox_openbao:engineauthmaterial_edit',
            kwargs={'pk': material.pk},
        ))

        self.assertEqual(response.status_code, 200)
        rendered = response.content.decode()
        self.assertNotIn('ui-hidden-role', rendered)
        self.assertNotIn(material.role_id_ciphertext, rendered)


class SettingsSingletonAPITest(APITestCase):

    def _grant(self, actions, *, constraints=None):
        permission = ObjectPermission.objects.create(
            name=f'Settings {" ".join(actions)}',
            actions=actions,
            constraints=constraints,
        )
        permission.object_types.add(ObjectType.objects.get_for_model(OpenBaoSettings))
        permission.users.add(self.user)
        return permission

    def test_get_returns_defaults_without_creating_a_row(self):
        self.add_permissions('netbox_openbao.view_openbaosettings')
        url = reverse('plugins-api:netbox_openbao-api:openbaosettings-singleton')

        response = self.client.get(url, **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['source'], 'default')
        self.assertEqual(response.data['reveal_ttl'], 300)
        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_patch_creates_then_updates_the_singleton(self):
        self.add_permissions(
            'netbox_openbao.add_openbaosettings',
            'netbox_openbao.change_openbaosettings',
            'netbox_openbao.view_openbaosettings',
        )
        url = reverse('plugins-api:netbox_openbao-api:openbaosettings-singleton')

        created = self.client.patch(url, {'reveal_ttl': 601}, format='json', **self.header)
        updated = self.client.patch(url, {'reveal_ttl': 602}, format='json', **self.header)

        self.assertEqual(created.status_code, 200, created.data)
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(OpenBaoSettings.objects.get().reveal_ttl, 602)

    def test_constrained_grant_cannot_read_or_patch_excluded_singleton(self):
        row = OpenBaoSettings.objects.create(reveal_ttl=601)
        self._grant(['view', 'change'], constraints={'pk': row.pk + 1})
        url = reverse('plugins-api:netbox_openbao-api:openbaosettings-singleton')

        fetched = self.client.get(url, **self.header)
        patched = self.client.patch(url, {'reveal_ttl': 602}, format='json', **self.header)

        self.assertEqual(fetched.status_code, 404)
        self.assertEqual(patched.status_code, 404)
        row.refresh_from_db()
        self.assertEqual(row.reveal_ttl, 601)

    def test_change_only_user_cannot_create_missing_singleton(self):
        self.add_permissions('netbox_openbao.change_openbaosettings')
        url = reverse('plugins-api:netbox_openbao-api:openbaosettings-singleton')

        response = self.client.patch(url, {'reveal_ttl': 602}, format='json', **self.header)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_if_match_mismatch_rejects_singleton_patch(self):
        row = OpenBaoSettings.objects.create(reveal_ttl=601)
        self.add_permissions(
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.change_openbaosettings',
        )
        url = reverse('plugins-api:netbox_openbao-api:openbaosettings-singleton')

        response = self.client.patch(
            url,
            {'reveal_ttl': 602},
            format='json',
            HTTP_IF_MATCH='"stale-etag"',
            **self.header,
        )

        self.assertEqual(response.status_code, 412)
        row.refresh_from_db()
        self.assertEqual(row.reveal_ttl, 601)


class ConcurrentAuthMaterialRotationTest(TransactionTestCase):

    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='Concurrent engine',
            slug='concurrent-engine',
            api_url='https://bao.invalid:8200',
            auth_method='token',
        )
        self.material = EngineAuthMaterial(engine=self.engine)
        self.material.set_secret('token', 'initial-token')
        self.material.save()

    def test_concurrent_rotation_and_login_never_reuses_superseded_token(self):
        writer_a = EngineAuthMaterial.objects.get(pk=self.material.pk)
        writer_b = EngineAuthMaterial.objects.get(pk=self.material.pk)
        a_saved = threading.Event()
        b_started = threading.Event()
        b_saved = threading.Event()
        release_a = threading.Event()
        release_b = threading.Event()
        errors = Queue()

        def pause_second_writer(sender, instance, **kwargs):
            del sender, instance, kwargs
            if threading.current_thread().name == 'auth-writer-b':
                b_saved.set()
                if not release_b.wait(10):
                    raise RuntimeError('Timed out waiting to commit writer B.')

        def rotate(instance, value, *, first):
            close_old_connections()
            try:
                with transaction.atomic():
                    instance.set_secret('token', value)
                    if not first:
                        b_started.set()
                    instance.save()
                    if first:
                        a_saved.set()
                        if not release_a.wait(10):
                            raise RuntimeError('Timed out waiting to commit writer A.')
            except Exception as exc:
                errors.put(exc)
            finally:
                close_old_connections()

        post_save.connect(
            pause_second_writer,
            sender=EngineAuthMaterial,
            dispatch_uid='test_concurrent_auth_rotation',
        )
        self.addCleanup(
            post_save.disconnect,
            sender=EngineAuthMaterial,
            dispatch_uid='test_concurrent_auth_rotation',
        )
        first = threading.Thread(
            target=rotate,
            args=(writer_a, 'writer-a-token'),
            kwargs={'first': True},
            name='auth-writer-a',
        )
        second = threading.Thread(
            target=rotate,
            args=(writer_b, 'writer-b-token'),
            kwargs={'first': False},
            name='auth-writer-b',
        )
        first.start()
        self.assertTrue(a_saved.wait(10))
        second.start()
        self.assertTrue(b_started.wait(10))
        release_a.set()
        first.join(10)
        self.assertFalse(first.is_alive())
        self.assertTrue(b_saved.wait(10))

        intermediate = EngineAuthMaterial.objects.get(pk=self.material.pk)
        client = SimpleNamespace(token=None)
        intermediate_backend = OpenBaoBackend(self.engine, auth_material=intermediate)
        with patch.object(intermediate_backend, '_build_client', return_value=client):
            intermediate_backend._get_client()
        self.assertEqual(client.token, 'writer-a-token')
        self.assertEqual(intermediate.revision, 2)

        release_b.set()
        second.join(10)
        self.assertFalse(second.is_alive())
        if not errors.empty():
            raise errors.get()

        final = EngineAuthMaterial.objects.get(pk=self.material.pk)
        final_client = SimpleNamespace(token=None)
        final_backend = OpenBaoBackend(self.engine, auth_material=final)
        with patch.object(final_backend, '_build_client', return_value=final_client):
            final_backend._get_client()
        self.assertEqual(final.revision, 3)
        self.assertEqual(final_client.token, 'writer-b-token')
        self.assertIsNone(cache.get(intermediate.token_cache_key()))

    def test_stale_full_row_saves_merge_independent_secret_fields(self):
        first = EngineAuthMaterial.objects.get(pk=self.material.pk)
        second = EngineAuthMaterial.objects.get(pk=self.material.pk)
        first.set_secret('role_id', 'new-role')
        first.save()
        second.set_secret('secret_id', 'new-secret')
        second.save()

        final = EngineAuthMaterial.objects.get(pk=self.material.pk)
        self.assertEqual(final.get_secret('role_id'), 'new-role')
        self.assertEqual(final.get_secret('secret_id'), 'new-secret')
        self.assertEqual(final.revision, 3)
