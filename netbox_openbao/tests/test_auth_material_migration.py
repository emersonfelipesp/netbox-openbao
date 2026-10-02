"""Forward/import/reverse coverage for retained legacy identity metadata."""

import io
import os
from unittest.mock import patch
from uuid import uuid4

from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class LegacyPolicyPrefixMigrationTest(TransactionTestCase):
    migrate_from = ('netbox_openbao', '0023_seed_ssh_service_template')
    migrate_to = ('netbox_openbao', '0024_engine_auth_material')

    @staticmethod
    def _migrate(targets):
        executor = MigrationExecutor(connection)
        executor.migrate(targets)
        return executor

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        self.latest_targets = executor.loader.graph.leaf_nodes()
        self.addCleanup(self._migrate, self.latest_targets)
        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        SecretEngine = old_apps.get_model('netbox_openbao', 'SecretEngine')
        CredentialPolicy = old_apps.get_model('netbox_openbao', 'CredentialPolicy')
        suffix = uuid4().hex[:10]
        engine = SecretEngine.objects.create(
            name=f'Legacy engine {suffix}',
            slug=f'legacy-engine-{suffix}',
            api_url='https://bao.invalid:8200',
        )
        self.policy_slug = f'legacy-policy-{suffix}'
        self.prefix = f'CUSTOM_TIER_{suffix.upper()}'
        self.policy_pk = CredentialPolicy.objects.create(
            name=f'Legacy policy {suffix}',
            slug=self.policy_slug,
            engine=engine,
            openbao_policy=f'policy-{suffix}',
            approle_env_prefix=self.prefix,
        ).pk

    def test_forward_import_and_rollback_preserve_custom_prefix(self):
        executor = self._migrate([self.migrate_to])
        current_apps = executor.loader.project_state([self.migrate_to]).apps
        CurrentPolicy = current_apps.get_model('netbox_openbao', 'CredentialPolicy')
        policy = CurrentPolicy.objects.get(pk=self.policy_pk)
        self.assertEqual(policy.legacy_approle_env_prefix, self.prefix)
        self.assertFalse(CurrentPolicy._meta.get_field('legacy_approle_env_prefix').editable)

        environment = {
            f'{self.prefix}_ROLE_ID': 'custom-prefix-role',
            f'{self.prefix}_SECRET_ID': 'custom-prefix-secret',
        }
        with patch.dict(os.environ, environment, clear=False):
            call_command(
                'openbao_configure',
                'import-env',
                '--policy',
                self.policy_slug,
                stdout=io.StringIO(),
            )

        CurrentMaterial = current_apps.get_model('netbox_openbao', 'EngineAuthMaterial')
        material = CurrentMaterial.objects.get(policy_id=self.policy_pk)
        self.assertTrue(material.role_id_ciphertext)
        self.assertNotIn('custom-prefix-role', material.role_id_ciphertext)

        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        OldPolicy = old_apps.get_model('netbox_openbao', 'CredentialPolicy')
        restored = OldPolicy.objects.get(pk=self.policy_pk)
        self.assertEqual(restored.approle_env_prefix, self.prefix)
