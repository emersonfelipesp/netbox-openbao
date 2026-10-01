"""Forward and reverse coverage for the service-endpoint/credential-schema seed migration."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class CredentialTypeSchemaSeedMigrationTest(TransactionTestCase):
    """`0021_service_endpoints_and_credential_schemas` must never clobber an
    existing `CredentialTypeSchema` row, and its reverse must delete only the
    rows it created itself."""

    migrate_from = ('netbox_openbao', '0020_finalization_permissions')
    migrate_to = ('netbox_openbao', '0021_service_endpoints_and_credential_schemas')

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
        self._migrate([self.migrate_from])

    def test_forward_does_not_overwrite_a_preexisting_custom_schema(self):
        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        CredentialTypeSchema = old_apps.get_model('netbox_openbao', 'CredentialTypeSchema')
        custom = CredentialTypeSchema.objects.create(
            name='Operator SSH password',
            slug='ssh_password',
            description='Custom operator-authored schema, not the NMS import seed.',
            schema={
                '$schema': 'https://json-schema.org/draft/2020-12/schema',
                'type': 'object',
                'properties': {'password': {'type': 'string'}, 'note': {'type': 'string'}},
                'required': ['password'],
                'additionalProperties': False,
            },
            secret_fields=['password'],
            extractor='',
        )

        executor = self._migrate([self.migrate_to])
        new_apps = executor.loader.project_state([self.migrate_to]).apps
        NewCredentialTypeSchema = new_apps.get_model('netbox_openbao', 'CredentialTypeSchema')
        preserved = NewCredentialTypeSchema.objects.get(pk=custom.pk)
        self.assertEqual(preserved.description, custom.description)
        self.assertEqual(preserved.schema, custom.schema)
        self.assertEqual(NewCredentialTypeSchema.objects.filter(slug='ssh_password').count(), 1)

        executor = self._migrate([self.migrate_from])
        reverted_apps = executor.loader.project_state([self.migrate_from]).apps
        RevertedCredentialTypeSchema = reverted_apps.get_model('netbox_openbao', 'CredentialTypeSchema')
        still_there = RevertedCredentialTypeSchema.objects.get(pk=custom.pk)
        self.assertEqual(still_there.description, custom.description)
        self.assertEqual(still_there.schema, custom.schema)

    def test_forward_seeds_an_absent_slug_and_reverse_keeps_it(self):
        executor = self._migrate([self.migrate_to])
        new_apps = executor.loader.project_state([self.migrate_to]).apps
        CredentialTypeSchema = new_apps.get_model('netbox_openbao', 'CredentialTypeSchema')
        seeded = CredentialTypeSchema.objects.get(slug='snmp_v2c')
        self.assertEqual(seeded.description, 'Credential schema used by the NMS import for SNMP v2c.')

        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        OldCredentialTypeSchema = old_apps.get_model('netbox_openbao', 'CredentialTypeSchema')
        # Field equality cannot prove ownership, so the reverse never deletes.
        self.assertTrue(OldCredentialTypeSchema.objects.filter(slug='snmp_v2c').exists())


class CredentialImportSourceUniqueMigrationTest(TransactionTestCase):
    """`0022` must apply on a database that already holds duplicate provenance."""

    migrate_from = ('netbox_openbao', '0021_service_endpoints_and_credential_schemas')
    migrate_to = ('netbox_openbao', '0022_credential_import_source_unique')

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        self.addCleanup(lambda: MigrationExecutor(connection).migrate(latest))
        executor.migrate([self.migrate_from])

    def test_duplicates_are_disambiguated_not_deleted(self):
        executor = MigrationExecutor(connection)
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        Credential = old_apps.get_model('netbox_openbao', 'Credential')
        SecretEngine = old_apps.get_model('netbox_openbao', 'SecretEngine')
        CredentialPolicy = old_apps.get_model('netbox_openbao', 'CredentialPolicy')
        engine = SecretEngine.objects.create(
            name='Dup engine', slug='dup-engine', api_url='https://bao.example.net:8200',
        )
        policy = CredentialPolicy.objects.create(
            name='Dup policy', slug='dup-policy', engine=engine, openbao_policy='dup',
        )
        ids = [
            Credential.objects.create(
                name=f'dup-{index}', credential_type='password', policy=policy,
                engine=engine, path=f'dup/{index}', import_source='netbox_nms.DeviceCredential:99',
            ).pk
            for index in range(2)
        ]
        # A value already shaped like a generated replacement must not collide.
        squatter = Credential.objects.create(
            name='squatter', credential_type='password', policy=policy, engine=engine,
            path='dup/squatter', import_source=f'netbox_nms.DeviceCredential:99#duplicate-{max(ids)}',
        )

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        new_apps = executor.loader.project_state([self.migrate_to]).apps
        NewCredential = new_apps.get_model('netbox_openbao', 'Credential')
        rows = {row.pk: row.import_source for row in NewCredential.objects.filter(pk__in=ids)}
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[min(ids)], 'netbox_nms.DeviceCredential:99')
        self.assertEqual(rows[max(ids)], f'netbox_nms.DeviceCredential:99#duplicate-{max(ids)}-1')
        self.assertEqual(
            NewCredential.objects.get(pk=squatter.pk).import_source,
            f'netbox_nms.DeviceCredential:99#duplicate-{max(ids)}',
        )
