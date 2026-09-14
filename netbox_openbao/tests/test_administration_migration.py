"""Forward and reverse coverage for the administration foundation migration."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class AdministrationFoundationMigrationTest(TransactionTestCase):
    migrate_from = ('netbox_openbao', '0010_live_identity_and_policy_lock')
    migrate_to = ('netbox_openbao', '0011_openbao_administration_foundation')

    @staticmethod
    def _migrate(targets):
        executor = MigrationExecutor(connection)
        executor.migrate(targets)
        return executor

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        self.latest_targets = executor.loader.graph.leaf_nodes()
        executor = self._migrate([self.migrate_from])
        self.addCleanup(self._migrate, self.latest_targets)

        old_apps = executor.loader.project_state([self.migrate_from]).apps
        SecretEngine = old_apps.get_model('netbox_openbao', 'SecretEngine')
        self.engine_pk = SecretEngine.objects.create(
            name='Migrated engine',
            slug='migrated-engine',
            api_url='https://bao.example.net:8200',
            namespace='team-a',
            tls_verify=False,
            ca_cert_path='/etc/openbao/ca.pem',
            status='healthy',
            status_message='Version 2.6.2.',
        ).pk

    def test_forward_copy_and_reverse_preserve_the_engine(self):
        executor = self._migrate([self.migrate_to])
        new_apps = executor.loader.project_state([self.migrate_to]).apps
        SecretEngine = new_apps.get_model('netbox_openbao', 'SecretEngine')
        OpenBaoCluster = new_apps.get_model('netbox_openbao', 'OpenBaoCluster')

        engine = SecretEngine.objects.get(pk=self.engine_pk)
        cluster = OpenBaoCluster.objects.get(pk=engine.cluster_id)
        self.assertEqual(cluster.name, engine.name)
        self.assertEqual(cluster.slug, engine.slug)
        self.assertEqual(cluster.api_url, engine.api_url)
        self.assertEqual(cluster.namespace, engine.namespace)
        self.assertEqual(cluster.tls_verify, engine.tls_verify)
        self.assertEqual(cluster.ca_cert_path, engine.ca_cert_path)
        self.assertEqual(cluster.status, engine.status)
        self.assertEqual(cluster.status_message, engine.status_message)

        connection.check_constraints()
        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        OldSecretEngine = old_apps.get_model('netbox_openbao', 'SecretEngine')
        self.assertTrue(OldSecretEngine.objects.filter(pk=self.engine_pk).exists())
