"""Forward and reverse coverage for the administration foundation migration."""

from uuid import uuid4

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from netbox.models.mixins import OwnerMixin


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


class AuthenticationAdministrationMigrationTest(TransactionTestCase):
    """Prove the audit outcome migration supports forward, reverse, and reapply."""

    migrate_from = ("netbox_openbao", "0012_cluster_lifecycle_permissions")
    migrate_to = ("netbox_openbao", "0013_authentication_administration_permissions")

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
        OpenBaoCluster = old_apps.get_model("netbox_openbao", "OpenBaoCluster")
        OpenBaoAdministrationLog = old_apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
        suffix = uuid4().hex[:12]
        self.cluster_slug = f"migration-cluster-{suffix}"
        cluster = OpenBaoCluster.objects.create(
            name=f"Migration cluster {suffix}",
            slug=self.cluster_slug,
            api_url="https://bao.example.net:8200",
        )
        common = {
            "cluster": cluster,
            "cluster_name_snapshot": cluster.name,
            "cluster_slug_snapshot": cluster.slug,
            "risk_level": "read",
        }
        self.log_pks = {
            "succeeded": OpenBaoAdministrationLog.objects.create(
                **common,
                action="migration-test",
                success=True,
            ).pk,
            "failed": OpenBaoAdministrationLog.objects.create(
                **common,
                action="migration-test-failed",
                success=False,
            ).pk,
            "authorized": OpenBaoAdministrationLog.objects.create(
                **common,
                action="migration-test-authorized",
                success=True,
            ).pk,
        }
        self.addCleanup(self._restore_latest_and_delete)

    def _restore_latest_and_delete(self):
        executor = self._migrate(self.latest_targets)
        apps = executor.loader.project_state(self.latest_targets).apps
        Log = apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
        Cluster = apps.get_model("netbox_openbao", "OpenBaoCluster")
        Log.objects.filter(pk__in=self.log_pks.values()).delete()
        Cluster.objects.filter(slug=self.cluster_slug).delete()

    def _fixture_teardown(self):
        """Avoid the unrelated netbox-proxbox cross-app flush defect in the shared test database."""

    def test_forward_reverse_and_reapply_classify_existing_audit_records(self):
        executor = self._migrate([self.migrate_to])
        current_apps = executor.loader.project_state([self.migrate_to]).apps
        CurrentLog = current_apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
        self.assertEqual(
            {
                outcome: CurrentLog.objects.get(pk=pk).outcome
                for outcome, pk in self.log_pks.items()
            },
            {"succeeded": "succeeded", "failed": "failed", "authorized": "authorized"},
        )

        executor = self._migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        OldLog = old_apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
        self.assertNotIn("outcome", {field.name for field in OldLog._meta.fields})
        self.assertEqual(OldLog.objects.filter(pk__in=self.log_pks.values()).count(), 3)

        executor = self._migrate([self.migrate_to])
        reapplied_apps = executor.loader.project_state([self.migrate_to]).apps
        ReappliedLog = reapplied_apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
        self.assertEqual(
            {
                outcome: ReappliedLog.objects.get(pk=pk).outcome
                for outcome, pk in self.log_pks.items()
            },
            {"succeeded": "succeeded", "failed": "failed", "authorized": "authorized"},
        )


class OpenBaoClusterOwnerStateMigrationTest(TransactionTestCase):
    """Prove the cluster owner state follows the installed NetBox release."""

    migrate_from = ("netbox_openbao", "0013_authentication_administration_permissions")
    migrate_to = ("netbox_openbao", "0014_align_cluster_owner_related_name")

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

    def test_owner_related_name_matches_netbox_core(self):
        executor = self._migrate([self.migrate_to])
        apps = executor.loader.project_state([self.migrate_to]).apps
        Cluster = apps.get_model("netbox_openbao", "OpenBaoCluster")

        expected = OwnerMixin._meta.get_field("owner").remote_field.related_name
        actual = Cluster._meta.get_field("owner").remote_field.related_name

        self.assertEqual(actual, expected)
