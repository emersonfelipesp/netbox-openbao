"""0025 carries endpoint pins and SSH keys onto the Application Service."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class DropServiceEndpointMigrationTest(TransactionTestCase):
    migrate_from = ('netbox_openbao', '0024_engine_auth_material')
    migrate_to = ('netbox_openbao', '0025_application_service_connection')

    @staticmethod
    def _migrate(targets):
        executor = MigrationExecutor(connection)
        executor.migrate(targets)
        return executor

    def setUp(self):
        super().setUp()
        self.latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        self.addCleanup(self._migrate, self.latest)
        self.old = self._migrate([self.migrate_from]).loader.project_state([self.migrate_from]).apps

    def _seed(self):
        apps = self.old
        CT = apps.get_model('contenttypes', 'ContentType')
        User = apps.get_model('users', 'User')
        Engine = apps.get_model('netbox_openbao', 'SecretEngine')
        Policy = apps.get_model('netbox_openbao', 'CredentialPolicy')
        Credential = apps.get_model('netbox_openbao', 'Credential')
        Assignment = apps.get_model('netbox_openbao', 'CredentialAssignment')
        Endpoint = apps.get_model('netbox_openbao', 'ServiceEndpoint')
        Key = apps.get_model('netbox_openbao', 'SSHPublicKey')
        Service = apps.get_model('ipam', 'Service')
        service_ct = CT.objects.get(app_label='ipam', model='service')
        device_ct = CT.objects.get(app_label='dcim', model='device')
        engine = Engine.objects.create(name='E', slug='e', api_url='https://bao.example.net:8200')
        policy = Policy.objects.create(name='P', slug='p', engine=engine, openbao_policy='p')
        credential = Credential.objects.create(
            name='c', credential_type='ssh-password', policy=policy, engine=engine, username='root',
        )
        service = Service.objects.create(
            name='SSH', port_mappings=['tcp/22'], parent_object_type=service_ct, parent_object_id=1,
        )
        assignment = Assignment.objects.create(
            credential=credential, assigned_object_type=service_ct, assigned_object_id=service.pk, purpose='login',
        )
        user = User.objects.create(username='u')
        mapped = Endpoint.objects.create(
            assigned_object_type=service_ct, assigned_object_id=service.pk, service_type='ssh', host='192.0.2.1',
            port=22, credential=credential, ssh_known_hosts_entry='192.0.2.1 ssh-ed25519 AAAA',
            ssh_strict_host_key_checking=False,
        )
        unmapped = Endpoint.objects.create(
            assigned_object_type=device_ct, assigned_object_id=1, service_type='ssh', host='192.0.2.2', port=22,
        )
        Key.objects.create(
            user=user, service_endpoint=mapped, public_key='k1', fingerprint='f1', key_type='ssh-ed25519',
        )
        Key.objects.create(
            user=user, service_endpoint=unmapped, public_key='k2', fingerprint='f2', key_type='ssh-ed25519',
        )
        return assignment, service

    def test_pins_and_keys_move_to_service_and_unmapped_keys_drop(self):
        assignment, service = self._seed()
        new = self._migrate([self.migrate_to]).loader.project_state([self.migrate_to]).apps
        moved = new.get_model('netbox_openbao', 'CredentialAssignment').objects.get(pk=assignment.pk)
        self.assertEqual(moved.ssh_known_hosts_entry, '192.0.2.1 ssh-ed25519 AAAA')
        self.assertFalse(moved.ssh_strict_host_key_checking)
        keys = new.get_model('netbox_openbao', 'SSHPublicKey').objects.all()
        self.assertEqual([key.application_service_id for key in keys], [service.pk])
        with self.assertRaises(LookupError):
            new.get_model('netbox_openbao', 'ServiceEndpoint')

    def test_upgrade_without_endpoint_rows_succeeds(self):
        new = self._migrate([self.migrate_to]).loader.project_state([self.migrate_to]).apps
        self.assertEqual(new.get_model('netbox_openbao', 'SSHPublicKey').objects.count(), 0)

    def _endpoint(self, apps, service, credential, **extra):
        CT = apps.get_model('contenttypes', 'ContentType')
        Endpoint = apps.get_model('netbox_openbao', 'ServiceEndpoint')
        return Endpoint.objects.create(
            assigned_object_type=CT.objects.get(app_label='ipam', model='service'),
            assigned_object_id=service.pk, service_type='ssh', host='192.0.2.5', credential=credential, **extra,
        )

    def test_endpoint_only_credential_link_gets_an_assignment(self):
        assignment, service = self._seed()
        Credential = self.old.get_model('netbox_openbao', 'Credential')
        Assignment = self.old.get_model('netbox_openbao', 'CredentialAssignment')
        other = Credential.objects.create(
            name='c2', credential_type='ssh-password', policy_id=assignment.credential.policy_id,
            engine_id=assignment.credential.engine_id, username='u2', path='secret/c2',
        )
        self._endpoint(self.old, service, other, port=2222, ssh_known_hosts_entry='pin')
        Assignment.objects.filter(credential=other).delete()
        new = self._migrate([self.migrate_to]).loader.project_state([self.migrate_to]).apps
        created = new.get_model('netbox_openbao', 'CredentialAssignment').objects.get(credential_id=other.pk)
        self.assertEqual(created.assigned_object_id, service.pk)
        self.assertEqual(created.ssh_known_hosts_entry, 'pin')

    def test_different_keys_for_one_user_and_service_stop_the_migration(self):
        assignment, service = self._seed()
        Key = self.old.get_model('netbox_openbao', 'SSHPublicKey')
        user_id = Key.objects.first().user_id
        second = self._endpoint(self.old, service, None, port=2222)
        Key.objects.create(
            user_id=user_id, service_endpoint=second, public_key='other', fingerprint='f3', key_type='ssh-ed25519',
        )
        # The failed upgrade leaves the old schema; clear the conflict before the latest-state cleanup runs.
        self.addCleanup(Key.objects.all().delete)
        with self.assertRaises(RuntimeError):
            self._migrate([self.migrate_to])

    def test_conflicting_host_key_settings_stop_the_migration(self):
        assignment, service = self._seed()
        Endpoint = self.old.get_model('netbox_openbao', 'ServiceEndpoint')
        self._endpoint(self.old, service, assignment.credential, port=2222, ssh_strict_host_key_checking=True)
        self.addCleanup(Endpoint.objects.all().delete)
        with self.assertRaises(RuntimeError):
            self._migrate([self.migrate_to])

    def test_other_purpose_assignment_is_not_mistaken_for_login(self):
        assignment, service = self._seed()
        Assignment = self.old.get_model('netbox_openbao', 'CredentialAssignment')
        Assignment.objects.filter(pk=assignment.pk).update(purpose='enable')
        Endpoint = self.old.get_model('netbox_openbao', 'ServiceEndpoint')
        Endpoint.objects.filter(assigned_object_id=service.pk).update(ssh_known_hosts_entry='', service_type='ssh')
        new = self._migrate([self.migrate_to]).loader.project_state([self.migrate_to]).apps
        rows = new.get_model('netbox_openbao', 'CredentialAssignment').objects.filter(
            credential_id=assignment.credential_id,
        )
        self.assertEqual(sorted(r.purpose for r in rows), ['enable', 'login'])

    def test_endpoint_and_key_of_a_deleted_service_do_not_block_the_upgrade(self):
        assignment, service = self._seed()
        Service = self.old.get_model('ipam', 'Service')
        Endpoint = self.old.get_model('netbox_openbao', 'ServiceEndpoint')
        Assignment = self.old.get_model('netbox_openbao', 'CredentialAssignment')
        # Generic relations leave rows behind when the service is deleted.
        Assignment.objects.filter(pk=assignment.pk).delete()
        Service.objects.filter(pk=service.pk).delete()
        self.assertTrue(Endpoint.objects.filter(assigned_object_id=service.pk).exists())
        new = self._migrate([self.migrate_to]).loader.project_state([self.migrate_to]).apps
        self.assertEqual(new.get_model('netbox_openbao', 'SSHPublicKey').objects.count(), 0)
