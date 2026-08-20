"""
Write-path behaviour: atomicity, compensation, and audit.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from netbox_openbao.backends.exceptions import OpenBaoConflict
from netbox_openbao.choices import AccessActionChoices, CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAccessLog
from netbox_openbao.services import reveal_material, rotate_material, write_material

from .base import OpenBaoTestCase
from .fakes import FakeBackend

User = get_user_model()


class WritePathTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username='operator')

    def test_write_persists_row_and_material(self):
        credential = self.make_credential()
        _cred, version = write_material(
            credential, {'password': 'hunter2'}, user=self.user,
        )

        self.assertEqual(version, 1)
        self.assertEqual(FakeBackend.store[credential.path], [{'password': 'hunter2'}])
        self.assertEqual(Credential.objects.count(), 1)
        self.assertEqual(Credential.objects.get().kv_version, 1)

    def test_custom_metadata_never_contains_an_empty_value(self):
        """
        OpenBao refuses an empty value in custom_metadata, and
        `netbox_assignments` is empty for every credential at creation time —
        assignments can only be added after the credential exists. Sending it
        made every create fail against a real server.
        """
        credential = self.make_credential()
        write_material(credential, {'password': 'hunter2'}, user=self.user)

        metadata = FakeBackend.metadata[credential.path]
        self.assertNotIn('netbox_assignments', metadata)
        for key, value in metadata.items():
            self.assertTrue(value, f'custom_metadata["{key}"] is empty; OpenBao rejects that')

    def test_assignments_appear_once_they_exist(self):
        """Dropping empty values must not drop the key when it has content."""
        from django.contrib.contenttypes.models import ContentType
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        from netbox_openbao.models import CredentialAssignment

        site = Site.objects.create(name='S', slug='s')
        manufacturer = Manufacturer.objects.create(name='M', slug='m')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='T', slug='t')
        role = DeviceRole.objects.create(name='R', slug='r')
        device = Device.objects.create(
            name='d1', site=site, device_type=device_type, role=role,
        )

        credential = self.make_credential()
        write_material(credential, {'password': 'hunter2'}, user=self.user)
        CredentialAssignment.objects.create(
            credential=credential,
            assigned_object_type=ContentType.objects.get_for_model(Device),
            assigned_object_id=device.pk,
        )

        metadata = FakeBackend.metadata[credential.path]
        self.assertIn('netbox_assignments', metadata)
        self.assertIn(f'dcim.device:{device.pk}', metadata['netbox_assignments'])

    def test_custom_metadata_is_written(self):
        credential = self.make_credential()
        write_material(credential, {'password': 'hunter2'}, user=self.user)

        metadata = FakeBackend.metadata[credential.path]
        self.assertEqual(metadata['managed_by'], 'netbox-openbao')
        self.assertEqual(metadata['netbox_credential_uuid'], str(credential.uuid))
        self.assertEqual(metadata['netbox_policy'], 'lab')

    def test_backend_failure_rolls_back_the_row(self):
        """A failed OpenBao write must not leave an inventory row behind."""
        FakeBackend.fail_on_write = True
        credential = self.make_credential()

        with self.assertRaises(OpenBaoConflict):
            write_material(credential, {'password': 'hunter2'}, user=self.user)

        self.assertEqual(Credential.objects.count(), 0)

    def test_metadata_failure_compensates_the_orphaned_write(self):
        """
        The material landed but the transaction then failed. Django has no
        rollback hook, so the compensator must delete the orphaned path
        explicitly.
        """
        FakeBackend.fail_on_metadata = True
        credential = self.make_credential()

        with self.assertRaises(OpenBaoConflict):
            write_material(credential, {'password': 'hunter2'}, user=self.user)

        self.assertEqual(Credential.objects.count(), 0)
        self.assertNotIn(credential.path, FakeBackend.store)
        # cas=0 on a create means nothing else lived at this path, so the
        # compensator destroys it wholesale (versions=None).
        self.assertEqual(FakeBackend.delete_calls, [(credential.path, None)])

    def test_duplicate_path_is_refused_by_the_database(self):
        """
        Two credentials may never share a path. The unique constraint catches
        this before the backend is reached, which is the stronger guarantee —
        `cas=0` is the second line of defence for material written outside
        NetBox.
        """
        credential = self.make_credential()
        write_material(credential, {'password': 'first'}, user=self.user)

        colliding = self.make_credential(name='colliding')
        colliding.path = credential.path
        with self.assertRaises(ValidationError):
            write_material(colliding, {'password': 'second'}, user=self.user, cas=0)

        self.assertEqual(FakeBackend.store[credential.path], [{'password': 'first'}])
        self.assertEqual(Credential.objects.count(), 1)

    def test_cas_refuses_a_write_against_a_stale_version(self):
        """
        A rotation must not clobber a version it never saw. Simulates another
        writer advancing the secret between our read and our write.
        """
        credential = self.make_credential()
        write_material(credential, {'password': 'first'}, user=self.user)
        credential.refresh_from_db()
        self.assertEqual(credential.kv_version, 1)

        # Someone else writes v2 directly, without NetBox's knowledge.
        FakeBackend.store[credential.path].append({'password': 'concurrent'})

        # Our rotation still believes v1 is current, so check-and-set refuses.
        with self.assertRaises(OpenBaoConflict):
            rotate_material(credential, {'password': 'ours'}, user=self.user)

        self.assertEqual(FakeBackend.store[credential.path][-1], {'password': 'concurrent'})

    def test_rotation_creates_a_new_version(self):
        credential = self.make_credential()
        write_material(credential, {'password': 'first'}, user=self.user)

        rotate_material(credential, {'password': 'second'}, user=self.user)
        credential.refresh_from_db()

        self.assertEqual(credential.kv_version, 2)
        self.assertIsNotNone(credential.last_rotated)
        self.assertEqual(len(FakeBackend.store[credential.path]), 2)

    def test_failed_rotation_must_not_destroy_the_existing_secret(self):
        """
        Compensation after a failed *rotation* must remove only the version it
        just wrote. Destroying the whole path would take the working secret
        with it — turning a recoverable failure into data loss, which is far
        worse than the orphan the compensator exists to prevent.
        """
        credential = self.make_credential()
        write_material(credential, {'password': 'good-v1'}, user=self.user)
        credential.refresh_from_db()

        # The rotation's material lands, then the metadata update fails.
        FakeBackend.fail_on_metadata = True
        with self.assertRaises(OpenBaoConflict):
            rotate_material(credential, {'password': 'bad-v2'}, user=self.user)

        self.assertIn(
            credential.path, FakeBackend.store,
            'The credential path was destroyed by a failed rotation.',
        )
        self.assertEqual(
            FakeBackend.store[credential.path][0], {'password': 'good-v1'},
            'The previously-good version did not survive a failed rotation.',
        )
        # ...and the still-readable current value is that good version.
        backend = FakeBackend(self.engine)
        self.assertEqual(backend.read(credential.path), {'password': 'good-v1'})
        # Only the failed version was removed, not the whole path.
        self.assertEqual(FakeBackend.delete_calls, [(credential.path, (2,))])

    def test_failed_create_still_removes_the_whole_path(self):
        """The create case is different: nothing else lives there, so a full
        destroy is the correct compensation."""
        FakeBackend.fail_on_metadata = True
        credential = self.make_credential()

        with self.assertRaises(OpenBaoConflict):
            write_material(credential, {'password': 'never-committed'}, user=self.user)

        self.assertNotIn(credential.path, FakeBackend.store)

    def test_invalid_payload_is_rejected_before_any_write(self):
        credential = self.make_credential(credential_type=CredentialTypeChoices.TYPE_SSH_KEYPAIR)
        with self.assertRaises(ValidationError):
            write_material(credential, {'password': 'wrong field'}, user=self.user)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(FakeBackend.store, {})


class AuditTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username='operator')
        self.credential = self.make_credential()
        write_material(self.credential, {'password': 'hunter2'}, user=self.user)

    def test_write_is_logged(self):
        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_WRITE).first()
        self.assertIsNotNone(entry)
        self.assertTrue(entry.success)
        self.assertEqual(entry.username_snapshot, 'operator')

    def test_reveal_is_logged(self):
        reveal_material(self.credential, self.user)
        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_REVEAL).first()
        self.assertIsNotNone(entry)
        self.assertTrue(entry.success)

    def test_log_never_contains_the_value(self):
        reveal_material(self.credential, self.user, reason='ticket-42')
        for entry in CredentialAccessLog.objects.all():
            blob = ' '.join(filter(None, [entry.reason, entry.message, entry.credential_name_snapshot]))
            self.assertNotIn('hunter2', blob)

    def test_log_survives_credential_deletion(self):
        name = self.credential.name
        self.credential.delete()

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_WRITE).first()
        self.assertIsNone(entry.credential)
        self.assertEqual(entry.credential_name_snapshot, name)

    def test_deleting_a_credential_destroys_its_material(self):
        path = self.credential.path
        self.credential.delete()
        self.assertNotIn(path, FakeBackend.store)


class RevealPolicyTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username='operator')
        self.credential = self.make_credential()
        write_material(self.credential, {'password': 'hunter2'}, user=self.user)

    def test_reveal_returns_material_and_ttl(self):
        data, ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'hunter2'})
        self.assertEqual(ttl, 300)

    def test_ttl_is_capped_by_policy(self):
        self.policy.max_reveal_ttl = 60
        self.policy.save()
        self.credential.refresh_from_db()

        _data, ttl = reveal_material(self.credential, self.user)
        self.assertEqual(ttl, 60)

    def test_required_reason_is_enforced(self):
        self.policy.require_reason = True
        self.policy.save()
        self.credential.refresh_from_db()

        with self.assertRaises(ValidationError):
            reveal_material(self.credential, self.user)

        failed = CredentialAccessLog.objects.filter(
            action=AccessActionChoices.ACTION_REVEAL, success=False,
        )
        self.assertTrue(failed.exists(), 'A refused reveal must still be audited.')

    def test_reason_is_recorded(self):
        self.policy.require_reason = True
        self.policy.save()
        self.credential.refresh_from_db()

        reveal_material(self.credential, self.user, reason='CHG-1234')
        entry = CredentialAccessLog.objects.filter(
            action=AccessActionChoices.ACTION_REVEAL, success=True,
        ).first()
        self.assertEqual(entry.reason, 'CHG-1234')
