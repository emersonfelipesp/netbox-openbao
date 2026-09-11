"""
Staged rotation.

The guarantee under test is the one in the issue title: a rotation in progress
must never break a consumer. Everything else here is in service of that — the
live pointer, the resolution order, and the discard scope all exist so that
what automation resolves keeps working until someone decides otherwise.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from netbox_openbao.choices import AccessActionChoices, CredentialStatusChoices
from netbox_openbao.models import CredentialAccessLog
from netbox_openbao.services import (
    discard_staged,
    promote_staged,
    reveal_material,
    stage_material,
    write_material,
)

from .base import OpenBaoTransactionTestCase as OpenBaoTestCase
from .fakes import FakeBackend

User = get_user_model()


class StagedRotationTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username='operator')
        self.credential = self.make_credential()
        write_material(self.credential, {'password': 'live-v1'}, user=self.user)
        self.credential.refresh_from_db()

    # -- the headline guarantee ----------------------------------------

    def test_staging_does_not_change_what_consumers_get(self):
        """
        The whole point. A staged version exists in OpenBao but every reader
        still receives the version that is known to work.
        """
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})

        # ...even though v2 is genuinely written and readable by number.
        self.assertEqual(len(FakeBackend.store[self.credential.path]), 2)
        explicit, _ttl = reveal_material(self.credential, self.user, version=2)
        self.assertEqual(explicit, {'password': 'candidate-v2'})

    def test_promotion_switches_consumers_over(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        promote_staged(self.credential, user=self.user)
        self.credential.refresh_from_db()

        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'candidate-v2'})
        self.assertEqual(self.credential.status, CredentialStatusChoices.STATUS_ACTIVE)
        self.assertFalse(self.credential.has_staged_version)
        self.assertIsNotNone(self.credential.last_rotated)

    def test_discard_leaves_the_live_version_serving(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        discard_staged(self.credential, user=self.user)
        self.credential.refresh_from_db()

        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})
        self.assertEqual(self.credential.status, CredentialStatusChoices.STATUS_ACTIVE)
        self.assertFalse(self.credential.has_staged_version)
        # Only the staged version was removed.
        self.assertEqual(FakeBackend.delete_calls, [(self.credential.path, (2,))])

    # -- state machine --------------------------------------------------

    def test_status_is_staged_while_a_candidate_waits(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        self.assertEqual(self.credential.status, CredentialStatusChoices.STATUS_STAGED)
        self.assertTrue(self.credential.has_staged_version)
        self.assertEqual(self.credential.kv_version, 2)
        self.assertEqual(self.credential.live_kv_version, 1)

    def test_cannot_stage_twice(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        with self.assertRaises(ValidationError):
            stage_material(self.credential, {'password': 'candidate-v3'}, user=self.user)

    def test_cannot_promote_without_a_staged_version(self):
        with self.assertRaises(ValidationError):
            promote_staged(self.credential, user=self.user)

    def test_cannot_discard_without_a_staged_version(self):
        with self.assertRaises(ValidationError):
            discard_staged(self.credential, user=self.user)

    def test_can_stage_again_after_discarding(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()
        discard_staged(self.credential, user=self.user)
        self.credential.refresh_from_db()

        # Check-and-set must still compare against the highest number ever
        # issued: OpenBao's current-version counter does not go backwards when
        # a version is deleted.
        self.assertEqual(self.credential.kv_version, 2)
        stage_material(self.credential, {'password': 'candidate-v3'}, user=self.user)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, 3)
        self.assertEqual(self.credential.live_kv_version, 1)

        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})

    def test_promotion_refuses_a_version_that_vanished(self):
        """
        Promotion commits every consumer to a version. If it were flipped to
        one destroyed out of band, all of them would break at once — silently,
        because nothing reads the material during promotion.
        """
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        # Something removed the staged version behind our back.
        FakeBackend(self.engine).delete(self.credential.path, versions=[2])

        with self.assertRaises(ValidationError):
            promote_staged(self.credential, user=self.user)

        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 1)
        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})

        failed = CredentialAccessLog.objects.filter(
            action=AccessActionChoices.ACTION_PROMOTE, success=False,
        )
        self.assertTrue(failed.exists(), 'A refused promotion must still be audited.')

    # -- backwards compatibility ---------------------------------------

    def test_credential_predating_staging_is_pinned_before_staging(self):
        """
        A credential written before this feature has no live pointer, which
        means "serve latest". Staging under that rule would put the unverified
        version straight into service — so the pointer is pinned first.
        """
        self.credential.live_kv_version = None
        self.credential.save(update_fields=['live_kv_version'])

        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()

        self.assertEqual(self.credential.live_kv_version, 1)
        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})

    def test_unstaged_credentials_still_resolve_to_latest(self):
        """Nothing changes for a credential that never stages."""
        self.credential.live_kv_version = None
        self.credential.save(update_fields=['live_kv_version'])

        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'live-v1'})

    def test_ordinary_rotation_still_promotes_immediately(self):
        """`rotate` keeps its old semantics; staging is opt-in."""
        from netbox_openbao.services import rotate_material

        rotate_material(self.credential, {'password': 'rotated'}, user=self.user)
        self.credential.refresh_from_db()

        self.assertFalse(self.credential.has_staged_version)
        data, _ttl = reveal_material(self.credential, self.user)
        self.assertEqual(data, {'password': 'rotated'})

    # -- audit ----------------------------------------------------------

    def test_every_transition_is_audited(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()
        promote_staged(self.credential, user=self.user, verified=True, note='checked on core-sw-01')

        actions = list(
            CredentialAccessLog.objects.filter(credential=self.credential)
            .values_list('action', flat=True)
        )
        self.assertIn(AccessActionChoices.ACTION_STAGE, actions)
        self.assertIn(AccessActionChoices.ACTION_PROMOTE, actions)

        promotion = CredentialAccessLog.objects.get(action=AccessActionChoices.ACTION_PROMOTE)
        self.assertIn('verified', promotion.reason)
        self.assertIn('core-sw-01', promotion.reason)

    def test_audit_never_records_the_material(self):
        stage_material(self.credential, {'password': 'candidate-v2'}, user=self.user)
        self.credential.refresh_from_db()
        promote_staged(self.credential, user=self.user)

        for entry in CredentialAccessLog.objects.all():
            blob = ' '.join(filter(None, [entry.reason, entry.message]))
            self.assertNotIn('candidate-v2', blob)
            self.assertNotIn('live-v1', blob)
