"""Live SSH identity remains verifiable independently of display extraction."""

from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import TransactionTestCase, override_settings

from netbox_openbao.automation import AutomationResolutionDenied, capture_reference_identity
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialTypeSchema
from netbox_openbao.services import discard_staged, promote_staged, stage_material, write_material

from .fakes import FakeBackend
from .test_automation import CANARY, _AutomationFixture


def new_ssh_material():
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.BestAvailableEncryption(CANARY.encode()),
    ).decode()


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class AutomationLiveKeyIdentityTest(_AutomationFixture, TransactionTestCase):
    def prepare_custom_ssh(self):
        self.prepare_ssh_bundle()
        schema = CredentialTypeSchema.objects.create(
            name='Automation custom SSH', slug='automation-custom-ssh', extractor='ssh',
            schema={'type': 'object', 'properties': {
                'private_key': {'type': 'string'}, 'passphrase': {'type': 'string'},
            }, 'required': ['private_key']}, secret_fields=['private_key', 'passphrase'],
        )
        self.credential.credential_type = schema.slug
        self.credential.save(update_fields=['credential_type'])
        identity = capture_reference_identity(reference=self.authority.reference, initiating_actor=self.actor,
                                              target_object=self.target, reason=self.authority.reason)
        self.authority = replace(self.authority, provider_identity=identity)
        return schema

    def test_custom_extractor_edit_changes_frozen_schema_identity(self):
        schema = self.prepare_custom_ssh()
        schema.extractor = ''
        schema.save(update_fields=['extractor'])
        self.assert_denied_before_read()

    def test_custom_extractor_edit_cannot_disable_approved_bundle_verification(self):
        schema = self.prepare_custom_ssh()
        replacement = {'private_key': new_ssh_material(), 'passphrase': CANARY}

        def changed_during_read(*args, **kwargs):
            # Defense in depth even if an internal callback mutates the schema
            # inside the same transaction after the final metadata check.
            CredentialTypeSchema.objects.filter(pk=schema.pk).update(extractor='')
            return replacement

        with patch.object(FakeBackend, 'read', side_effect=changed_during_read), \
                self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.assertFalse(CredentialAccessLog.objects.filter(execution_id=91, success=True).exists())

    def test_disabled_display_still_binds_actual_live_key(self):
        with patch('netbox_openbao.secrets.registry.get_config', return_value=False):
            self.prepare_ssh_bundle()
            self.assertEqual(self.credential.fingerprint, '')
            self.assertRegex(self.credential.live_key_fingerprint, r'^SHA256:')
            self.assertEqual(self.credential.live_key_version, 2)
            write_material(self.credential, {'private_key': new_ssh_material(), 'passphrase': CANARY}, cas=2)
        self.assertEqual(self.credential.fingerprint, '')
        self.assert_denied_before_read()

    def test_stale_nonempty_display_fingerprint_is_never_authority(self):
        self.prepare_ssh_bundle()
        original = self.credential.fingerprint
        with patch('netbox_openbao.secrets.registry.get_config', return_value=False):
            write_material(self.credential, {'private_key': new_ssh_material(), 'passphrase': CANARY}, cas=2)
        self.assertEqual(self.credential.fingerprint, original)
        self.assertNotEqual(self.credential.live_key_fingerprint, original)
        self.assert_denied_before_read()

    def test_unverified_legacy_identity_and_wrong_version_refuse_admission(self):
        self.prepare_ssh_bundle()
        original = self.credential.live_key_fingerprint
        for fingerprint, version in (('', None), (original, 1)):
            with self.subTest(version=version):
                Credential.objects.filter(pk=self.credential.pk).update(
                    live_key_fingerprint=fingerprint, live_key_version=version,
                )
                with self.assertRaises(AutomationResolutionDenied):
                    capture_reference_identity(reference=self.authority.reference, initiating_actor=self.actor,
                                               target_object=self.target, reason=self.authority.reason)

    def test_backend_key_substitution_is_detected_before_delivery(self):
        self.prepare_ssh_bundle()
        replacement = {'private_key': new_ssh_material(), 'passphrase': CANARY}
        with patch.object(FakeBackend, 'read', return_value=replacement), \
                self.assertRaises(AutomationResolutionDenied) as caught:
            self.resolve()
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertFalse(CredentialAccessLog.objects.filter(execution_id=91, success=True).exists())

    def test_staged_key_identity_does_not_replace_live_and_discard_preserves_it(self):
        original = self.prepare_ssh_bundle()
        fingerprint = self.credential.live_key_fingerprint
        stage_material(self.credential, {'private_key': new_ssh_material(), 'passphrase': CANARY})
        self.assertEqual(self.credential.live_key_fingerprint, fingerprint)
        self.assertNotEqual(self.credential.staged_key_fingerprint, fingerprint)
        self.assertEqual(self.resolve()['fields']['private_key'], original)
        discard_staged(self.credential)
        self.assertEqual(self.credential.staged_key_fingerprint, '')
        self.assertIsNone(self.credential.staged_key_version)
        self.assertEqual(self.credential.live_key_fingerprint, fingerprint)
        self.authority = replace(self.authority, dispatch_nonce='after-discard')
        self.assertEqual(self.resolve()['fields']['private_key'], original)

    def test_promotion_changes_live_identity_and_requires_new_admission(self):
        self.prepare_ssh_bundle()
        stage_material(self.credential, {'private_key': new_ssh_material(), 'passphrase': CANARY})
        staged = self.credential.staged_key_fingerprint
        promote_staged(self.credential)
        self.assertEqual(self.credential.live_key_fingerprint, staged)
        self.assertEqual(self.credential.live_key_version, self.credential.live_kv_version)
        self.assertEqual(self.credential.staged_key_fingerprint, '')
        self.assert_denied_before_read()

    def test_unverified_staged_identity_is_not_inferred_from_display_on_promotion(self):
        self.prepare_ssh_bundle()
        stage_material(self.credential, {'private_key': new_ssh_material(), 'passphrase': CANARY})
        Credential.objects.filter(pk=self.credential.pk).update(staged_key_version=None)
        promote_staged(self.credential)
        self.assertEqual(self.credential.live_key_fingerprint, '')
        self.assert_denied_before_read()
