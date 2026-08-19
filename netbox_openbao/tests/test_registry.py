from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.secrets.generators import generate_ssh_keypair
from netbox_openbao.secrets.registry import extract_metadata, validate_payload


class PayloadValidationTest(TestCase):

    def test_required_field_is_enforced(self):
        with self.assertRaises(ValidationError) as ctx:
            validate_payload(CredentialTypeChoices.TYPE_PASSWORD, {})
        self.assertIn('secret_data', ctx.exception.message_dict)

    def test_unknown_field_is_rejected(self):
        """
        A typo like `privatekey` would otherwise store material under a name no
        consumer looks for — present but unreachable.
        """
        with self.assertRaises(ValidationError):
            validate_payload(CredentialTypeChoices.TYPE_PASSWORD, {
                'password': 'x', 'passwrod': 'y',
            })

    def test_generic_kv_accepts_arbitrary_keys(self):
        cleaned = validate_payload(CredentialTypeChoices.TYPE_GENERIC_KV, {'anything': 'goes'})
        self.assertEqual(cleaned, {'anything': 'goes'})

    def test_empty_values_are_dropped(self):
        cleaned = validate_payload(CredentialTypeChoices.TYPE_SSH_KEYPAIR, {
            'private_key': 'material', 'passphrase': '',
        })
        self.assertEqual(cleaned, {'private_key': 'material'})

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_payload('not-a-type', {'password': 'x'})


class ExtractionTest(TestCase):

    def test_ssh_metadata_is_extracted(self):
        pair = generate_ssh_keypair('ed25519')
        metadata = extract_metadata(CredentialTypeChoices.TYPE_SSH_KEYPAIR, pair)

        self.assertIn('public_key', metadata)
        self.assertIn('fingerprint', metadata)
        self.assertEqual(metadata['key_type'], 'ed25519')

    def test_extraction_never_returns_secret_fields(self):
        """
        Only fields on the allowlist may be written back to the model, so a
        future extractor cannot introduce a secret-bearing column by accident.
        """
        pair = generate_ssh_keypair('ed25519')
        metadata = extract_metadata(CredentialTypeChoices.TYPE_SSH_KEYPAIR, pair)

        self.assertNotIn('private_key', metadata)
        self.assertNotIn('passphrase', metadata)
        for value in metadata.values():
            self.assertNotIn('PRIVATE KEY', str(value))

    def test_password_type_extracts_nothing(self):
        self.assertEqual(extract_metadata(CredentialTypeChoices.TYPE_PASSWORD, {'password': 'x'}), {})

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'store_public_material': False}})
    def test_opting_out_disables_extraction(self):
        pair = generate_ssh_keypair('ed25519')
        self.assertEqual(extract_metadata(CredentialTypeChoices.TYPE_SSH_KEYPAIR, pair), {})
