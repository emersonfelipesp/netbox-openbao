"""Extraction of non-secret metadata from real key material."""

import datetime
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.test import TestCase

from netbox_openbao.secrets.extractors import extract_certificate_metadata, extract_ssh_metadata
from netbox_openbao.secrets.generators import generate_ssh_keypair


class SSHExtractionTest(TestCase):

    def test_ed25519_roundtrip(self):
        pair = generate_ssh_keypair('ed25519')
        meta = extract_ssh_metadata(pair['private_key'])

        self.assertEqual(meta['key_type'], 'ed25519')
        self.assertTrue(meta['public_key'].startswith('ssh-ed25519 '))
        self.assertTrue(meta['fingerprint'].startswith('SHA256:'))
        # The public key derived from the private half must match the one the
        # generator handed back, or the value stored in NetBox would not be the
        # counterpart of the material in OpenBao.
        self.assertEqual(
            meta['public_key'].split()[1],
            pair['public_key'].split()[1],
        )

    def test_rsa_reports_bit_length(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        meta = extract_ssh_metadata(pem)
        self.assertEqual(meta['key_type'], 'rsa-2048')

    def test_fingerprint_matches_ssh_keygen(self):
        """
        The fingerprint must be byte-identical to `ssh-keygen -lf`, or
        operators cannot match a NetBox record against a host's authorized_keys.
        """
        if not _have_ssh_keygen():
            self.skipTest('ssh-keygen is not available')

        pair = generate_ssh_keypair('ed25519')
        meta = extract_ssh_metadata(pair['private_key'])

        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / 'id.pub'
            pub.write_text(meta['public_key'] + '\n')
            output = subprocess.run(
                ['ssh-keygen', '-lf', str(pub)],
                capture_output=True, text=True, check=True,
            ).stdout
        self.assertIn(meta['fingerprint'], output)

    def test_encrypted_key_without_passphrase_is_rejected_cleanly(self):
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.BestAvailableEncryption(b'hunter2'),
        ).decode()

        with self.assertRaises(ValidationError) as ctx:
            extract_ssh_metadata(pem)
        # The error must describe the problem without quoting the material.
        self.assertNotIn('BEGIN', str(ctx.exception))

    def test_encrypted_key_with_passphrase_parses(self):
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.BestAvailableEncryption(b'hunter2'),
        ).decode()
        meta = extract_ssh_metadata(pem, passphrase='hunter2')
        self.assertEqual(meta['key_type'], 'ed25519')

    def test_garbage_is_rejected(self):
        with self.assertRaises(ValidationError):
            extract_ssh_metadata('not a key')


class CertificateExtractionTest(TestCase):

    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'core-sw-01.example.net'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example'),
        ])
        self.not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        self.not_after = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.key.public_key())
            .serial_number(0x1234abcd)
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName('core-sw-01.example.net')]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_extracts_identity_and_validity(self):
        meta = extract_certificate_metadata(self.pem)

        self.assertIn('core-sw-01.example.net', meta['cert_subject'])
        self.assertIn('core-sw-01.example.net', meta['cert_issuer'])
        self.assertEqual(meta['cert_serial'], '1234abcd')
        self.assertEqual(meta['valid_from'], self.not_before)
        self.assertEqual(meta['valid_until'], self.not_after)
        self.assertEqual(meta['subject_alternative_names'], ['core-sw-01.example.net'])

    def test_validity_is_what_makes_the_expiry_dashboard_free(self):
        """valid_until must be a real datetime so it can be indexed and filtered."""
        meta = extract_certificate_metadata(self.pem)
        self.assertIsInstance(meta['valid_until'], datetime.datetime)
        self.assertIsNotNone(meta['valid_until'].tzinfo)

    def test_garbage_is_rejected(self):
        with self.assertRaises(ValidationError):
            extract_certificate_metadata('-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----')


def _have_ssh_keygen():
    try:
        subprocess.run(['ssh-keygen', '-h'], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False
