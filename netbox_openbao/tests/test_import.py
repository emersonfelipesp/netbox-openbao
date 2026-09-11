"""
Migration from `netbox-secrets`.

Built on `SourceSecret` rather than the `netbox-secrets` ORM models, so the
suite does not require that plugin to be installed in order to test the code
that migrates away from it.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.contenttypes.models import ContentType

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.importers import SourceSecret, import_secrets, infer_credential_type
from netbox_openbao.importers.netbox_secrets import source_marker
from netbox_openbao.models import Credential, CredentialAssignment, CredentialPolicy
from netbox_openbao.secrets.generators import generate_ssh_keypair

from .base import OpenBaoTestCase, OpenBaoTransactionTestCase
from .fakes import FakeBackend


def _certificate_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'imported.example.net')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(4242)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TypeInferenceTest(OpenBaoTestCase):
    """
    Inference is verified by extraction: a type is only claimed if this
    plugin's own extractors can parse the material as that type.
    """

    def test_single_line_is_a_password(self):
        kind, payload = infer_credential_type('hunter2')
        self.assertEqual(kind, CredentialTypeChoices.TYPE_PASSWORD)
        self.assertEqual(payload, {'password': 'hunter2'})

    def test_material_is_copied_verbatim(self):
        """
        A migration is a copy. Detection may ignore surrounding whitespace, but
        what gets written must be byte-identical to what was read — a trimmed
        PEM can fail a parser that insists on the trailing newline, and a
        trimmed password is simply a different password.
        """
        padded = '  hunter2  '
        _kind, payload = infer_credential_type(padded)
        self.assertEqual(payload['password'], padded)

        pair = generate_ssh_keypair('ed25519')
        _kind, payload = infer_credential_type(pair['private_key'])
        self.assertEqual(payload['private_key'], pair['private_key'])

    def test_ssh_private_key_is_detected(self):
        pair = generate_ssh_keypair('ed25519')
        kind, payload = infer_credential_type(pair['private_key'])

        self.assertEqual(kind, CredentialTypeChoices.TYPE_SSH_KEYPAIR)
        self.assertEqual(payload['private_key'], pair['private_key'])

    def test_certificate_alone_is_a_ca(self):
        kind, payload = infer_credential_type(_certificate_pem())
        self.assertEqual(kind, CredentialTypeChoices.TYPE_X509_CA)
        self.assertIn('certificate', payload)

    def test_material_that_looks_like_a_key_but_is_not_falls_back(self):
        """
        The important case. Text with PEM markers that no extractor can parse
        must not be claimed as a keypair — the metadata that would follow
        would be fabricated.
        """
        junk = '-----BEGIN PRIVATE KEY-----\nnot actually a key\n-----END PRIVATE KEY-----'
        kind, payload = infer_credential_type(junk)

        self.assertEqual(kind, CredentialTypeChoices.TYPE_GENERIC_KV)
        self.assertEqual(payload, {'value': junk})

    def test_multiline_unstructured_text_falls_back(self):
        kind, payload = infer_credential_type('line one\nline two')
        self.assertEqual(kind, CredentialTypeChoices.TYPE_GENERIC_KV)

    def test_empty_falls_back(self):
        kind, _payload = infer_credential_type('')
        self.assertEqual(kind, CredentialTypeChoices.TYPE_GENERIC_KV)


class ImportTest(OpenBaoTransactionTestCase):

    def setUp(self):
        super().setUp()
        self.sources = [
            SourceSecret(pk=1, name='switch login', plaintext='hunter2', username='admin'),
            SourceSecret(pk=2, name='fleet key', plaintext=generate_ssh_keypair('ed25519')['private_key']),
        ]

    def test_imports_and_writes_material(self):
        result = import_secrets(self.sources, self.engine, self.policy)

        self.assertEqual(result.imported, 2)
        self.assertEqual(result.failed, 0)
        self.assertEqual(Credential.objects.count(), 2)

        password = Credential.objects.get(name='switch login')
        self.assertEqual(password.credential_type, CredentialTypeChoices.TYPE_PASSWORD)
        self.assertEqual(password.username, 'admin')
        self.assertEqual(FakeBackend.store[password.path], [{'password': 'hunter2'}])

    def test_extracted_metadata_lands_on_the_credential(self):
        import_secrets(self.sources, self.engine, self.policy)

        key = Credential.objects.get(name='fleet key')
        self.assertEqual(key.credential_type, CredentialTypeChoices.TYPE_SSH_KEYPAIR)
        self.assertTrue(key.public_key.startswith('ssh-ed25519 '))
        self.assertTrue(key.fingerprint.startswith('SHA256:'))

    def test_provenance_is_recorded(self):
        import_secrets(self.sources, self.engine, self.policy)

        markers = set(Credential.objects.values_list('import_source', flat=True))
        self.assertEqual(markers, {source_marker(1), source_marker(2)})

    def test_rerunning_is_a_no_op(self):
        """Resumability is the point: a repeated run must not duplicate."""
        import_secrets(self.sources, self.engine, self.policy)
        second = import_secrets(self.sources, self.engine, self.policy)

        self.assertEqual(second.imported, 0)
        self.assertEqual(second.skipped, 2)
        self.assertEqual(Credential.objects.count(), 2)

    def test_dry_run_writes_nothing(self):
        result = import_secrets(self.sources, self.engine, self.policy, dry_run=True)

        self.assertEqual(result.imported, 2)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(FakeBackend.store, {})

    def test_dry_run_reports_the_inferred_type(self):
        result = import_secrets(self.sources, self.engine, self.policy, dry_run=True)
        planned = {name: detail for _pk, name, outcome, detail in result.details if outcome == 'planned'}

        self.assertEqual(planned['switch login'], CredentialTypeChoices.TYPE_PASSWORD)
        self.assertEqual(planned['fleet key'], CredentialTypeChoices.TYPE_SSH_KEYPAIR)

    def test_one_failure_does_not_abandon_the_rest(self):
        """Per-secret atomicity is what makes an interrupted run resumable."""
        sources = [
            SourceSecret(pk=1, name='good', plaintext='hunter2'),
            # A name long enough to fail model validation.
            SourceSecret(pk=2, name='x' * 5, plaintext=''),
            SourceSecret(pk=3, name='also good', plaintext='swordfish'),
        ]
        # An empty payload cannot be stored, so #2 fails validation.
        result = import_secrets(sources, self.engine, self.policy)

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.imported, 2)
        self.assertEqual(
            set(Credential.objects.values_list('name', flat=True)), {'good', 'also good'}
        )

    def test_failures_never_report_the_material(self):
        sources = [SourceSecret(pk=9, name='bad', plaintext='')]
        result = import_secrets(sources, self.engine, self.policy)

        for _pk, _name, outcome, detail in result.details:
            self.assertEqual(outcome, 'failed')
            # The exception *type*, never its message.
            self.assertNotIn(' ', detail)

    def test_roles_are_not_mapped_by_default(self):
        """
        A policy created from a netbox-secrets role names an OpenBao policy
        that does not exist yet, so it is opt-in.
        """
        sources = [SourceSecret(pk=1, name='s', plaintext='x', role_name='Production')]
        import_secrets(sources, self.engine, self.policy)

        self.assertEqual(Credential.objects.get().policy, self.policy)
        self.assertEqual(CredentialPolicy.objects.count(), 1)

    def test_map_roles_creates_tiers_and_flags_them(self):
        sources = [SourceSecret(pk=1, name='s', plaintext='x', role_name='Production')]
        result = import_secrets(sources, self.engine, self.policy, map_roles=True)

        created = CredentialPolicy.objects.get(slug='production')
        self.assertEqual(Credential.objects.get().policy, created)
        self.assertEqual(created.engine, self.engine)
        # The operator must be told these need creating in OpenBao.
        self.assertIn(created.openbao_policy, result.policies_needing_setup)


class AssignmentImportTest(OpenBaoTransactionTestCase):

    def setUp(self):
        super().setUp()
        site = Site.objects.create(name='S', slug='s')
        manufacturer = Manufacturer.objects.create(name='M', slug='m')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='T', slug='t')
        role = DeviceRole.objects.create(name='R', slug='r')
        self.device = Device.objects.create(
            name='core-sw-01', site=site, device_type=device_type, role=role,
        )
        self.device_ct = ContentType.objects.get_for_model(Device)

    def test_assignment_is_carried_over(self):
        sources = [SourceSecret(
            pk=1, name='device login', plaintext='hunter2',
            assigned_object_type_id=self.device_ct.pk,
            assigned_object_id=self.device.pk,
        )]
        import_secrets(sources, self.engine, self.policy)

        assignment = CredentialAssignment.objects.get()
        self.assertEqual(assignment.assigned_object, self.device)
        self.assertEqual(assignment.credential.name, 'device login')
