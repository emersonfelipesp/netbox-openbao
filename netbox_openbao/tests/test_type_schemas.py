"""
Operator-defined credential types.

The tests that matter here are the ones about what a stored schema *cannot* do.
A type defined as data is a small privilege-escalation surface if the wrong
things are resolvable from it, so those limits are asserted directly rather
than assumed from the shape of the code.
"""

from django.core.exceptions import ValidationError
from django.urls import reverse
from utilities.testing import APITestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialPolicy, CredentialTypeSchema, SecretEngine
from netbox_openbao.secrets.registry import (
    EXTRACTABLE_FIELDS,
    EXTRACTORS,
    credential_type_choices,
    extract_metadata,
    is_known_credential_type,
    validate_payload,
)
from netbox_openbao.services import write_material

from .base import OpenBaoTestCase
from .fakes import FakeBackend

RADIUS_SCHEMA = {
    'type': 'object',
    'properties': {
        'shared_secret': {'type': 'string', 'minLength': 8},
        'server': {'type': 'string'},
        'port': {'type': 'integer'},
    },
    'required': ['shared_secret', 'server'],
}


class SchemaValidationTest(OpenBaoTestCase):

    def _schema(self, **kwargs):
        defaults = {
            'name': 'RADIUS', 'slug': 'radius',
            'schema': RADIUS_SCHEMA, 'secret_fields': ['shared_secret'],
        }
        defaults.update(kwargs)
        return CredentialTypeSchema(**defaults)

    def test_a_valid_schema_is_accepted(self):
        schema = self._schema()
        schema.full_clean()
        schema.save()
        self.assertTrue(is_known_credential_type('radius'))

    def test_a_stored_type_may_not_shadow_a_builtin(self):
        """
        The built-ins are what the plugin's own code paths assume. A stored
        type quietly overriding `ssh-keypair` would change how existing
        credentials validate.
        """
        with self.assertRaises(ValidationError) as ctx:
            self._schema(slug=CredentialTypeChoices.TYPE_SSH_KEYPAIR).full_clean()
        self.assertIn('slug', ctx.exception.message_dict)

    def test_extractor_must_come_from_the_registry(self):
        """
        The security constraint the whole model is shaped around. If this ever
        accepts a dotted path, the model becomes remote code execution with a
        JSON Schema attached.
        """
        for attempt in (
            'os.system',
            'netbox_openbao.secrets.extractors.extract_ssh_metadata',
            'builtins.eval',
            'subprocess.run',
        ):
            with self.assertRaises(ValidationError, msg=attempt) as ctx:
                self._schema(extractor=attempt).full_clean()
            self.assertIn('extractor', ctx.exception.message_dict)

    def test_a_registry_extractor_is_accepted(self):
        schema = self._schema(extractor='ssh')
        schema.full_clean()
        self.assertIn('ssh', EXTRACTORS)

    def test_secret_fields_must_exist_in_the_schema(self):
        """
        A typo here would silently mark nothing as secret, and the value would
        then be eligible for mirroring into a NetBox column.
        """
        with self.assertRaises(ValidationError) as ctx:
            self._schema(secret_fields=['shared_secrit']).full_clean()
        self.assertIn('secret_fields', ctx.exception.message_dict)

    def test_schema_must_define_properties(self):
        with self.assertRaises(ValidationError):
            self._schema(schema={'type': 'object'}).full_clean()

    def test_malformed_json_schema_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            self._schema(schema={'type': 'object', 'properties': {'x': {'type': 'nonsense'}}}).full_clean()
        self.assertIn('schema', ctx.exception.message_dict)

    def test_public_fields_are_everything_not_secret(self):
        schema = self._schema()
        self.assertEqual(sorted(schema.public_fields), ['port', 'server'])


class StoredTypeUsageTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.schema = CredentialTypeSchema.objects.create(
            name='RADIUS', slug='radius', schema=RADIUS_SCHEMA, secret_fields=['shared_secret'],
        )

    def test_payload_is_validated_against_the_json_schema(self):
        cleaned = validate_payload('radius', {'shared_secret': 'longenough', 'server': 'radius-01'})
        self.assertEqual(cleaned['server'], 'radius-01')

        # minLength is enforced, not just presence.
        with self.assertRaises(ValidationError):
            validate_payload('radius', {'shared_secret': 'short', 'server': 'radius-01'})

    def test_missing_required_field_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_payload('radius', {'server': 'radius-01'})

    def test_validation_errors_never_quote_the_material(self):
        """
        jsonschema's own message embeds the failing instance, which for a
        secret payload is the material itself.
        """
        with self.assertRaises(ValidationError) as ctx:
            validate_payload('radius', {'shared_secret': 'sekrit', 'server': 'radius-01'})

        rendered = str(ctx.exception)
        self.assertNotIn('sekrit', rendered)

    def test_a_credential_can_use_a_stored_type(self):
        credential = Credential(
            name='radius shared secret',
            credential_type='radius',
            policy=self.policy,
            engine=self.engine,
        )
        write_material(
            credential, {'shared_secret': 'longenough', 'server': 'radius-01'},
        )

        credential.refresh_from_db()
        self.assertEqual(credential.credential_type, 'radius')
        self.assertEqual(
            FakeBackend.store[credential.path][0],
            {'shared_secret': 'longenough', 'server': 'radius-01'},
        )

    def test_an_unknown_type_is_still_rejected(self):
        """Dropping the field's `choices` must not mean anything goes."""
        credential = Credential(
            name='bogus', credential_type='not-a-real-type',
            policy=self.policy, engine=self.engine,
        )
        with self.assertRaises(ValidationError) as ctx:
            credential.full_clean()
        self.assertIn('credential_type', ctx.exception.message_dict)

    def test_display_name_resolves_for_stored_types(self):
        """
        The field has no `choices`, so `get_FOO_display()` is supplied by the
        model. Tables and detail panels call it.
        """
        credential = Credential(
            name='r', credential_type='radius', policy=self.policy, engine=self.engine,
        )
        self.assertEqual(credential.get_credential_type_display(), 'RADIUS')

        builtin = Credential(
            name='p', credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy, engine=self.engine,
        )
        self.assertEqual(str(builtin.get_credential_type_display()), 'Password')

    def test_choices_include_built_ins_and_stored_types(self):
        values = [value for value, _label in credential_type_choices()]
        self.assertIn(CredentialTypeChoices.TYPE_PASSWORD, values)
        self.assertIn('radius', values)


class StoredTypeCannotLeakTest(OpenBaoTestCase):
    """
    The claim worth proving: a schema an operator writes cannot cause secret
    material to be mirrored into a NetBox column.
    """

    def test_extraction_output_is_still_confined_to_the_allowlist(self):
        CredentialTypeSchema.objects.create(
            name='Sneaky', slug='sneaky',
            schema={'type': 'object', 'properties': {'private_key': {'type': 'string'}}},
            secret_fields=['private_key'],
            extractor='ssh',
        )
        from netbox_openbao.secrets.generators import generate_ssh_keypair

        pair = generate_ssh_keypair('ed25519')
        metadata = extract_metadata('sneaky', {'private_key': pair['private_key']})

        self.assertTrue(set(metadata).issubset(EXTRACTABLE_FIELDS))
        self.assertNotIn('private_key', metadata)
        for value in metadata.values():
            self.assertNotIn('PRIVATE KEY', str(value))

    def test_a_schema_cannot_name_a_field_outside_the_allowlist(self):
        """
        Even a type whose properties are named after model columns cannot get
        them written: extraction output is filtered, and the payload itself
        never reaches a model field.
        """
        CredentialTypeSchema.objects.create(
            name='Impostor', slug='impostor',
            schema={
                'type': 'object',
                'properties': {'username': {'type': 'string'}, 'password': {'type': 'string'}},
                'required': ['password'],
            },
            secret_fields=['password'],
        )
        credential = Credential(
            name='i', credential_type='impostor', policy=self.policy, engine=self.engine,
        )
        write_material(credential, {'username': 'admin', 'password': 'hunter2'})

        credential.refresh_from_db()
        # The payload's "username" is in OpenBao, not silently copied onto the
        # model's own username column.
        self.assertEqual(credential.username, '')
        self.assertEqual(
            FakeBackend.store[credential.path][0], {'username': 'admin', 'password': 'hunter2'},
        )


class SchemaAPITest(APITestCase):

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))
        self.engine = SecretEngine.objects.create(
            name='P', slug='p', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.policy = CredentialPolicy.objects.create(
            name='L', slug='l', engine=self.engine, openbao_policy='netbox-l',
        )

    def test_create_via_api(self):
        self.add_permissions(
            'netbox_openbao.add_credentialtypeschema', 'netbox_openbao.view_credentialtypeschema',
        )
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credentialtypeschema-list'),
            {
                'name': 'RADIUS', 'slug': 'radius',
                'schema': RADIUS_SCHEMA, 'secret_fields': ['shared_secret'],
            },
            format='json', **self.header,
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_api_rejects_an_extractor_outside_the_registry(self):
        """The allowlist must hold over the API too, not only in the form."""
        self.add_permissions(
            'netbox_openbao.add_credentialtypeschema', 'netbox_openbao.view_credentialtypeschema',
        )
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credentialtypeschema-list'),
            {
                'name': 'Evil', 'slug': 'evil',
                'schema': RADIUS_SCHEMA, 'secret_fields': ['shared_secret'],
                'extractor': 'os.system',
            },
            format='json', **self.header,
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(CredentialTypeSchema.objects.filter(slug='evil').exists())
