"""
The invariants that make this plugin safe.

These are not "nice to have" assertions — each one guards a property that is
otherwise easy to break with a well-meaning refactor, and whose breakage would
not be visible in ordinary use. A private key leaking into a changelog entry
or a `brief=true` response looks like nothing at all until someone reads the
database.
"""

from django.test import TestCase
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer

from netbox_openbao.api.serializers import CredentialSerializer
from netbox_openbao.api.views import CredentialViewSet
from netbox_openbao.backends.exceptions import OpenBaoAuthError, OpenBaoError
from netbox_openbao.models import Credential

# Substrings that would indicate a field capable of holding secret material.
FORBIDDEN_FIELD_TOKENS = ('password', 'private', 'secret', 'passphrase', 'token')

# `cert_serial` is a public certificate attribute, and `api_token`-style names
# are absent by design; nothing here is an exception to the rule above.
ALLOWED_EXCEPTIONS = frozenset()


class ModelSurfaceTest(TestCase):

    def test_credential_has_no_secret_bearing_field(self):
        """
        No column on Credential can hold material.

        This is the structural claim the whole design rests on: because there
        is no such field, the changelog, export templates, and the REST
        representation cannot leak material no matter how they are configured.
        """
        offenders = []
        for field in Credential._meta.get_fields():
            name = getattr(field, 'name', '')
            if name in ALLOWED_EXCEPTIONS:
                continue
            if any(token in name.lower() for token in FORBIDDEN_FIELD_TOKENS):
                offenders.append(name)
        self.assertEqual(
            offenders, [],
            f'Credential gained field(s) that may hold secret material: {offenders}. '
            f'Secret material must live only in OpenBao.',
        )

    def test_reveal_is_a_distinct_permission(self):
        """`reveal` must be separate from `view`, and must actually exist."""
        codenames = {perm[0] for perm in Credential._meta.permissions}
        self.assertIn('reveal', codenames)
        self.assertIn('rotate', codenames)
        self.assertNotIn('view', codenames, 'view is a reserved action and must not be redeclared')


class SerializerSurfaceTest(TestCase):

    def test_secret_data_is_write_only(self):
        serializer = CredentialSerializer()
        field = serializer.fields['secret_data']
        self.assertTrue(
            field.write_only,
            'secret_data must be write_only so DRF cannot serialize it into any response.',
        )

    def test_secret_data_absent_from_brief_fields(self):
        self.assertNotIn('secret_data', CredentialSerializer.Meta.brief_fields)

    def test_no_secret_field_in_read_representation(self):
        """
        Walk the serializer's declared output and assert nothing secret-shaped
        survives. Catches a future field added without the write_only flag.
        """
        serializer = CredentialSerializer()
        readable = [name for name, field in serializer.fields.items() if not field.write_only]
        offenders = [
            name for name in readable
            if any(token in name.lower() for token in FORBIDDEN_FIELD_TOKENS)
        ]
        self.assertEqual(offenders, [], f'Readable secret-shaped serializer field(s): {offenders}')


class RevealEndpointTest(TestCase):

    def test_reveal_uses_json_renderer_only(self):
        """
        BrowsableAPIRenderer would template the secret into an HTML page,
        which caches and history retain.
        """
        renderers = CredentialViewSet.reveal.kwargs['renderer_classes']
        self.assertEqual(list(renderers), [JSONRenderer])
        self.assertNotIn(BrowsableAPIRenderer, renderers)

    def test_reveal_is_throttled(self):
        throttles = CredentialViewSet.reveal.kwargs.get('throttle_classes')
        self.assertTrue(throttles, 'The reveal endpoint must be rate limited.')

    def test_rotate_uses_json_renderer_only(self):
        renderers = CredentialViewSet.rotate.kwargs['renderer_classes']
        self.assertEqual(list(renderers), [JSONRenderer])


class ExceptionScrubbingTest(TestCase):

    def test_backend_exceptions_carry_no_server_text(self):
        """
        An OpenBao 403 body can enumerate policy rules. Backend exceptions are
        built from fixed strings so that body never reaches a log or a
        response.
        """
        exc = OpenBaoAuthError(status_code=403)
        self.assertEqual(str(exc), OpenBaoAuthError.default_message)
        self.assertNotIn('policy', str(exc).lower())

    def test_custom_message_is_still_developer_supplied(self):
        exc = OpenBaoError('OpenBao rejected the request.', status_code=400)
        self.assertEqual(str(exc), 'OpenBao rejected the request.')
