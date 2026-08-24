"""
The invariants that make this plugin safe.

These are not "nice to have" assertions — each one guards a property that is
otherwise easy to break with a well-meaning refactor, and whose breakage would
not be visible in ordinary use. A private key leaking into a changelog entry
or a `brief=true` response looks like nothing at all until someone reads the
database.
"""

import importlib.util
from pathlib import Path

from django.test import TestCase
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer

from netbox_openbao.api.serializers import CredentialSerializer
from netbox_openbao.api.views import CredentialViewSet
from netbox_openbao.backends.exceptions import OpenBaoAuthError, OpenBaoError
from netbox_openbao.models import Credential

# Substrings that would indicate a field capable of holding secret material.
#
# Imported from the standalone checker rather than restated here, so the two
# cannot drift. `scripts/check_no_secret_fields.py` is what CI runs on a runner
# that cannot stand up NetBox; a shorter copy there once checked three of these
# five and only plain assignments, which meant `secret_data = models.JSONField()`
# would have passed every check the public workflow advertised. One list.
#
# Loaded by path because `scripts/` is not part of the installed package — this
# test runs from a NetBox checkout, where the repository root is not on
# sys.path.
CHECKER_PATH = Path(__file__).resolve().parents[2] / 'scripts' / 'check_no_secret_fields.py'
MODELS_PATH = Path(__file__).resolve().parents[1] / 'models'


def _load_checker():
    path = CHECKER_PATH
    spec = importlib.util.spec_from_file_location('netbox_openbao_field_checker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_checker = _load_checker()

FORBIDDEN_FIELD_TOKENS = _checker.FORBIDDEN_FIELD_TOKENS

# `cert_serial` is a public certificate attribute, and `api_token`-style names
# are absent by design; nothing on Credential is an exception to the rule above.
# The checker carries its own, wider exception list because it scans every
# model rather than this one.
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


class SharedCheckerTest(TestCase):
    """
    The CI checker and this suite must enforce the same rule.

    CI runs `scripts/check_no_secret_fields.py` on a runner with no NetBox, no
    database, and no Redis, and reports it as a restatement of the invariant
    above. A restatement that checks less than the original is worse than no
    check, because it makes a weaker guarantee look like the real one.
    """

    def test_the_checker_passes_on_the_real_models(self):
        self.assertEqual(_checker.main(['check_no_secret_fields.py', str(MODELS_PATH)]), 0)

    def test_the_checker_rejects_a_plain_secret_field(self):
        offenders = _checker.offending_names('secret_data = models.JSONField()')
        self.assertEqual(offenders, ['secret_data'])

    def test_the_checker_rejects_an_annotated_secret_field(self):
        """
        An `ast.Assign`-only walk misses this form entirely, which is how an
        annotated field would have slipped past the earlier inline copy.
        """
        offenders = _checker.offending_names('token: str = models.CharField()')
        self.assertEqual(offenders, ['token'])

    def test_every_forbidden_token_is_actually_detected(self):
        for token in FORBIDDEN_FIELD_TOKENS:
            with self.subTest(token=token):
                self.assertEqual(
                    _checker.offending_names(f'my_{token}_field = models.CharField()'),
                    [f'my_{token}_field'],
                )
