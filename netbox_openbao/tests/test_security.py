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

# The reviewed allowlist of non-secret `Credential` fields, imported from the
# standalone checker rather than restated here so the two cannot disagree.
#
# It is an allowlist on purpose. The first version of both checks looked for
# field *names* containing `password`, `private`, `secret`, `passphrase`, or
# `token` — a heuristic dressed as a guarantee, since `material =
# models.JSONField()` violates the invariant completely and matches none of
# them. Sharing one token list removed drift between two checks without making
# either of them true.
#
# Loaded by path because `scripts/` is not part of the installed package — this
# test runs from a NetBox checkout, where the repository root is not on
# sys.path.
CHECKER_PATH = Path(__file__).resolve().parents[2] / 'scripts' / 'check_no_secret_fields.py'
CREDENTIALS_MODULE = Path(__file__).resolve().parents[1] / 'models' / 'credentials.py'


def _load_checker():
    spec = importlib.util.spec_from_file_location('netbox_openbao_field_checker', CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_checker = _load_checker()

APPROVED_FIELDS = _checker.APPROVED_FIELDS

# Fields Django and NetBox contribute that are not declared in the model body,
# so the source-parsing checker never sees them. Each is machinery, not data
# the plugin writes.
SERIALIZER_ONLY_FIELDS = frozenset({
    'id', 'url', 'display_url', 'display', 'created', 'last_updated',
    'description', 'comments', 'owner', 'tags', 'custom_fields',
    # Derived, read-only, and boolean/integer by declaration.
    'has_staged_version', 'assignment_count',
})

INHERITED_FIELDS = frozenset({
    'id', 'created', 'last_updated', 'custom_field_data', 'description', 'comments',
    'tags', 'owner', 'journal_entries', 'bookmarks', 'subscriptions', 'notifications',
    'tagged_items', 'assignments', 'access_logs', 'cached_relations', 'table_configs',
    'notificationgroup', 'jobs', 'changes', 'events',
})


class ModelSurfaceTest(TestCase):

    def test_every_credential_field_is_on_the_reviewed_allowlist(self):
        """
        No column on Credential can hold material.

        This is the structural claim the whole design rests on: because there
        is no such field, the changelog, export templates, and the REST
        representation cannot leak material no matter how they are configured.

        Asserted as an **allowlist**. A denylist of secret-sounding names is
        walked around by calling the field `material`, `payload`, or `blob`, so
        instead every field is enumerated in
        `scripts/check_no_secret_fields.py` having been reviewed as non-secret,
        and anything else fails — whatever it is called. Adding a field means
        editing that list, and that edit is the review.
        """
        known = APPROVED_FIELDS | INHERITED_FIELDS
        offenders = sorted(
            name for field in Credential._meta.get_fields()
            if (name := getattr(field, 'name', '')) and name not in known
        )
        self.assertEqual(
            offenders, [],
            f'Credential gained unreviewed field(s): {offenders}. Secret material must live only '
            f'in OpenBao. If these are genuinely non-secret, add them to APPROVED_FIELDS in '
            f'scripts/check_no_secret_fields.py with the reasoning.',
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

    def test_the_read_representation_exposes_only_reviewed_fields(self):
        """
        Walk the serializer's declared output and assert every readable field
        is one that has been reviewed as non-secret.

        Same allowlist discipline as the model check, and for the same reason:
        a name heuristic here would pass a readable field called `material`.
        `secret_data` is excluded by being `write_only`, which is asserted
        separately above — this catches a *new* field added without that flag.
        """
        serializer = CredentialSerializer()
        readable = {name for name, field in serializer.fields.items() if not field.write_only}
        known = APPROVED_FIELDS | SERIALIZER_ONLY_FIELDS | INHERITED_FIELDS

        offenders = sorted(readable - known)
        self.assertEqual(
            offenders, [],
            f'Serializer exposes unreviewed field(s) in read responses: {offenders}. '
            f'If they are non-secret, add them to APPROVED_FIELDS in '
            f'scripts/check_no_secret_fields.py or SERIALIZER_ONLY_FIELDS here.',
        )


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

    def test_the_checker_passes_on_the_real_model(self):
        self.assertEqual(
            _checker.main(['check_no_secret_fields.py', str(CREDENTIALS_MODULE)]), 0
        )

    def _offenders(self, body):
        source = f'class Credential:\n    name = models.CharField()\n    {body}\n'
        return _checker.unapproved_names(source)

    def test_a_secret_field_named_something_innocuous_is_still_rejected(self):
        """
        The case a name denylist cannot catch, and the reason this is an
        allowlist. None of these words appear in any forbidden-token list, and
        each would hold material outright.
        """
        for body in (
            'material = models.JSONField()',
            'payload = models.JSONField()',
            'blob = models.TextField()',
            'value = models.TextField()',
        ):
            with self.subTest(body=body):
                self.assertTrue(self._offenders(body), f'{body} was accepted')

    def test_an_annotated_field_is_rejected(self):
        """An `ast.Assign`-only walk misses this form entirely."""
        self.assertEqual(self._offenders('token: str = models.CharField()'), ['token'])

    def test_a_tuple_assigned_field_is_rejected(self):
        """So does reading only `target.id` on a single target."""
        self.assertEqual(
            sorted(self._offenders('secret_a, secret_b = models.CharField(), models.CharField()')),
            ['secret_a', 'secret_b'],
        )

    def test_the_approved_fields_are_accepted(self):
        self.assertEqual(self._offenders('username = models.CharField()'), [])

    def test_the_checker_and_the_model_agree(self):
        """
        Every name on the allowlist that is a real model field must exist, so a
        rename cannot leave a stale entry silently approving nothing while the
        renamed field goes unreviewed.
        """
        real = {getattr(f, 'name', '') for f in Credential._meta.get_fields()}
        declared = _checker.unapproved_names.__globals__['APPROVED_FIELDS']
        stale = sorted(
            name for name in declared
            if name not in real and name not in {'clone_fields', 'objects'}
        )
        self.assertEqual(stale, [], f'APPROVED_FIELDS names no longer on the model: {stale}')
