"""
The policy tier's group gate, on every surface that reaches a credential.

`CredentialPolicy.groups` is documented as authorization layer 2 in
`docs/security.md` — a coarse filter applied in addition to object
permissions. It was implemented in `api/views.CredentialViewSet._authorize`
and nowhere else, so the REST actions enforced it and the web UI did not: a
user in none of the tier's groups was refused a reveal over the API and served
the same material by the credential page.

These tests exist because that is not a bug a single-surface test suite can
find. Each surface is exercised separately and asserted to refuse *and* to
render no material, because "returned 403" and "leaked nothing" are different
claims and only the second one matters if the first regresses.
"""

from django.test import override_settings
from django.urls import reverse
from users.models import Group, ObjectPermission
from utilities.testing import APITestCase
from utilities.testing.views import ModelViewTestCase

from netbox_openbao import backends
from netbox_openbao.api.views import CredentialAccessLogViewSet
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialPolicy, SecretEngine
from netbox_openbao.services import stage_material, write_material

from .fakes import FakeBackend

SECRET = 'hunter2'


class _GateFixture:
    """Builds a credential on a tier gated to a group the test user is not in."""

    def build_estate(self):
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.policy = CredentialPolicy.objects.create(
            name='Production', slug='production', engine=self.engine, openbao_policy='netbox-prod',
        )
        self.permitted_group = Group.objects.create(name='secops')
        self.policy.groups.add(self.permitted_group)

        self.credential = Credential(
            name='core-switch-login',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
            engine=self.engine,
            username='admin',
        )
        # user=None: an internal caller has no group membership to consult, so
        # the fixture itself is not subject to the gate it is testing.
        write_material(self.credential, {'password': SECRET})
        self.credential.refresh_from_db()

    def join_permitted_group(self):
        self.user.groups.add(self.permitted_group)


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class UIRevealGateTest(_GateFixture, ModelViewTestCase):
    """The full-page and HTMX reveal views."""

    model = Credential

    def setUp(self):
        super().setUp()
        self.build_estate()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

    def full_page_url(self):
        return reverse('plugins:netbox_openbao:credential_reveal', kwargs={'pk': self.credential.pk})

    def partial_url(self):
        return reverse(
            'plugins:netbox_openbao:credential_reveal-partial', kwargs={'pk': self.credential.pk}
        )

    def test_full_page_reveal_is_refused_outside_the_permitted_groups(self):
        response = self.client.post(self.full_page_url(), data={'reason': 'CHG-1'}, follow=True)

        self.assertNotIn(SECRET.encode(), response.content)

    def test_htmx_reveal_is_refused_outside_the_permitted_groups(self):
        response = self.client.post(self.partial_url(), data={'reason': 'CHG-1'})

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SECRET.encode(), response.content)

    def test_htmx_refusal_renders_the_error_fragment_rather_than_a_403_page(self):
        """
        HTMX does not swap a non-2xx response by default, so an uncaught
        PermissionDenied would leave the panel silently unchanged. The view
        catches it and renders the same fragment slot a backend failure uses.
        """
        response = self.client.post(self.partial_url(), data={})

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b'<html', response.content.lower())
        self.assertIn(b'alert', response.content)

    def test_refusal_is_audited_as_a_failed_reveal(self):
        self.client.post(self.partial_url(), data={'reason': 'CHG-1'})

        entry = CredentialAccessLog.objects.filter(action='reveal', success=False).first()
        self.assertIsNotNone(entry, 'A refused reveal must still be recorded.')
        self.assertNotIn(SECRET, entry.message)

    def test_a_member_of_a_permitted_group_is_served(self):
        self.join_permitted_group()
        response = self.client.post(self.partial_url(), data={'reason': 'CHG-1'})

        self.assertEqual(response.status_code, 200)
        self.assertIn(SECRET.encode(), response.content)

    def test_an_ungated_tier_serves_everyone_holding_the_permission(self):
        """An empty group list means the tier does not use the gate."""
        self.policy.groups.clear()
        response = self.client.post(self.partial_url(), data={'reason': 'CHG-1'})

        self.assertEqual(response.status_code, 200)
        self.assertIn(SECRET.encode(), response.content)


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class UIStagedTransitionGateTest(_GateFixture, ModelViewTestCase):
    """Promote and discard, which decide what every consumer is served."""

    model = Credential

    def setUp(self):
        super().setUp()
        self.build_estate()
        stage_material(self.credential, {'password': 'candidate'})
        self.credential.refresh_from_db()
        self.live_version = self.credential.live_kv_version
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')

    def url(self, name):
        return reverse(f'plugins:netbox_openbao:credential_{name}', kwargs={'pk': self.credential.pk})

    def test_promote_is_refused_outside_the_permitted_groups(self):
        self.client.post(self.url('promote'), data={})

        self.credential.refresh_from_db()
        self.assertTrue(self.credential.has_staged_version)
        self.assertEqual(self.credential.live_kv_version, self.live_version)

    def test_discard_is_refused_outside_the_permitted_groups(self):
        self.client.post(self.url('discard'), data={})

        self.credential.refresh_from_db()
        self.assertTrue(self.credential.has_staged_version)

    def test_a_member_of_a_permitted_group_may_promote(self):
        self.join_permitted_group()
        self.client.post(self.url('promote'), data={})

        self.credential.refresh_from_db()
        self.assertFalse(self.credential.has_staged_version)


class APIGateTest(_GateFixture, APITestCase):
    """The REST surfaces, including the update route that bypasses `rotate`."""

    def setUp(self):
        super().setUp()
        self.build_estate()

    def detail_url(self):
        return reverse('plugins-api:netbox_openbao-api:credential-detail', kwargs={'pk': self.credential.pk})

    def test_reveal_is_refused_outside_the_permitted_groups(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        url = reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk})

        response = self.client.get(url, **self.header)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SECRET, response.content.decode())

    def test_patching_secret_data_is_refused_outside_the_permitted_groups(self):
        """
        `PATCH` is routed by DRF's own `update()` and never reaches the
        action's authorization helper, so a caller could otherwise replace
        material through the standard update route that `rotate` refuses —
        the same gate, bypassed by a different verb.
        """
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        before = self.credential.kv_version

        response = self.client.patch(
            self.detail_url(),
            {'secret_data': {'password': 'replaced'}},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before)

    def test_a_member_of_a_permitted_group_may_patch_secret_data(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        self.join_permitted_group()
        before = self.credential.kv_version

        response = self.client.patch(
            self.detail_url(),
            {'secret_data': {'password': 'replaced'}},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 200)
        self.credential.refresh_from_db()
        self.assertGreater(self.credential.kv_version, before)


class AccessLogRestrictionTest(APITestCase):
    """
    The audit log's REST endpoint must honour ObjectPermission constraints.

    NetBox applies them in `BaseViewSet.initial()`, which is what calls
    `queryset.restrict()`. A viewset outside that hierarchy is still gated on
    the model-level permission but ignores every constraint — so a role scoped
    to one tier read the whole estate's log through the API while the UI list
    view held it to the constraint.
    """

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.lab = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=self.engine, openbao_policy='netbox-lab',
        )
        self.production = CredentialPolicy.objects.create(
            name='Production', slug='production', engine=self.engine, openbao_policy='netbox-prod',
        )

        for name, policy in (('lab-login', self.lab), ('prod-login', self.production)):
            credential = Credential(
                name=name,
                credential_type=CredentialTypeChoices.TYPE_PASSWORD,
                policy=policy,
                engine=self.engine,
            )
            write_material(credential, {'password': SECRET})

        self.list_url = reverse('plugins-api:netbox_openbao-api:credentialaccesslog-list')

    def grant_constrained_view(self):
        from core.models import ObjectType

        permission = ObjectPermission(
            name='lab access log only',
            actions=['view'],
            constraints={'credential__policy__slug': 'lab'},
        )
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ObjectType.objects.get_for_model(CredentialAccessLog))

    def test_constraint_is_applied_to_the_list_endpoint(self):
        self.grant_constrained_view()

        response = self.client.get(self.list_url, **self.header)

        self.assertEqual(response.status_code, 200)
        names = {row['credential_name_snapshot'] for row in response.data['results']}
        self.assertEqual(names, {'lab-login'})

    def test_constraint_is_applied_to_the_detail_endpoint(self):
        self.grant_constrained_view()
        hidden = CredentialAccessLog.objects.get(credential_name_snapshot='prod-login')
        url = reverse(
            'plugins-api:netbox_openbao-api:credentialaccesslog-detail', kwargs={'pk': hidden.pk}
        )

        response = self.client.get(url, **self.header)

        self.assertEqual(response.status_code, 404)

    def test_the_viewset_declares_no_write_handler(self):
        """
        The read-only base must not have brought write routes with it: the
        same token that reveals a secret must not be able to erase the record
        of having done so.

        Asserted on the viewset rather than only over HTTP, because DRF runs
        `initial()` — and therefore the permission check — before it resolves
        the handler. A caller without the permission gets 403 whether or not
        the route exists, which would let a write mixin creep back in behind a
        passing test.
        """
        for handler in ('create', 'update', 'partial_update', 'destroy'):
            self.assertFalse(
                hasattr(CredentialAccessLogViewSet, handler),
                f'CredentialAccessLogViewSet gained a {handler}() handler; the audit log is evidence.',
            )

    def test_write_methods_are_not_allowed_even_with_the_permission(self):
        self.add_permissions(
            'netbox_openbao.view_credentialaccesslog',
            'netbox_openbao.add_credentialaccesslog',
            'netbox_openbao.change_credentialaccesslog',
            'netbox_openbao.delete_credentialaccesslog',
        )
        entry = CredentialAccessLog.objects.first()
        detail = reverse(
            'plugins-api:netbox_openbao-api:credentialaccesslog-detail', kwargs={'pk': entry.pk}
        )

        self.assertEqual(self.client.post(self.list_url, {}, format='json', **self.header).status_code, 405)
        self.assertEqual(self.client.delete(detail, **self.header).status_code, 405)
        self.assertEqual(
            self.client.patch(detail, {'reason': 'x'}, format='json', **self.header).status_code, 405
        )
