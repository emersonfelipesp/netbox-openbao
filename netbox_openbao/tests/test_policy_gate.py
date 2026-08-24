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

from django.db import transaction
from django.test import TransactionTestCase, override_settings
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
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.change_credential',
            'netbox_openbao.rotate_credential',
        )
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

    def test_bulk_patching_secret_data_is_refused_outside_the_permitted_groups(self):
        """
        `PATCH` on the *list* endpoint is a third route to the same write.

        NetBox's `BulkUpdateModelMixin.perform_bulk_update()` loops calling
        `self.perform_update(serializer)`, so the gate applied there covers this
        too — but only because it is applied in `perform_update` rather than in
        the detail route's dispatch. Asserted so a future refactor that moves it
        cannot silently open a bulk-shaped hole.
        """
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.change_credential',
            'netbox_openbao.rotate_credential',
        )
        before = self.credential.kv_version

        response = self.client.patch(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            [{'id': self.credential.pk, 'secret_data': {'password': 'replaced'}}],
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before)

    def test_a_member_of_a_permitted_group_may_patch_secret_data(self):
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.change_credential',
            'netbox_openbao.rotate_credential',
        )
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


class PolicyReassignmentTest(_GateFixture, APITestCase):
    """
    Moving a credential between tiers must not be a way around the group gate.

    The escalation this closes, in three requests: a user in `lab`'s groups but
    not `production`'s is refused a reveal on a production credential, PATCHes
    its `policy` to `lab` — an update carrying no `secret_data`, and therefore
    ungated when only material-bearing updates were checked — and reveals it.

    It works because credential paths are UUID-derived under one shared prefix,
    so the receiving tier's AppRole reads the very same secret. Layer 2 (the
    group gate) and layer 3 (the tier's own OpenBao policy) both fall to one
    request that never touches material.
    """

    def setUp(self):
        super().setUp()
        self.build_estate()
        self.lab = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=self.engine, openbao_policy='netbox-lab',
        )
        self.my_group = Group.objects.create(name='labops')
        self.lab.groups.add(self.my_group)
        self.user.groups.add(self.my_group)

        self.detail_url = reverse(
            'plugins-api:netbox_openbao-api:credential-detail', kwargs={'pk': self.credential.pk}
        )
        self.reveal_url = reverse(
            'plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk}
        )

    def grant_everything_except_membership(self):
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.change_credential',
            'netbox_openbao.reveal_credential',
        )

    def test_moving_a_credential_out_of_a_tier_is_refused(self):
        self.grant_everything_except_membership()

        response = self.client.patch(
            self.detail_url, {'policy': self.lab.pk}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.policy_id, self.policy.pk)

    def test_the_material_is_still_unreachable_after_attempting_the_move(self):
        self.grant_everything_except_membership()

        self.client.patch(self.detail_url, {'policy': self.lab.pk}, format='json', **self.header)
        response = self.client.get(self.reveal_url + '?reason=x', **self.header)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SECRET, response.content.decode())

    def test_an_ordinary_edit_is_refused_too(self):
        """
        The gate is on the update, not on the `policy` field specifically.
        Anything else would be a denylist, and the next writable field that
        changes who may read a credential would walk straight through it.
        """
        self.grant_everything_except_membership()

        response = self.client.patch(
            self.detail_url, {'description': 'harmless'}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 403)

    def test_a_member_of_the_tier_may_still_edit_and_move(self):
        self.grant_everything_except_membership()
        self.join_permitted_group()

        response = self.client.patch(
            self.detail_url, {'policy': self.lab.pk}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.policy_id, self.lab.pk)

    def test_an_ungated_tier_is_unaffected(self):
        self.policy.groups.clear()
        self.grant_everything_except_membership()

        response = self.client.patch(
            self.detail_url, {'description': 'harmless'}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200)


class RotatePermissionOnUpdateTest(_GateFixture, APITestCase):
    """
    An update carrying material is a rotation whatever verb it arrives on.

    `rotate` is a permission of its own precisely so replacing material can be
    withheld from someone who may otherwise edit a credential. `PUT`, `PATCH`,
    and the bulk list endpoint all reach `perform_update()` under
    `change_credential`, so gating only the dedicated `rotate` action left the
    same write reachable by a different verb — a principal deliberately denied
    rotation could inject replacement credentials or take an integration
    offline.
    """

    def setUp(self):
        super().setUp()
        self.build_estate()
        # Isolate from the tier group gate; this is about the NetBox permission.
        self.policy.groups.clear()
        self.detail_url = reverse(
            'plugins-api:netbox_openbao-api:credential-detail', kwargs={'pk': self.credential.pk}
        )
        self.list_url = reverse('plugins-api:netbox_openbao-api:credential-list')

    def test_patching_secret_data_needs_rotate_not_merely_change(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        before = self.credential.kv_version

        response = self.client.patch(
            self.detail_url, {'secret_data': {'password': 'injected'}}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before, 'Material was replaced without rotate.')

    def test_putting_secret_data_needs_rotate(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        before = self.credential.kv_version

        response = self.client.put(
            self.detail_url,
            {
                'name': self.credential.name,
                'credential_type': self.credential.credential_type,
                'policy': self.policy.pk,
                'secret_data': {'password': 'injected'},
            },
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before)

    def test_bulk_patching_secret_data_needs_rotate(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        before = self.credential.kv_version

        response = self.client.patch(
            self.list_url,
            [{'id': self.credential.pk, 'secret_data': {'password': 'injected'}}],
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before)

    def test_a_metadata_only_edit_still_needs_only_change(self):
        """
        The point of the permission split. Withholding `rotate` must not also
        withhold renaming, retagging, or adjusting a rotation interval.
        """
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')

        response = self.client.patch(
            self.detail_url, {'description': 'renamed'}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200)

    def test_holding_rotate_permits_the_write(self):
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.change_credential',
            'netbox_openbao.rotate_credential',
        )
        before = self.credential.kv_version

        response = self.client.patch(
            self.detail_url, {'secret_data': {'password': 'authorised'}}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200)
        self.credential.refresh_from_db()
        self.assertGreater(self.credential.kv_version, before)

    def test_a_constrained_rotate_permission_is_honoured(self):
        """`restrict()` rather than `has_perm()`, so constraints apply."""
        from core.models import ObjectType

        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.change_credential')
        constrained = ObjectPermission(
            name='rotate lab only',
            actions=['rotate'],
            constraints={'policy__slug': 'lab-only-nothing-matches'},
        )
        constrained.save()
        constrained.users.add(self.user)
        constrained.object_types.add(ObjectType.objects.get_for_model(Credential))
        before = self.credential.kv_version

        response = self.client.patch(
            self.detail_url, {'secret_data': {'password': 'injected'}}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 403)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, before)


class AuditLogDynamicFieldsTest(APITestCase):
    """
    NetBox's `BaseViewSet` passes `fields`/`omit` down to the serializer.

    A plain DRF `ModelSerializer` does not accept them, so `?brief=true`,
    `?fields=`, and `?omit=` each raised
    `TypeError: Field.__init__() got an unexpected keyword argument 'fields'`
    — a 500 on three ordinary query modes. Invisible while the viewset was
    DRF's own `ReadOnlyModelViewSet`, because nothing passed the arguments;
    adopting `NetBoxReadOnlyModelViewSet` to get constraint enforcement is what
    started passing them.
    """

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        policy = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=engine, openbao_policy='netbox-lab',
        )
        credential = Credential(
            name='switch-login',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=policy,
            engine=engine,
        )
        write_material(credential, {'password': SECRET})

        self.entry = CredentialAccessLog.objects.first()
        self.list_url = reverse('plugins-api:netbox_openbao-api:credentialaccesslog-list')
        self.detail_url = reverse(
            'plugins-api:netbox_openbao-api:credentialaccesslog-detail', kwargs={'pk': self.entry.pk}
        )
        self.add_permissions('netbox_openbao.view_credentialaccesslog')

    def test_brief_mode(self):
        response = self.client.get(f'{self.list_url}?brief=true', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data['results'][0]), {'id', 'url', 'display', 'action', 'timestamp'})

    def test_explicit_fields(self):
        response = self.client.get(f'{self.list_url}?fields=id,action', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data['results'][0]), {'id', 'action'})

    def test_omit(self):
        response = self.client.get(f'{self.list_url}?omit=reason', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('reason', response.data['results'][0])

    def test_detail_supports_them_too(self):
        response = self.client.get(f'{self.detail_url}?fields=id', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data), {'id'})

    def test_no_query_mode_returns_material(self):
        for qs in ('', '?brief=true', '?fields=message,reason', '?omit=id'):
            response = self.client.get(self.list_url + qs, **self.header)
            self.assertNotIn(SECRET, response.content.decode(), qs)


class DeletionOrderingTest(TransactionTestCase):
    """
    Destroying material is irreversible; a transaction is not.

    So the destroy must happen **after** the row's deletion commits. Doing it
    in `pre_delete` put the irreversible half first: a later failure in the
    same transaction restored the row and left it pointing at material that no
    longer existed. `perform_bulk_destroy()` puts N deletions in one
    transaction, so one failure at the end did that to every credential before
    it.

    A `TransactionTestCase` rather than the usual `TestCase`, because the
    behaviour under test *is* commit and rollback. `TestCase` wraps each test
    in an atomic block it never commits, so `transaction.on_commit()` callbacks
    would never fire and this suite would pass while asserting nothing.
    """

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.policy = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=self.engine, openbao_policy='netbox-lab',
        )
        self.credential = self._make('doomed', SECRET)
        self.path = self.credential.path

    def _make(self, name, password):
        credential = Credential(
            name=name,
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
            engine=self.engine,
        )
        write_material(credential, {'password': password})
        credential.refresh_from_db()
        return credential

    def test_a_committed_delete_destroys_the_material(self):
        self.credential.delete()

        self.assertNotIn(self.path, FakeBackend.store)

    def test_a_rolled_back_delete_leaves_the_material_intact(self):
        """
        The regression this ordering exists for. The row survives the rollback,
        so its material must survive with it — a restored row pointing at a
        destroyed secret is unrecoverable, and every consumer of it fails.
        """
        # Captured first: Django's Collector sets `instance.pk = None` on
        # delete(), and does not put it back when the transaction rolls back.
        pk = self.credential.pk

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.credential.delete()
                raise RuntimeError('something later in the same transaction failed')

        self.assertTrue(
            Credential.objects.filter(pk=pk).exists(),
            'The row should have been restored by the rollback.',
        )
        self.assertIn(
            self.path, FakeBackend.store,
            'The material was destroyed for a deletion that never committed.',
        )
        self.assertEqual(FakeBackend(self.engine).read(self.path), {'password': SECRET})

    def test_a_partially_failed_bulk_delete_destroys_nothing(self):
        """
        One transaction, several rows. A failure part-way through must not have
        already destroyed the material of the ones that came first.
        """
        second = self._make('also-doomed', 'second-secret')

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.credential.delete()
                second.delete()
                raise RuntimeError('the last one failed')

        self.assertEqual(Credential.objects.count(), 2)
        self.assertIn(self.path, FakeBackend.store)
        self.assertIn(second.path, FakeBackend.store)

    def test_the_deletion_is_audited_without_a_dangling_foreign_key(self):
        """
        By the time the destroy runs the row is gone, so the audit entry must
        record it by snapshot rather than by foreign key — linking would raise
        a deferred violation at commit and lose the record for the deletion it
        exists to capture.
        """
        uuid = self.credential.uuid
        self.credential.delete()

        entry = CredentialAccessLog.objects.filter(action='delete', success=True).first()
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.credential_id)
        self.assertEqual(entry.credential_uuid_snapshot, uuid)
        self.assertEqual(entry.credential_name_snapshot, 'doomed')
        self.assertNotIn(SECRET, entry.message)
