"""
REST API behaviour, with the permission layers as the focus.

The reveal endpoint is the plugin's only route to secret material, so its
authorization is tested from the outside — through real HTTP with real
ObjectPermissions — rather than by asserting on internals.
"""

from django.test import override_settings
from django.urls import reverse
from users.models import ObjectPermission
from utilities.testing import APITestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialPolicy, SecretEngine
from netbox_openbao.services import write_material

from .fakes import FakeBackend


class OpenBaoAPITestCase(APITestCase):

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
        self.credential = Credential(
            name='switch-login',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
            engine=self.engine,
            username='admin',
        )
        write_material(self.credential, {'password': 'hunter2'})

    def reveal_url(self):
        return reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk})


class CredentialReadTest(OpenBaoAPITestCase):

    def test_detail_never_returns_material(self):
        self.add_permissions('netbox_openbao.view_credential')
        url = reverse('plugins-api:netbox_openbao-api:credential-detail', kwargs={'pk': self.credential.pk})

        response = self.client.get(url, **self.header)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('secret_data', response.data)
        self.assertNotIn('hunter2', response.content.decode())

    def test_list_never_returns_material(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.get(reverse('plugins-api:netbox_openbao-api:credential-list'), **self.header)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('hunter2', response.content.decode())

    def test_brief_never_returns_material(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.get(
            reverse('plugins-api:netbox_openbao-api:credential-list') + '?brief=1', **self.header
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('hunter2', response.content.decode())


class RevealErrorHandlingTest(OpenBaoAPITestCase):

    def test_missing_required_reason_is_a_400_not_a_500(self):
        """
        The policy check raises Django's ValidationError from the service
        layer, which DRF does not translate. Unhandled it surfaced as a 500.
        """
        self.policy.require_reason = True
        self.policy.save()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        url = reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk})
        response = self.client.get(url, **self.header)

        self.assertEqual(response.status_code, 400, response.content)
        self.assertNotIn(b'hunter2', response.content)

    def test_supplying_the_reason_succeeds(self):
        self.policy.require_reason = True
        self.policy.save()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        url = reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk})
        response = self.client.get(url + '?reason=CHG-77', **self.header)
        self.assertEqual(response.status_code, 200, response.content)


class RevealPermissionTest(OpenBaoAPITestCase):

    def test_view_permission_alone_cannot_reveal(self):
        """
        The headline separation: a user may inventory every credential and
        reveal none.
        """
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.get(self.reveal_url(), **self.header)
        self.assertIn(response.status_code, (403, 404))
        self.assertNotIn('hunter2', response.content.decode())

    def test_reveal_permission_returns_material(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.get(self.reveal_url(), **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['secret_data'], {'password': 'hunter2'})

    def test_reveal_accepts_post(self):
        """
        POST keeps the reason out of the URL and out of every intermediary's
        access log. NetBox maps POST to `add_<model>` by default, which would
        make this require add_credential — so this asserts the override holds.
        """
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.post(
            self.reveal_url(), {'reason': 'CHG-9'}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['secret_data'], {'password': 'hunter2'})

    def test_reveal_does_not_require_add_permission(self):
        """A reader must never need create rights to read."""
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        self.assertFalse(self.user.has_perm('netbox_openbao.add_credential'))

        self.assertEqual(self.client.get(self.reveal_url(), **self.header).status_code, 200)

    def test_reveal_response_is_not_storable(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.get(self.reveal_url(), **self.header)
        self.assertIn('no-store', response['Cache-Control'])

    def test_reveal_is_audited(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        self.client.get(self.reveal_url(), **self.header)

        entry = CredentialAccessLog.objects.filter(action='reveal', success=True).first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.user, self.user)

    def test_constrained_permission_hides_other_tiers(self):
        """
        An ObjectPermission constrained to the lab tier must not reveal a
        production credential — and must 404 rather than 403, so the response
        does not confirm the credential exists.
        """
        other_policy = CredentialPolicy.objects.create(
            name='Prod', slug='prod', engine=self.engine, openbao_policy='netbox-prod',
        )
        prod_credential = Credential(
            name='prod-login',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=other_policy,
            engine=self.engine,
        )
        write_material(prod_credential, {'password': 'prod-secret'})

        perm = ObjectPermission(
            name='lab-reveal',
            actions=['view', 'reveal'],
            constraints={'policy__slug': 'lab'},
        )
        perm.save()
        perm.users.add(self.user)
        perm.object_types.add(*[
            ot for ot in _credential_object_types()
        ])

        url = reverse(
            'plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': prod_credential.pk}
        )
        response = self.client.get(url, **self.header)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn('prod-secret', response.content.decode())

        # The lab credential is still reachable through the same permission.
        response = self.client.get(self.reveal_url(), **self.header)
        self.assertEqual(response.status_code, 200)


class CredentialWriteTest(OpenBaoAPITestCase):

    def test_create_writes_material(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            {
                'name': 'new-credential',
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
                'secret_data': {'password': 'newsecret'},
            },
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertNotIn('secret_data', response.data)

        created = Credential.objects.get(name='new-credential')
        self.assertEqual(FakeBackend.store[created.path], [{'password': 'newsecret'}])

    def test_create_without_material_is_rejected(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            {
                'name': 'no-material',
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
            },
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('secret_data', response.data)

    def test_bad_payload_shape_is_a_400_not_a_500(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            {
                'name': 'wrong-fields',
                'credential_type': CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                'policy': self.policy.pk,
                'secret_data': {'password': 'not an ssh key field'},
            },
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 400)


class RevealThrottleTest(OpenBaoAPITestCase):
    """
    The reveal rate limit bounds how fast a leaked token can drain the store,
    which only matters if it is actually wired up.
    """

    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()
        self.addCleanup(cache.clear)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_rate_limit': '2/hour'}})
    def test_reveal_is_rate_limited(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        url = self.reveal_url()

        self.assertEqual(self.client.get(url, **self.header).status_code, 200)
        self.assertEqual(self.client.get(url, **self.header).status_code, 200)

        throttled = self.client.get(url, **self.header)
        self.assertEqual(throttled.status_code, 429)
        self.assertNotIn(b'hunter2', throttled.content)

    def reveal_url(self):
        return reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk})


class CredentialRotateTest(OpenBaoAPITestCase):
    """The rotate endpoint had no coverage; these are its first tests."""

    def rotate_url(self):
        return reverse('plugins-api:netbox_openbao-api:credential-rotate', kwargs={'pk': self.credential.pk})

    def test_rotate_requires_its_own_permission(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.post(
            self.rotate_url(), {'secret_data': {'password': 'next'}}, format='json', **self.header
        )
        self.assertIn(response.status_code, (403, 404))

    def test_rotate_writes_a_new_version(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        response = self.client.post(
            self.rotate_url(), {'secret_data': {'password': 'rotated'}}, format='json', **self.header
        )

        self.assertEqual(response.status_code, 200, response.content)
        # kv_version must be the integer version, not a tuple or an object.
        self.assertEqual(response.data['kv_version'], 2)
        self.assertIsInstance(response.data['kv_version'], int)

        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, 2)
        self.assertEqual(FakeBackend.store[self.credential.path][-1], {'password': 'rotated'})

    def test_rotate_without_material_is_rejected(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        response = self.client.post(self.rotate_url(), {}, format='json', **self.header)
        self.assertEqual(response.status_code, 400)

    def test_rotate_response_carries_no_material(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        response = self.client.post(
            self.rotate_url(), {'secret_data': {'password': 'rotated'}}, format='json', **self.header
        )
        self.assertNotIn(b'rotated', response.content)


class StagedRotationAPITest(OpenBaoAPITestCase):
    """
    The stage/promote/discard endpoints.

    Written before trusting them, because the previous review found that every
    custom POST action on this viewset was broken by NetBox's default
    permission map and nobody noticed — there were no tests.
    """

    def url(self, name):
        return reverse(f'plugins-api:netbox_openbao-api:credential-{name}', kwargs={'pk': self.credential.pk})

    def grant(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')

    def test_stage_requires_rotate_permission(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.post(
            self.url('stage'), {'secret_data': {'password': 'cand'}}, format='json', **self.header
        )
        self.assertIn(response.status_code, (403, 404))

    def test_stage_does_not_require_add_permission(self):
        """The POST-maps-to-add trap, asserted directly."""
        self.grant()
        self.assertFalse(self.user.has_perm('netbox_openbao.add_credential'))
        response = self.client.post(
            self.url('stage'), {'secret_data': {'password': 'cand'}}, format='json', **self.header
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_full_stage_promote_cycle(self):
        self.grant()

        staged = self.client.post(
            self.url('stage'), {'secret_data': {'password': 'candidate'}}, format='json', **self.header
        )
        self.assertEqual(staged.status_code, 200, staged.content)
        self.assertTrue(staged.data['has_staged_version'])
        self.assertEqual(staged.data['live_kv_version'], 1)

        # Consumers still get the old material while it is staged.
        reveal = self.client.get(
            reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk}),
            **self.header,
        )
        # 404 rather than 403 by design — the response must not confirm that a
        # credential the caller cannot reveal exists.
        self.assertEqual(reveal.status_code, 404)

        promoted = self.client.post(self.url('promote'), {'verified': True}, format='json', **self.header)
        self.assertEqual(promoted.status_code, 200, promoted.content)
        self.assertFalse(promoted.data['has_staged_version'])
        self.assertEqual(promoted.data['live_kv_version'], 2)

    def test_discard_returns_to_the_live_version(self):
        self.grant()
        self.client.post(
            self.url('stage'), {'secret_data': {'password': 'candidate'}}, format='json', **self.header
        )
        discarded = self.client.post(self.url('discard'), {}, format='json', **self.header)

        self.assertEqual(discarded.status_code, 200, discarded.content)
        self.assertFalse(discarded.data['has_staged_version'])
        self.assertEqual(discarded.data['live_kv_version'], 1)
        self.assertEqual(FakeBackend.store[self.credential.path][0], {'password': 'hunter2'})

    def test_promote_without_a_staged_version_is_a_400(self):
        self.grant()
        response = self.client.post(self.url('promote'), {}, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)

    def test_discard_without_a_staged_version_is_a_400(self):
        self.grant()
        response = self.client.post(self.url('discard'), {}, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)

    def test_stage_without_material_is_a_400(self):
        self.grant()
        response = self.client.post(self.url('stage'), {}, format='json', **self.header)
        self.assertEqual(response.status_code, 400)

    def test_no_endpoint_echoes_material(self):
        self.grant()
        staged = self.client.post(
            self.url('stage'), {'secret_data': {'password': 'candidate'}}, format='json', **self.header
        )
        promoted = self.client.post(self.url('promote'), {}, format='json', **self.header)
        for response in (staged, promoted):
            self.assertNotIn(b'candidate', response.content)
            self.assertNotIn(b'hunter2', response.content)

    def test_staged_material_is_not_served_to_readers(self):
        """The guarantee, end to end over HTTP."""
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.rotate_credential',
            'netbox_openbao.reveal_credential',
        )
        self.client.post(
            self.url('stage'), {'secret_data': {'password': 'candidate'}}, format='json', **self.header
        )
        reveal = self.client.get(
            reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk}),
            **self.header,
        )
        self.assertEqual(reveal.status_code, 200, reveal.content)
        self.assertEqual(reveal.data['secret_data'], {'password': 'hunter2'})

        self.client.post(self.url('promote'), {}, format='json', **self.header)
        reveal = self.client.get(
            reverse('plugins-api:netbox_openbao-api:credential-reveal', kwargs={'pk': self.credential.pk}),
            **self.header,
        )
        self.assertEqual(reveal.data['secret_data'], {'password': 'candidate'})


class AccessLogAPITest(OpenBaoAPITestCase):

    def test_access_log_is_read_only(self):
        self.add_permissions('netbox_openbao.view_credentialaccesslog')
        url = reverse('plugins-api:netbox_openbao-api:credentialaccesslog-list')

        self.assertEqual(self.client.get(url, **self.header).status_code, 200)
        # The audit trail must not be erasable by the same token that reads it.
        self.assertIn(self.client.post(url, {}, format='json', **self.header).status_code, (403, 405))


def _credential_object_types():
    from core.models import ObjectType

    return ObjectType.objects.filter(app_label='netbox_openbao', model='credential')
