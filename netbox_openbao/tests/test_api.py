"""
REST API behaviour, with the permission layers as the focus.

The reveal endpoint is the plugin's only route to secret material, so its
authorization is tested from the outside — through real HTTP with real
ObjectPermissions — rather than by asserting on internals.
"""

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
