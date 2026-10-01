from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse
from users.models import ObjectPermission
from utilities.testing import APITestCase

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, ServiceEndpoint, SSHPublicKey
from netbox_openbao.secrets.generators import generate_ssh_keypair
from netbox_openbao.services import write_material

from .base import MaterialTransactionTestMixin, OpenBaoTestCase


class ServiceEndpointModelTest(OpenBaoTestCase):
    def setUp(self):
        super().setUp()
        site = Site.objects.create(name='Site', slug='site')
        manufacturer = Manufacturer.objects.create(name='Maker', slug='maker')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Model', slug='model')
        role = DeviceRole.objects.create(name='Role', slug='role')
        self.device = Device.objects.create(
            name='router', site=site, device_type=device_type, role=role,
        )
        self.content_type = ContentType.objects.get_for_model(self.device)

    def endpoint(self, **kwargs):
        values = {
            'assigned_object_type': self.content_type,
            'assigned_object_id': self.device.pk,
            'service_type': 'ssh',
            'port': 22,
        }
        values.update(kwargs)
        return ServiceEndpoint(**values)

    def test_rejects_unregistered_object_type(self):
        endpoint = self.endpoint(assigned_object_type=ContentType.objects.get_for_model(ContentType))
        with self.assertRaises(ValidationError):
            endpoint.full_clean()

    def test_unique_object_service_port(self):
        self.endpoint().save()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.endpoint().save()

    def test_options_reject_secret_shaped_keys(self):
        endpoint = self.endpoint(options={'password': 'must-not-be-stored'})
        with self.assertRaises(ValidationError):
            endpoint.full_clean()

    def test_public_key_fingerprint_is_computed(self):
        endpoint = self.endpoint()
        endpoint.save()
        public_key = generate_ssh_keypair('ed25519')['public_key']
        user = get_user_model().objects.create_user(username='key-owner')
        key = SSHPublicKey(user=user, service_endpoint=endpoint, public_key=public_key)
        key.save()
        self.assertTrue(key.fingerprint.startswith('SHA256:'))
        self.assertEqual(key.key_type, 'ed25519')

    def test_public_key_requires_ssh_endpoint(self):
        endpoint = self.endpoint(service_type='http', port=80)
        endpoint.save()
        user = get_user_model().objects.create_user(username='key-owner')
        key = SSHPublicKey(user=user, service_endpoint=endpoint, public_key='ssh-ed25519 AAAA')
        with self.assertRaises(ValidationError):
            key.full_clean(exclude=('fingerprint', 'key_type'))


class _ServiceEndpointFixtureMixin(MaterialTransactionTestMixin):
    """Shared FakeBackend/engine/policy/credential/endpoint estate.

    Both `ServiceEndpointAPITest` and `ServiceEndpointWebCredentialVisibilityTest`
    need this exact fixture. Sharing it here — rather than the web test
    subclassing the API test case — keeps the API tests from running twice
    under two test-runner labels.
    """

    def setUp(self):
        super().setUp()
        from netbox_openbao import backends
        from netbox_openbao.tests.fakes import FakeBackend

        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        site = Site.objects.create(name='Site', slug='site')
        manufacturer = Manufacturer.objects.create(name='Maker', slug='maker')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Model', slug='model')
        role = DeviceRole.objects.create(name='Role', slug='role')
        self.device = Device.objects.create(
            name='router', site=site, device_type=device_type, role=role,
        )
        self.content_type = ContentType.objects.get_for_model(self.device)
        from netbox_openbao.models import CredentialPolicy, SecretEngine

        engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        policy = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=engine, openbao_policy='lab',
        )
        self.credential = Credential(
            name='login', credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=policy, engine=engine, username='admin',
        )
        write_material(self.credential, {'password': 'resolve-secret-canary'})
        self.endpoint = ServiceEndpoint.objects.create(
            assigned_object=self.device, service_type='ssh', port=22, credential=self.credential,
        )

    def _resolve_url(self):
        return (
            reverse('plugins-api:netbox_openbao-api:resolve')
            + f'?object_type=dcim.device&object_id={self.device.pk}&service_type=ssh'
        )


class ServiceEndpointAPITest(_ServiceEndpointFixtureMixin, APITestCase):
    def test_service_endpoint_crud_requires_permissions(self):
        url = reverse('plugins-api:netbox_openbao-api:serviceendpoint-list')
        self.assertIn(self.client.get(url, **self.header).status_code, (403, 404))
        self.add_permissions(
            'netbox_openbao.add_serviceendpoint', 'netbox_openbao.view_serviceendpoint',
            'netbox_openbao.change_serviceendpoint', 'netbox_openbao.delete_serviceendpoint',
            'netbox_openbao.view_credential',
        )
        self.assertEqual(self.client.get(url, **self.header).status_code, 200)
        created = self.client.post(url, {
            'assigned_object_type': 'dcim.device', 'assigned_object_id': self.device.pk,
            'service_type': 'http', 'port': 8080,
        }, format='json', **self.header)
        self.assertEqual(created.status_code, 201, created.content)
        detail = reverse(
            'plugins-api:netbox_openbao-api:serviceendpoint-detail', kwargs={'pk': created.data['id']},
        )
        self.assertEqual(self.client.patch(detail, {'port': 8081}, format='json', **self.header).status_code, 200)
        self.assertEqual(self.client.delete(detail, **self.header).status_code, 204)

    def test_ssh_public_key_crud_requires_permissions(self):
        url = reverse('plugins-api:netbox_openbao-api:sshpublickey-list')
        self.assertIn(self.client.get(url, **self.header).status_code, (403, 404))
        self.add_permissions(
            'netbox_openbao.add_sshpublickey', 'netbox_openbao.view_sshpublickey',
            'netbox_openbao.change_sshpublickey', 'netbox_openbao.delete_sshpublickey',
        )
        self.assertEqual(self.client.get(url, **self.header).status_code, 200)
        created = self.client.post(url, {
            'user': self.user.pk, 'service_endpoint': self.endpoint.pk,
            'public_key': generate_ssh_keypair('ed25519')['public_key'],
        }, format='json', **self.header)
        self.assertEqual(created.status_code, 201, created.content)
        detail = reverse(
            'plugins-api:netbox_openbao-api:sshpublickey-detail', kwargs={'pk': created.data['id']},
        )
        response = self.client.patch(detail, {'installed_at': None}, format='json', **self.header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.delete(detail, **self.header).status_code, 204)

    def test_resolve_denies_target_without_object_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint', 'netbox_openbao.view_credential')
        response = self.client.get(self._resolve_url(), **self.header)
        self.assertEqual(response.status_code, 403)

    def test_resolve_returns_metadata_and_never_material(self):
        permission = ObjectPermission(name='view resolve target', actions=['view'])
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ContentType.objects.get_for_model(Device))
        self.add_permissions('netbox_openbao.view_serviceendpoint', 'netbox_openbao.view_credential')
        response = self.client.get(self._resolve_url(), **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['service_endpoints'][0]['credential']['username'], 'admin')
        self.assertNotIn('resolve-secret-canary', response.content.decode())
        self.assertNotIn('secret_data', response.content.decode())
        endpoint = response.data['service_endpoints'][0]
        self.assertEqual(endpoint['ssh_known_hosts_entry'], self.endpoint.ssh_known_hosts_entry)
        self.assertEqual(endpoint['ssh_strict_host_key_checking'], self.endpoint.ssh_strict_host_key_checking)

    def test_credential_import_source_filter_is_exact(self):
        self.add_permissions('netbox_openbao.view_credential')
        credential = self.endpoint.credential
        Credential.objects.filter(pk=credential.pk).update(import_source='netbox_nms.DeviceCredential:7')
        url = reverse('plugins-api:netbox_openbao-api:credential-list')
        response = self.client.get(url + '?import_source=netbox_nms.DeviceCredential:7', **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual([item['id'] for item in response.data['results']], [credential.pk])
        response = self.client.get(url + '?import_source=netbox_nms.DeviceCredential:70', **self.header)
        self.assertEqual(response.data['count'], 0)

    def test_endpoint_write_rejects_credential_the_caller_cannot_view(self):
        self.add_permissions(
            'netbox_openbao.view_serviceendpoint', 'netbox_openbao.add_serviceendpoint',
            'netbox_openbao.change_serviceendpoint',
        )
        url = reverse('plugins-api:netbox_openbao-api:serviceendpoint-list')
        response = self.client.post(url, {
            'assigned_object_type': 'dcim.device', 'assigned_object_id': self.device.pk,
            'service_type': 'netconf', 'port': 830, 'credential': self.credential.pk,
        }, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(ServiceEndpoint.objects.filter(service_type='netconf').exists())

        unbound = ServiceEndpoint.objects.create(assigned_object=self.device, service_type='gnmi', port=57400)
        detail = reverse('plugins-api:netbox_openbao-api:serviceendpoint-detail', kwargs={'pk': unbound.pk})
        response = self.client.patch(detail, {'credential': self.credential.pk}, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)
        unbound.refresh_from_db()
        self.assertIsNone(unbound.credential_id)

    def test_service_endpoint_list_hides_credential_without_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint')
        url = reverse('plugins-api:netbox_openbao-api:serviceendpoint-list')
        response = self.client.get(url, **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        endpoint = next(item for item in response.data['results'] if item['id'] == self.endpoint.pk)
        self.assertIsNone(endpoint['credential'])
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_service_endpoint_detail_hides_credential_without_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint')
        detail = reverse('plugins-api:netbox_openbao-api:serviceendpoint-detail', kwargs={'pk': self.endpoint.pk})
        response = self.client.get(detail, **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(response.data['credential'])

    def test_service_endpoint_detail_exposes_bounded_credential_with_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint', 'netbox_openbao.view_credential')
        detail = reverse('plugins-api:netbox_openbao-api:serviceendpoint-detail', kwargs={'pk': self.endpoint.pk})
        response = self.client.get(detail, **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        credential = response.data['credential']
        self.assertEqual(credential['username'], 'admin')
        self.assertEqual(set(credential), {'id', 'url', 'display', 'name', 'credential_type', 'username'})
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_resolve_hides_credential_when_credential_permission_is_absent(self):
        permission = ObjectPermission(name='view resolve target', actions=['view'])
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ContentType.objects.get_for_model(Device))
        self.add_permissions('netbox_openbao.view_serviceendpoint')
        response = self.client.get(self._resolve_url(), **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(response.data['service_endpoints'][0]['credential'])
        self.assertNotIn('resolve-secret-canary', response.content.decode())


class ServiceEndpointWebCredentialVisibilityTest(_ServiceEndpointFixtureMixin, APITestCase):
    """The web list and detail views must hide credentials the viewer cannot view."""

    def _login(self):
        self.client.force_login(self.user)

    def test_list_and_detail_hide_credential_without_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint')
        self._login()
        for url in (
            reverse('plugins:netbox_openbao:serviceendpoint_list'),
            reverse('plugins:netbox_openbao:serviceendpoint', kwargs={'pk': self.endpoint.pk}),
        ):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(self.credential.get_absolute_url(), response.content.decode())

    def test_list_shows_credential_with_permission(self):
        self.add_permissions('netbox_openbao.view_serviceendpoint', 'netbox_openbao.view_credential')
        self._login()
        response = self.client.get(reverse('plugins:netbox_openbao:serviceendpoint_list'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.credential.get_absolute_url(), response.content.decode())


class EndpointWithCredentialAPITest(_ServiceEndpointFixtureMixin, APITestCase):
    """The atomic endpoint-with-credential write binds material and endpoint together."""

    def setUp(self):
        super().setUp()
        from netbox_openbao.models import CredentialPolicy

        self.policy = CredentialPolicy.objects.get(slug='lab')
        self.url = reverse('plugins-api:netbox_openbao-api:serviceendpoint-with-credential')
        permission = ObjectPermission(name='view device target', actions=['view'])
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ContentType.objects.get_for_model(Device))

    def _grant_all(self):
        self.add_permissions(
            'netbox_openbao.add_serviceendpoint', 'netbox_openbao.change_serviceendpoint',
            'netbox_openbao.view_serviceendpoint', 'netbox_openbao.add_credential',
            'netbox_openbao.view_credential', 'netbox_openbao.view_credentialpolicy',
        )

    def _payload(self, **overrides):
        payload = {
            'assigned_object_type': 'dcim.device',
            'assigned_object_id': self.device.pk,
            'service_type': 'netconf',
            'host': '10.0.0.9',
            'port': 830,
            'options': {'netconf_driver': 'huaweiyang', 'enabled': False},
            'new_credential': {
                'name': 'router netconf',
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
                'username': 'admin',
                'secret_data': {'password': 'netconf-secret-canary'},
            },
        }
        payload.update(overrides)
        return payload

    def test_creates_credential_and_endpoint_together(self):
        self._grant_all()
        response = self.client.post(self.url, self._payload(), format='json', **self.header)
        self.assertEqual(response.status_code, 201, response.content)
        endpoint = ServiceEndpoint.objects.get(pk=response.data['id'])
        self.assertEqual(endpoint.service_type, 'netconf')
        self.assertEqual(endpoint.options['enabled'], False)
        self.assertEqual(endpoint.credential.name, 'router netconf')
        self.assertNotIn('netconf-secret-canary', response.content.decode())

    def test_incompatible_credential_type_is_rejected_without_writing(self):
        self._grant_all()
        before = Credential.objects.count()
        payload = self._payload(service_type='snmp', port=161)
        response = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(Credential.objects.count(), before)
        self.assertFalse(ServiceEndpoint.objects.filter(service_type='snmp').exists())

    def test_existing_credential_updates_the_endpoint_in_place(self):
        self._grant_all()
        payload = self._payload(
            service_type='ssh', port=22, new_credential=None,
            existing_credential=self.credential.pk, host='10.0.0.10',
        )
        response = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.host, '10.0.0.10')
        self.assertEqual(ServiceEndpoint.objects.filter(service_type='ssh').count(), 1)

    def test_requires_credential_create_permission_and_writes_nothing(self):
        self.add_permissions(
            'netbox_openbao.add_serviceendpoint', 'netbox_openbao.change_serviceendpoint',
            'netbox_openbao.view_credentialpolicy',
        )
        before = Credential.objects.count()
        response = self.client.post(self.url, self._payload(), format='json', **self.header)
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(Credential.objects.count(), before)

    def test_replayed_request_with_idempotency_key_creates_one_credential(self):
        self._grant_all()
        payload = self._payload(idempotency_key='nms-ui-req-1')
        first = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(first.status_code, 201, first.content)
        before = Credential.objects.count()
        second = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(second.status_code, 200, second.content)
        self.assertEqual(Credential.objects.count(), before)
        self.assertEqual(second.data['credential']['id'], first.data['credential']['id'])

    def test_reusing_a_key_for_a_different_request_is_refused(self):
        self._grant_all()
        first = self.client.post(self.url, self._payload(idempotency_key='k-2'), format='json', **self.header)
        self.assertEqual(first.status_code, 201, first.content)
        before = Credential.objects.count()
        other = self._payload(idempotency_key='k-2', port=8830)
        response = self.client.post(self.url, other, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(Credential.objects.count(), before)

    def test_constrained_change_permission_is_enforced(self):
        self.add_permissions(
            'netbox_openbao.add_serviceendpoint', 'netbox_openbao.view_serviceendpoint',
            'netbox_openbao.view_credential',
        )
        restricted = ObjectPermission(
            name='change other endpoints only', actions=['change'], constraints={'port': 65000},
        )
        restricted.save()
        restricted.users.add(self.user)
        restricted.object_types.add(ContentType.objects.get_for_model(ServiceEndpoint))
        payload = self._payload(
            service_type='ssh', port=22, new_credential=None, existing_credential=self.credential.pk,
            host='10.0.0.99',
        )
        response = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(response.status_code, 403, response.content)
        self.endpoint.refresh_from_db()
        self.assertNotEqual(self.endpoint.host, '10.0.0.99')

    def test_target_permission_revoked_while_waiting_for_locks_writes_nothing(self):
        from unittest import mock

        from netbox_openbao import endpoint_credentials

        self._grant_all()
        before = Credential.objects.count()
        real = endpoint_credentials._save_endpoint

        def revoke_then_save(*args, **kwargs):
            ObjectPermission.objects.filter(name='view device target').delete()
            return real(*args, **kwargs)

        with mock.patch.object(endpoint_credentials, '_save_endpoint', side_effect=revoke_then_save):
            response = self.client.post(self.url, self._payload(), format='json', **self.header)
        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(Credential.objects.count(), before)
        self.assertFalse(ServiceEndpoint.objects.filter(service_type='netconf', port=830).exists())

    def test_exactly_one_credential_source_is_required(self):
        self._grant_all()
        payload = self._payload(existing_credential=self.credential.pk)
        response = self.client.post(self.url, payload, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)


class EndpointRevealCredentialAPITest(_ServiceEndpointFixtureMixin, APITestCase):
    """Reveal through an endpoint only while it still matches what was approved."""

    def setUp(self):
        super().setUp()
        self.add_permissions(
            'netbox_openbao.view_serviceendpoint', 'netbox_openbao.view_credential',
            'netbox_openbao.reveal_credential',
        )
        self.url = reverse(
            'plugins-api:netbox_openbao-api:serviceendpoint-reveal-credential', kwargs={'pk': self.endpoint.pk},
        )

    def _expected(self, **overrides):
        self.endpoint.refresh_from_db()
        body = {
            'reason': 'rpc execution 1',
            'endpoint_revision': self.endpoint.last_updated.isoformat().replace('+00:00', 'Z'),
            'object_type': 'dcim.device',
            'object_id': self.device.pk,
            'credential_uuid': str(self.credential.uuid),
            'credential_type': self.credential.credential_type,
            'kv_version': Credential.objects.get(pk=self.credential.pk).live_kv_version,
        }
        body.update(overrides)
        return body

    def test_permission_revoked_while_waiting_for_locks_stops_the_reveal(self):
        from unittest import mock

        from users.models import ObjectPermission as ObjPerm

        real = ServiceEndpoint.objects.select_for_update

        def revoke_then_lock(*args, **kwargs):
            ObjPerm.objects.filter(actions__contains=['reveal']).delete()
            return real(*args, **kwargs)

        with mock.patch.object(ServiceEndpoint.objects, 'select_for_update', side_effect=revoke_then_lock):
            response = self.client.post(self.url, self._expected(), format='json', **self.header)
        self.assertEqual(response.status_code, 403, response.content)
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_credential_rebound_without_new_revision_returns_no_material(self):
        from unittest import mock

        real = ServiceEndpoint.objects.select_for_update

        def rebind_then_lock(*args, **kwargs):
            # A queryset update keeps last_updated, so only the binding changes.
            ServiceEndpoint.objects.filter(pk=self.endpoint.pk).update(credential=None)
            return real(*args, **kwargs)

        expected = self._expected()
        with mock.patch.object(ServiceEndpoint.objects, 'select_for_update', side_effect=rebind_then_lock):
            response = self.client.post(self.url, expected, format='json', **self.header)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.data['mismatch'], 'credential_id')
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_unpromoted_credential_is_revealed_at_its_latest_version(self):
        credential = Credential.objects.get(pk=self.credential.pk)
        latest = credential.live_kv_version
        Credential.objects.filter(pk=credential.pk).update(live_kv_version=None, kv_version=latest)
        response = self.client.post(self.url, self._expected(kv_version=latest), format='json', **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['kv_version'], latest)

    def test_missing_material_version_is_rejected(self):
        body = self._expected()
        body.pop('kv_version')
        response = self.client.post(self.url, body, format='json', **self.header)
        self.assertEqual(response.status_code, 400, response.content)

    def test_unapproved_material_version_returns_no_material(self):
        body = self._expected(kv_version=self._expected()['kv_version'] + 1)
        response = self.client.post(self.url, body, format='json', **self.header)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.data['mismatch'], 'kv_version')
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_reveals_when_everything_still_matches(self):
        response = self.client.post(self.url, self._expected(), format='json', **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['secret_data'], {'password': 'resolve-secret-canary'})
        self.assertEqual(response.data['endpoint_id'], self.endpoint.pk)

    def test_changed_endpoint_revision_returns_no_material(self):
        expected = self._expected()
        ServiceEndpoint.objects.filter(pk=self.endpoint.pk).update(host='10.9.9.9')
        self.endpoint.refresh_from_db()
        self.endpoint.save()
        response = self.client.post(self.url, expected, format='json', **self.header)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertNotIn('resolve-secret-canary', response.content.decode())

    def test_disabled_endpoint_returns_no_material(self):
        self.endpoint.options = {'enabled': False}
        self.endpoint.save()
        response = self.client.post(self.url, self._expected(), format='json', **self.header)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.data['mismatch'], 'enabled')

    def test_wrong_target_or_credential_identity_returns_no_material(self):
        for override in ({'object_id': self.device.pk + 1000}, {'credential_type': 'ssh-keypair'}):
            response = self.client.post(self.url, self._expected(**override), format='json', **self.header)
            self.assertEqual(response.status_code, 409, response.content)
            self.assertNotIn('resolve-secret-canary', response.content.decode())
