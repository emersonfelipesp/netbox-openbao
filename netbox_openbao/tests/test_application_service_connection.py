"""Connection resolution, resolver view and assignment reveal on Application Services.

`ServiceEndpoint` is gone: the host is the Application Service's single IP and
the port its single TCP port mapping. Anything else fails closed.
"""

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from ipam.models import IPAddress, Service

from netbox_openbao import connection
from netbox_openbao.choices import CredentialTypeChoices, PurposeChoices
from netbox_openbao.models import Credential, CredentialAssignment
from netbox_openbao.services import write_material

from .test_api import OpenBaoAPITestCase


def make_device():
    site = Site.objects.create(name='Conn Site', slug='conn-site')
    manufacturer = Manufacturer.objects.create(name='Conn Mfr', slug='conn-mfr')
    device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Conn', slug='conn')
    role = DeviceRole.objects.create(name='Conn Role', slug='conn-role')
    return Device.objects.create(name='conn-dev', site=site, device_type=device_type, role=role)


def make_service(device, ports=('tcp/22',), ips=('192.0.2.10/24',), name='SSH'):
    service = Service(
        parent_object_type=ContentType.objects.get_for_model(device),
        parent_object_id=device.pk,
        name=name,
        port_mappings=list(ports),
    )
    service.save()
    service.ipaddresses.set([IPAddress.objects.create(address=ip) for ip in ips])
    return service


class ServiceConnectionTest(TestCase):

    def setUp(self):
        self.device = make_device()

    def test_single_ip_and_tcp_port_resolve(self):
        result = connection.service_connection(make_service(self.device))
        self.assertTrue(result.usable)
        self.assertEqual((result.host, result.port), ('192.0.2.10', 22))

    def test_no_ip_fails_closed(self):
        result = connection.service_connection(make_service(self.device, ips=()))
        self.assertEqual(result.error, connection.ERROR_NO_IP)
        self.assertFalse(result.usable)
        self.assertTrue(result.message)

    def test_multiple_ips_fail_closed(self):
        result = connection.service_connection(
            make_service(self.device, ips=('192.0.2.10/24', '192.0.2.11/24'))
        )
        self.assertEqual(result.error, connection.ERROR_MULTIPLE_IPS)

    def test_no_tcp_port_fails_closed(self):
        result = connection.service_connection(make_service(self.device, ports=('udp/22',)))
        self.assertEqual(result.error, connection.ERROR_NO_TCP_PORT)

    def test_multiple_tcp_ports_fail_closed(self):
        result = connection.service_connection(make_service(self.device, ports=('tcp/22', 'tcp/2222')))
        self.assertEqual(result.error, connection.ERROR_MULTIPLE_TCP_PORTS)

    def test_overlapping_addresses_in_different_vrfs_are_ambiguous(self):
        from ipam.models import VRF

        vrf = VRF.objects.create(name='other')
        service = make_service(self.device)
        service.ipaddresses.add(IPAddress.objects.create(address='192.0.2.10/24', vrf=vrf))
        self.assertEqual(connection.service_connection(service).error, connection.ERROR_MULTIPLE_IPS)

    def test_udp_ports_are_ignored_when_one_tcp_port_exists(self):
        result = connection.service_connection(make_service(self.device, ports=('tcp/22', 'udp/53')))
        self.assertEqual(result.port, 22)


class AssignmentResolveAndRevealTest(OpenBaoAPITestCase):

    def setUp(self):
        super().setUp()
        self.device = make_device()
        self.service = make_service(self.device)
        self.credential = Credential(
            name='dev-ssh', credential_type=CredentialTypeChoices.TYPE_SSH_PASSWORD,
            policy=self.policy, engine=self.engine, username='root',
        )
        write_material(self.credential, {'password': 'hunter2'})
        self.assignment = CredentialAssignment.objects.create(
            credential=self.credential,
            assigned_object_type=ContentType.objects.get_for_model(Service),
            assigned_object_id=self.service.pk,
            purpose=PurposeChoices.PURPOSE_LOGIN,
            ssh_known_hosts_entry='192.0.2.10 ssh-ed25519 AAAA',
        )

    def grant(self, *extra):
        self.add_permissions(
            'netbox_openbao.view_credential', 'netbox_openbao.view_credentialassignment',
            'dcim.view_device', 'ipam.view_service', 'ipam.view_ipaddress', *extra,
        )

    def resolve(self):
        return self.client.get(
            reverse('plugins-api:netbox_openbao-api:resolve'),
            {'object_type': 'dcim.device', 'object_id': self.device.pk}, **self.header,
        )

    def reveal_body(self, **overrides):
        body = {
            'reason': 'test',
            'assignment_revision': self.assignment.last_updated.isoformat(),
            'object_type': 'ipam.service',
            'object_id': self.service.pk,
            'purpose': self.assignment.purpose,
            'credential_uuid': str(self.credential.uuid),
            'credential_type': self.credential.credential_type,
            'kv_version': self.credential.kv_version,
            'host': '192.0.2.10',
            'port': 22,
        }
        body.update(overrides)
        return body

    def reveal(self, **overrides):
        url = reverse(
            'plugins-api:netbox_openbao-api:credentialassignment-reveal-credential',
            kwargs={'pk': self.assignment.pk},
        )
        return self.client.post(url, self.reveal_body(**overrides), format='json', **self.header)

    def test_resolve_lists_service_with_host_port_and_pin(self):
        self.grant()
        response = self.resolve()
        self.assertEqual(response.status_code, 200, response.content)
        service = response.data['services'][0]
        self.assertEqual((service['host'], service['port'], service['error']), ('192.0.2.10', 22, ''))
        self.assertEqual(service['assignments'][0]['ssh_known_hosts_entry'], '192.0.2.10 ssh-ed25519 AAAA')
        self.assertNotIn('hunter2', response.content.decode())

    def test_resolve_reports_unusable_service(self):
        self.service.ipaddresses.clear()
        self.grant()
        service = self.resolve().data['services'][0]
        self.assertEqual(service['error'], connection.ERROR_NO_IP)
        self.assertEqual(service['host'], '')

    def test_reveal_returns_material_when_assignment_matches(self):
        self.grant('netbox_openbao.reveal_credential')
        response = self.reveal()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data['secret_data']['password'], 'hunter2')
        self.assertIn('no-store', response['Cache-Control'])

    def test_reveal_conflicts_when_host_changed(self):
        self.grant('netbox_openbao.reveal_credential')
        response = self.reveal(host='192.0.2.99')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['mismatch'], 'host')
        self.assertNotIn('hunter2', response.content.decode())

    def test_reveal_requires_host_and_port_for_a_service(self):
        self.grant('netbox_openbao.reveal_credential')
        body = self.reveal_body()
        del body['host'], body['port']
        url = reverse(
            'plugins-api:netbox_openbao-api:credentialassignment-reveal-credential',
            kwargs={'pk': self.assignment.pk},
        )
        response = self.client.post(url, body, format='json', **self.header)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn('hunter2', response.content.decode())

    def test_permission_revoked_during_the_backend_read_withholds_material(self):
        from unittest.mock import patch

        from users.models import ObjectPermission

        self.grant('netbox_openbao.reveal_credential')
        real = __import__('netbox_openbao.api.views', fromlist=['reveal_material']).reveal_material

        def revoke_then_read(*args, **kwargs):
            ObjectPermission.objects.filter(actions__contains=['reveal']).delete()
            return real(*args, **kwargs)

        with patch('netbox_openbao.api.views.reveal_material', side_effect=revoke_then_read):
            response = self.reveal()
        self.assertEqual(response.status_code, 403, response.content)
        self.assertNotIn('hunter2', response.content.decode())

    def test_reveal_conflicts_when_assignment_disabled(self):
        self.grant('netbox_openbao.reveal_credential')
        CredentialAssignment.objects.filter(pk=self.assignment.pk).update(enabled=False)
        self.assertEqual(self.reveal().status_code, 409)

    def test_reveal_requires_reveal_permission(self):
        self.grant()
        # Hidden like the credential endpoint: no reveal permission, no confirmation it exists.
        self.assertIn(self.reveal().status_code, (403, 404))

    def test_service_endpoint_api_is_gone(self):
        self.grant()
        response = self.client.get('/api/plugins/openbao/service-endpoints/', **self.header)
        self.assertEqual(response.status_code, 404)
