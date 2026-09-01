"""
Quick-add SSH.

Three objects created in one transaction, against NetBox 4.7's reshaped
`ipam.Service`. The rollback case matters as much as the happy path: a partial
result here would leave a service with no credential, or a credential with no
material.
"""

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.test import override_settings
from django.urls import reverse
from ipam.models import Service
from utilities.testing.views import ModelViewTestCase
from virtualization.models import Cluster, ClusterType, VirtualMachine

from netbox_openbao import backends
from netbox_openbao.backends.exceptions import OpenBaoConflict
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAssignment, CredentialPolicy, SecretEngine
from netbox_openbao.quickadd import quick_add_ssh
from netbox_openbao.secrets.generators import generate_ssh_keypair

from .fakes import FakeBackend


class _QuickAddBase(ModelViewTestCase):
    model = Credential

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

        site = Site.objects.create(name='S', slug='s')
        manufacturer = Manufacturer.objects.create(name='M', slug='m')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='T', slug='t')
        role = DeviceRole.objects.create(name='R', slug='r')
        self.device = Device.objects.create(
            name='core-sw-01', site=site, device_type=device_type, role=role,
        )

        cluster_type = ClusterType.objects.create(name='CT', slug='ct')
        cluster = Cluster.objects.create(name='C', type=cluster_type)
        self.vm = VirtualMachine.objects.create(name='vm-01', cluster=cluster)


class QuickAddServiceTest(_QuickAddBase):
    """
    The created service is asserted in whichever shape the running NetBox uses.

    4.7 represents ports as a `port_mappings` array of `"tcp/22"` strings; 4.6
    uses `protocol` plus a `ports` list. The generic-FK parent is common to
    both, contrary to what this docstring claimed before.

    `_assert_tcp_ports` reads the shape rather than the version so the suite
    checks the branch that actually ran. Asserting only 4.7's shape made these
    tests error on 4.6 while the code under test was working correctly — the
    test was the thing that was version-specific.
    """

    def _assert_tcp_ports(self, service, ports):
        """Assert `service` exposes exactly `ports` over TCP, either shape."""
        from netbox_openbao.quickadd import _service_uses_port_mappings

        if _service_uses_port_mappings():
            self.assertEqual(sorted(service.port_mappings),
                             sorted(f'tcp/{p}' for p in ports))
            return

        from ipam.choices import ServiceProtocolChoices

        self.assertEqual(service.protocol, ServiceProtocolChoices.PROTOCOL_TCP)
        self.assertEqual(sorted(service.ports), sorted(ports))

    def test_creates_a_wellformed_service(self):
        _credential, service, _pub = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )

        self.assertIsNotNone(service)
        self.assertEqual(service.name, 'ssh')
        self._assert_tcp_ports(service, [22])
        self.assertEqual(service.parent, self.device)
        self.assertEqual(
            service.parent_object_type, ContentType.objects.get_for_model(Device)
        )

    def test_reuses_an_existing_service(self):
        quick_add_ssh(self.device, self.policy, username='admin', generate=True)
        quick_add_ssh(self.device, self.policy, username='root', generate=True, name='second')

        self.assertEqual(Service.objects.filter(name='ssh').count(), 1)

    def test_a_nonstandard_port_is_added_to_the_existing_service(self):
        quick_add_ssh(self.device, self.policy, username='admin', generate=True)
        _c, service, _p = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True, port=2222, name='alt',
        )

        self._assert_tcp_ports(service, [22, 2222])

    def test_works_on_a_virtual_machine(self):
        _credential, service, _pub = quick_add_ssh(
            self.vm, self.policy, username='admin', generate=True,
        )
        self.assertEqual(service.parent, self.vm)

    def test_password_auth_stores_openbao_ssh_password(self):
        credential, service, public_key = quick_add_ssh(
            self.device,
            self.policy,
            username='root',
            password='login-secret',
            auth_method='password',
        )
        self.assertEqual(credential.credential_type, CredentialTypeChoices.TYPE_SSH_PASSWORD)
        self.assertEqual(credential.username, 'root')
        self.assertEqual(public_key, '')
        self.assertIsNotNone(service)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'assignable_models': ['dcim.device']}})
    def test_service_creation_is_skipped_when_services_are_not_assignable(self):
        """
        An estate that does not model services still wants the credential on
        the device, so this is configured-out rather than an error.
        """
        credential, service, _pub = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )

        self.assertIsNone(service)
        self.assertEqual(Service.objects.count(), 0)
        self.assertTrue(
            CredentialAssignment.objects.filter(credential=credential).exists()
        )


class QuickAddMaterialTest(_QuickAddBase):

    def test_generate_writes_the_private_half_and_returns_only_the_public(self):
        credential, _service, public_key = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )

        self.assertTrue(public_key.startswith('ssh-ed25519 '))
        self.assertEqual(credential.public_key.split()[1], public_key.split()[1])
        # The private half is in OpenBao and nowhere else.
        self.assertIn('private_key', FakeBackend.store[credential.path][0])
        self.assertNotIn('PRIVATE KEY', public_key)

    def test_paste_stores_the_supplied_key(self):
        pair = generate_ssh_keypair('ed25519')
        credential, _service, public_key = quick_add_ssh(
            self.device, self.policy, username='admin', private_key=pair['private_key'],
        )

        self.assertEqual(public_key, '', 'Only a generated key is handed back.')
        self.assertEqual(
            FakeBackend.store[credential.path][0]['private_key'], pair['private_key']
        )
        self.assertTrue(credential.fingerprint.startswith('SHA256:'))

    def test_reuse_creates_no_new_credential(self):
        first, _service, _pub = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )
        second, _service, _pub = quick_add_ssh(
            self.vm, self.policy, username='admin', existing_credential=first,
        )

        self.assertEqual(second.pk, first.pk)
        self.assertEqual(Credential.objects.count(), 1)
        # ...but it is now assigned to the VM as well.
        self.assertTrue(
            CredentialAssignment.objects.filter(
                credential=first,
                assigned_object_type=ContentType.objects.get_for_model(VirtualMachine),
                assigned_object_id=self.vm.pk,
            ).exists()
        )

    def test_exactly_one_source_is_required(self):
        with self.assertRaises(ValidationError):
            quick_add_ssh(self.device, self.policy, username='admin')
        with self.assertRaises(ValidationError):
            quick_add_ssh(
                self.device, self.policy, username='admin',
                generate=True, private_key='x',
            )

    def test_generation_honours_the_configured_default_key_type(self):
        """
        Passing key_type=None must not defeat the configured default: an
        explicit None overrides a function default, so the fallback has to be
        deliberate.
        """
        credential, _s, _p = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True, key_type=None,
        )
        self.assertEqual(credential.key_type, 'ed25519')

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'default_ssh_key_type': 'ecdsa-p256'}})
    def test_configured_default_key_type_is_used(self):
        credential, _s, _p = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )
        self.assertTrue(credential.key_type.startswith('ecdsa'))

    def test_credential_type_is_an_ssh_keypair(self):
        credential, _s, _p = quick_add_ssh(
            self.device, self.policy, username='admin', generate=True,
        )
        self.assertEqual(credential.credential_type, CredentialTypeChoices.TYPE_SSH_KEYPAIR)


class QuickAddRollbackTest(_QuickAddBase):

    def test_a_backend_failure_leaves_nothing_behind(self):
        """
        The reason this goes through store_credential rather than writing
        directly: a partial result would leave a service with no credential, or
        a credential whose path resolves to nothing.
        """
        FakeBackend.fail_on_write = True

        # Specifically the backend's own error, so this cannot pass because of
        # some unrelated failure earlier in the call.
        with self.assertRaises(OpenBaoConflict):
            quick_add_ssh(self.device, self.policy, username='admin', generate=True)

        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(CredentialAssignment.objects.count(), 0)
        self.assertEqual(Service.objects.count(), 0)


class QuickAddViewTest(_QuickAddBase):

    def url(self, obj):
        return reverse('plugins:netbox_openbao:quickadd_ssh', kwargs={
            'app_label': obj._meta.app_label,
            'model_name': obj._meta.model_name,
            'pk': obj.pk,
        })

    def grant(self):
        self.add_permissions(
            'netbox_openbao.add_credential', 'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy', 'netbox_openbao.view_secretengine',
            'netbox_openbao.add_credentialassignment',
            'dcim.view_device', 'ipam.add_service', 'ipam.view_service',
        )

    def test_requires_permission_to_add_credentials(self):
        self.add_permissions('dcim.view_device')
        response = self.client.get(self.url(self.device))
        self.assertIn(response.status_code, (403, 302))

    def test_form_renders(self):
        self.grant()
        response = self.client.get(self.url(self.device))
        self.assertEqual(response.status_code, 200)

    def test_generating_shows_the_public_key_once(self):
        self.grant()
        response = self.client.post(self.url(self.device), data={
            'username': 'admin',
            'policy': self.policy.pk,
            'source': 'generate',
            'key_type': 'ed25519',
            'port': 22,
            'create_service': 'on',
        })

        self.assertEqual(response.status_code, 200, response.content[:400])
        self.assertIn(b'ssh-ed25519 ', response.content)
        # The private half must never render.
        self.assertNotIn(b'PRIVATE KEY', response.content)

    def test_unassignable_target_is_a_404(self):
        """The allowlist is enforced here too, not only on the assignment."""
        self.grant()
        response = self.client.get(reverse('plugins:netbox_openbao:quickadd_ssh', kwargs={
            'app_label': 'dcim', 'model_name': 'site', 'pk': 1,
        }))
        self.assertEqual(response.status_code, 404)
