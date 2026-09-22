"""
REST API behaviour, with the permission layers as the focus.

The reveal endpoint is the plugin's only route to secret material, so its
authorization is tested from the outside — through real HTTP with real
ObjectPermissions — rather than by asserting on internals.
"""

from unittest.mock import patch

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.urls import reverse
from users.models import ObjectPermission
from utilities.testing import APITestCase

from netbox_openbao import backends
from netbox_openbao.backends.exceptions import OpenBaoMutationUnknown
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.config import clear_config
from netbox_openbao.models import (
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    SecretEngine,
)
from netbox_openbao.services import write_material

from .base import MaterialTransactionTestMixin
from .fakes import FakeBackend


class OpenBaoAPITestCase(MaterialTransactionTestMixin, APITestCase):

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

    def test_create_can_generate_an_ssh_key_without_returning_private_material(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            {
                'name': 'generated-key',
                'credential_type': CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                'policy': self.policy.pk,
                'username': 'admin',
                'generate_ssh_key': True,
                'ssh_key_type': 'ed25519',
            },
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertNotIn('generate_ssh_key', response.data)
        self.assertNotIn('ssh_key_type', response.data)
        self.assertNotIn('secret_data', response.data)
        self.assertNotIn(b'PRIVATE KEY', response.content)
        created = Credential.objects.get(name='generated-key')
        self.assertTrue(created.public_key.startswith('ssh-ed25519 '))
        self.assertIn('PRIVATE KEY', FakeBackend.store[created.path][0]['private_key'])

    def test_generation_rejects_supplied_material_before_writing(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        writes_before = dict(FakeBackend.store)
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            {
                'name': 'ambiguous-key',
                'credential_type': CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                'policy': self.policy.pk,
                'generate_ssh_key': True,
                'secret_data': {'private_key': 'must-not-be-reflected'},
            },
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b'must-not-be-reflected', response.content)
        self.assertEqual(FakeBackend.store, writes_before)

    def test_bulk_create_can_generate_ssh_keys_without_returning_private_material(self):
        self.add_permissions('netbox_openbao.add_credential', 'netbox_openbao.view_credential')
        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:credential-list'),
            [
                {
                    'name': f'generated-key-{index}',
                    'credential_type': CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                    'policy': self.policy.pk,
                    'username': 'admin',
                    'generate_ssh_key': True,
                    'ssh_key_type': 'ed25519',
                }
                for index in range(2)
            ],
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(len(response.data), 2)
        self.assertNotIn(b'PRIVATE KEY', response.content)
        for credential in Credential.objects.filter(name__startswith='generated-key-'):
            self.assertTrue(credential.public_key.startswith('ssh-ed25519 '))
            self.assertIn('PRIVATE KEY', FakeBackend.store[credential.path][0]['private_key'])


class QuickAddSSHAPITest(OpenBaoAPITestCase):

    def setUp(self):
        super().setUp()
        site = Site.objects.create(name='API Site', slug='api-site')
        manufacturer = Manufacturer.objects.create(name='API Manufacturer', slug='api-manufacturer')
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer, model='API Device', slug='api-device',
        )
        role = DeviceRole.objects.create(name='API Role', slug='api-role')
        self.device = Device.objects.create(
            name='api-switch', site=site, device_type=device_type, role=role,
        )
        self.device_type = ContentType.objects.get_for_model(Device)
        self.url = reverse('plugins-api:netbox_openbao-api:credential-quick-add-ssh')

    def grant(self):
        self.add_permissions(
            'netbox_openbao.add_credential',
            'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy',
            'dcim.view_device',
        )

    def payload(self, **overrides):
        data = {
            'target_type': self.device_type.pk,
            'target_id': self.device.pk,
            'username': 'admin',
            'policy': self.policy.pk,
            'auth_method': 'keypair',
            'source': 'generated',
            'key_type': 'ed25519',
        }
        data.update(overrides)
        return data

    def test_requires_add_credential_permission(self):
        self.add_permissions('dcim.view_device', 'netbox_openbao.view_credentialpolicy')
        response = self.client.post(self.url, self.payload(), format='json', **self.header)
        self.assertIn(response.status_code, (403, 404))

    def test_target_type_uses_the_documented_numeric_content_type_id(self):
        self.grant()
        by_id = self.client.post(self.url, self.payload(), format='json', **self.header)
        self.assertEqual(by_id.status_code, 201, by_id.content)

        by_label = self.client.post(
            self.url, self.payload(target_type='dcim.device', name='label-target'),
            format='json', **self.header,
        )
        self.assertEqual(by_label.status_code, 400, by_label.content)
        self.assertIn('target_type', by_label.data)

        site_type = ContentType.objects.get_for_model(Site)
        unassignable = self.client.post(
            self.url, self.payload(target_type=site_type.pk, name='site-target'),
            format='json', **self.header,
        )
        self.assertEqual(unassignable.status_code, 400, unassignable.content)
        self.assertIn('target_type', unassignable.data)

    def test_constrained_add_permission_rolls_back_out_of_scope_quick_add(self):
        self.add_permissions(
            'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy',
            'dcim.view_device',
        )
        permission = ObjectPermission(
            name='production-only-credential-add',
            actions=['add'],
            constraints={'policy__slug': 'production'},
        )
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(*_credential_object_types())
        credentials_before = Credential.objects.count()
        assignments_before = CredentialAssignment.objects.count()
        writes_before = dict(FakeBackend.store)

        response = self.client.post(self.url, self.payload(), format='json', **self.header)

        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(Credential.objects.count(), credentials_before)
        self.assertEqual(CredentialAssignment.objects.count(), assignments_before)
        self.assertEqual(FakeBackend.store, writes_before)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'assignable_models_deny': ['dcim.device']}})
    def test_live_assignable_model_deny_rejects_target_before_mutation(self):
        self.grant()
        clear_config()
        self.addCleanup(clear_config)
        credentials_before = Credential.objects.count()
        writes_before = dict(FakeBackend.store)

        response = self.client.post(self.url, self.payload(), format='json', **self.header)

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(Credential.objects.count(), credentials_before)
        self.assertEqual(FakeBackend.store, writes_before)

    def test_generated_key_response_is_bounded_and_private_key_stays_in_openbao(self):
        self.grant()
        response = self.client.post(self.url, self.payload(), format='json', **self.header)

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(set(response.data), {
            'credential_id', 'credential_uuid', 'credential_type', 'public_key', 'fingerprint',
            'key_type', 'service_id', 'assignment_ids', 'target_type', 'target_id',
        })
        self.assertTrue(response.data['public_key'].startswith('ssh-ed25519 '))
        self.assertNotIn(b'PRIVATE KEY', response.content)
        credential = Credential.objects.get(pk=response.data['credential_id'])
        self.assertIn('PRIVATE KEY', FakeBackend.store[credential.path][0]['private_key'])
        self.assertEqual(CredentialAssignment.objects.filter(credential=credential).count(), 2)
        self.assertIn('no-store', response['Cache-Control'])

    def test_generated_key_null_key_type_uses_the_configured_default(self):
        self.grant()
        response = self.client.post(
            self.url,
            self.payload(key_type=None, name='generated-default'),
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data['key_type'], 'ed25519')

    def test_provided_and_existing_key_sources_are_supported(self):
        self.grant()
        from netbox_openbao.secrets.generators import generate_ssh_keypair

        private_key = generate_ssh_keypair('ed25519')['private_key']
        provided = self.client.post(
            self.url,
            self.payload(source='provided', key_type=None, private_key=private_key, name='provided'),
            format='json',
            **self.header,
        )
        self.assertEqual(provided.status_code, 201, provided.content)
        self.assertTrue(provided.data['public_key'].startswith('ssh-ed25519 '))
        existing_id = provided.data['credential_id']

        reused = self.client.post(
            self.url,
            self.payload(
                source='existing', key_type=None, existing_credential=existing_id, name='ignored',
            ),
            format='json',
            **self.header,
        )
        self.assertEqual(reused.status_code, 201, reused.content)
        self.assertEqual(reused.data['credential_id'], existing_id)
        self.assertEqual(reused.data['public_key'], provided.data['public_key'])

    def test_reused_credential_requires_its_own_policy(self):
        self.grant()
        from netbox_openbao.secrets.generators import generate_ssh_keypair

        private_key = generate_ssh_keypair('ed25519')['private_key']
        provided = self.client.post(
            self.url,
            self.payload(source='provided', key_type=None, private_key=private_key, name='shared-policy'),
            format='json',
            **self.header,
        )
        self.assertEqual(provided.status_code, 201, provided.content)
        other_policy = CredentialPolicy.objects.create(
            name='Production', slug='production', engine=self.engine, openbao_policy='netbox-production',
        )
        assignments_before = CredentialAssignment.objects.count()

        response = self.client.post(
            self.url,
            self.payload(
                policy=other_policy.pk,
                source='existing',
                key_type=None,
                existing_credential=provided.data['credential_id'],
            ),
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn('policy', response.data)
        self.assertEqual(CredentialAssignment.objects.count(), assignments_before)

    def test_reused_credential_response_excludes_unrelated_assignments(self):
        self.grant()
        from netbox_openbao.secrets.generators import generate_ssh_keypair

        private_key = generate_ssh_keypair('ed25519')['private_key']
        provided = self.client.post(
            self.url,
            self.payload(source='provided', key_type=None, private_key=private_key, name='shared'),
            format='json',
            **self.header,
        )
        self.assertEqual(provided.status_code, 201, provided.content)
        credential = Credential.objects.get(pk=provided.data['credential_id'])
        other_device = Device.objects.create(
            name='unrelated-switch',
            site=self.device.site,
            device_type=self.device.device_type,
            role=self.device.role,
        )
        unrelated = CredentialAssignment.objects.create(
            credential=credential,
            assigned_object_type=ContentType.objects.get_for_model(other_device),
            assigned_object_id=other_device.pk,
        )

        reused = self.client.post(
            self.url,
            self.payload(source='existing', key_type=None, existing_credential=credential.pk),
            format='json',
            **self.header,
        )
        self.assertEqual(reused.status_code, 201, reused.content)
        self.assertNotIn(unrelated.pk, reused.data['assignment_ids'])

    @patch('netbox_openbao.quickadd.sync_ssh_password_to_nms')
    def test_password_auth_syncs_without_reflecting_the_password(self, sync_password):
        self.grant()
        response = self.client.post(
            self.url,
            self.payload(
                auth_method='password', source=None, key_type=None, password='api-login-canary',
            ),
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertNotIn(b'api-login-canary', response.content)
        sync_password.assert_called_once()
        credential = Credential.objects.get(pk=response.data['credential_id'])
        self.assertEqual(FakeBackend.store[credential.path][0], {'password': 'api-login-canary'})

    def test_incompatible_inputs_are_rejected_before_mutation(self):
        self.grant()
        credential_count = Credential.objects.count()
        response = self.client.post(
            self.url,
            self.payload(password='must-not-be-reflected'),
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b'must-not-be-reflected', response.content)
        self.assertEqual(Credential.objects.count(), credential_count)

    def test_non_device_or_vm_target_is_rejected(self):
        self.grant()
        site_type = ContentType.objects.get_for_model(Site)
        response = self.client.post(
            self.url,
            self.payload(target_type=site_type.pk, target_id=self.device.site_id),
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 400)

    def test_backend_failure_compensates_metadata_and_returns_sanitized_error(self):
        self.grant()
        FakeBackend.fail_on_write = True
        credential_count = Credential.objects.count()
        response = self.client.post(
            self.url,
            self.payload(name='backend-error-canary'),
            format='json',
            **self.header,
        )
        self.assertEqual(response.status_code, 502, response.content)
        self.assertEqual(response.data, {'detail': 'SSH access could not be added.'})
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(Credential.objects.count(), credential_count)
        self.assertFalse(CredentialAssignment.objects.filter(credential__name='backend-error-canary').exists())

    def test_unknown_backend_outcome_is_explicit_and_not_retry_safe(self):
        self.grant()
        credential_count = Credential.objects.count()
        with patch.object(FakeBackend, 'write', side_effect=OpenBaoMutationUnknown()):
            response = self.client.post(
                self.url,
                self.payload(name='unknown-outcome-canary'),
                format='json',
                **self.header,
            )

        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.data['outcome'], 'unknown')
        self.assertIn('Do not retry', response.data['message'])
        self.assertEqual(response['X-OpenBao-Operation-Outcome'], 'unknown')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(Credential.objects.count(), credential_count)
        self.assertFalse(CredentialAssignment.objects.filter(credential__name='unknown-outcome-canary').exists())


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
