"""HTTP shape, transport and failure behavior of the narrow provider action."""

from unittest.mock import patch

from core.models import ObjectType
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient
from users.models import ObjectPermission

from netbox_openbao.automation import AutomationResolutionDenied
from netbox_openbao.models import Credential

from .test_automation import CANARY, _AutomationFixture


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class AutomationProviderAPITest(_AutomationFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.executor)
        permission = ObjectPermission.objects.create(name='executor metadata', actions=['view'])
        permission.object_types.add(ObjectType.objects.get_for_model(Credential))
        permission.users.add(self.executor)
        self.url = reverse('plugins-api:netbox_openbao-api:credential-resolve-automation')

    def test_secure_success_is_json_only_and_unstorable(self):
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority):
            response = self.client.post(self.url, self.params, format='json', secure=True)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['fields'], {'password': CANARY})
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(response['Content-Type'], 'application/json')

    def test_insecure_transport_cannot_reach_provider(self):
        with patch('netbox_openbao.automation.resolve_automation') as provider:
            response = self.client.post(self.url, self.params, format='json')
        self.assertEqual(response.status_code, 403)
        provider.assert_not_called()

    def test_identity_and_raw_reference_inputs_are_not_accepted(self):
        with patch('netbox_openbao.automation.resolve_automation') as provider:
            response = self.client.post(self.url, self.params | {'actor_id': 1}, format='json', secure=True)
        self.assertEqual(response.status_code, 400)
        provider.assert_not_called()

    def test_authority_refusal_is_fixed_and_unstorable(self):
        with patch('netbox_openbao.automation.resolve_automation', side_effect=AutomationResolutionDenied()):
            response = self.client.post(self.url, self.params, format='json', secure=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'detail': 'Automation credential resolution was refused.'})
        self.assertIn('no-store', response['Cache-Control'])

    def test_get_never_reveals_material(self):
        with patch('netbox_openbao.automation.resolve_automation') as provider:
            response = self.client.get(self.url, secure=True)
        self.assertEqual(response.status_code, 405)
        provider.assert_not_called()
