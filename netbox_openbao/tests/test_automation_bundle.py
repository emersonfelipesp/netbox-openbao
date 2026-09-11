"""Payload boundary tests complement the real-backend composed proofs."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.services import read_automation_bundle


class AutomationBundleBoundaryTest(SimpleTestCase):
    def setUp(self):
        self.credential = SimpleNamespace(engine=object(), policy=SimpleNamespace(max_reveal_ttl=120),
                                          path='test', credential_type='password')

    def read(self, payload, fields):
        backend = SimpleNamespace(read=Mock(return_value=payload))
        with patch('netbox_openbao.services.get_backend', return_value=backend), \
                patch('netbox_openbao.services.get_config', return_value=300):
            result = read_automation_bundle(self.credential, version=7, fields=fields)
        backend.read.assert_called_once_with('test', version=7)
        return result

    def test_missing_optional_field_is_omitted_and_policy_limits_ttl(self):
        fields = {'password': {'required': True}, 'passphrase': {'required': False}}
        self.assertEqual(self.read({'password': 'transient-value', 'unrequested': 'omit'}, fields),
                         ({'password': 'transient-value'}, 120))

    def test_missing_required_field_and_non_object_payload_are_refused(self):
        for payload in (None, [], {}, {'unrequested': 'omit'}):
            with self.subTest(payload_type=type(payload).__name__), self.assertRaises(OpenBaoError):
                self.read(payload, {'password': {'required': True}})

    def test_non_string_and_oversized_values_are_refused(self):
        for value in (None, False, 7, [], {}, 'a' * 262145):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(OpenBaoError):
                self.read({'password': value}, {'password': {'required': True}})
