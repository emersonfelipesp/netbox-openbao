"""Fail-closed boundaries identified by the independent first review."""

import sys
from copy import copy
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from django.test import TransactionTestCase, override_settings
from users.models import ObjectPermission

from netbox_openbao.api.automation import AutomationResolveRequestSerializer
from netbox_openbao.automation import (
    AutomationResolutionDenied,
    _deliver,
    _reserve,
    capture_reference_identity,
    resolve_automation,
)
from netbox_openbao.models import CredentialAccessLog, SecretEngine
from netbox_openbao.services import write_material

from .fakes import FakeBackend
from .test_automation import CANARY, _AutomationFixture


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class AutomationSafetyBoundaryTest(_AutomationFixture, TransactionTestCase):
    def test_rpc_final_permission_error_is_fixed_and_blocks_material(self):
        self.permission_recheck_patch.stop()
        with patch('netbox_rpc.credential_authority.check_authorization_permissions', side_effect=RuntimeError(CANARY)):
            self.assert_denied_before_read()

    def test_provider_permission_revocation_during_read_prevents_disclosure(self):
        from netbox_openbao.services import read_automation_bundle

        def waited_read(*args, **kwargs):
            result = read_automation_bundle(*args, **kwargs)
            ObjectPermission.objects.filter(name='Credential').update(constraints={'pk': -1})
            return result

        with patch('netbox_openbao.services.read_automation_bundle', side_effect=waited_read), \
                self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.assertFalse(CredentialAccessLog.objects.filter(execution_id=91, success=True).exists())

    def test_live_version_change_during_read_cannot_deliver_the_old_bundle(self):
        from netbox_openbao.services import read_automation_bundle

        def changed_version(*args, **kwargs):
            result = read_automation_bundle(*args, **kwargs)
            type(self.credential).objects.filter(pk=self.credential.pk).update(live_kv_version=2)
            return result

        with patch('netbox_openbao.services.read_automation_bundle', side_effect=changed_version), \
                self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 1)

    def test_expiry_during_backend_read_prevents_delivery(self):
        receipt = _reserve(self.authority)
        from netbox_openbao.services import read_automation_bundle

        clock = patch('netbox_rpc.credential_authority.timezone.now',
                      return_value=self.authority.expires_at + timedelta(seconds=1))

        def delayed_read(*args, **kwargs):
            result = read_automation_bundle(*args, **kwargs)
            clock.start()
            return result

        try:
            with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority), \
                    patch('netbox_openbao.services.read_automation_bundle', side_effect=delayed_read), \
                    self.assertRaises(AutomationResolutionDenied):
                _deliver(self.request, self.params, receipt)
        finally:
            clock.stop()
        self.assertFalse(CredentialAccessLog.objects.filter(execution_id=91, success=True).exists())

    def test_authority_target_object_must_match_the_frozen_target(self):
        wrong_target = copy(self.target)
        wrong_target.pk += 1000
        self.authority = replace(self.authority, target_object=wrong_target)
        self.assert_denied_before_read()

    def test_absent_rpc_is_sanitized_and_audited_without_inventing_actor(self):
        with patch.dict(sys.modules, {'netbox_rpc.credential_authority': None}), \
                self.assertRaises(AutomationResolutionDenied) as caught:
            resolve_automation(self.request, self.params)
        self.assertEqual(str(caught.exception), 'Automation credential resolution was refused.')
        audit = CredentialAccessLog.objects.get(execution_id=91)
        self.assertIsNone(audit.user_id)
        self.assertEqual(audit.executor_id, self.executor.pk)

    def test_assignable_model_denial_precedes_read(self):
        with patch('netbox_openbao.automation.assignable_model_labels', return_value=[]):
            self.assert_denied_before_read()

    def test_target_view_permission_is_rechecked(self):
        permission = ObjectPermission.objects.get(name='Device')
        permission.constraints = {'pk': self.target.pk + 100}
        permission.save()
        self.assert_denied_before_read()

    def test_required_reason_is_rechecked(self):
        self.policy.require_reason = True
        self.policy.save()
        self.authority = replace(self.authority, reason='')
        self.assert_denied_before_read()

    def test_policy_engine_mismatch_is_refused(self):
        other = SecretEngine.objects.create(name='Other', slug='other', api_url='https://other.invalid')
        type(self.policy).objects.filter(pk=self.policy.pk).update(engine=other)
        self.assert_denied_before_read()

    def test_admission_exception_is_fixed_and_value_free(self):
        with patch('netbox_openbao.automation._resolve_metadata', side_effect=ValueError(CANARY)), \
                self.assertRaises(AutomationResolutionDenied) as caught:
            capture_reference_identity(reference=self.authority.reference, initiating_actor=self.actor,
                                       target_object=self.target, reason=self.authority.reason)
        self.assertNotIn(CANARY, str(caught.exception))

    def test_rotation_between_reservation_and_delivery_is_refused(self):
        receipt = _reserve(self.authority)
        write_material(self.credential, {'password': 'new-transient-version'}, cas=1)
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority), \
                patch.object(FakeBackend, 'read', autospec=True) as read, self.assertRaises(AutomationResolutionDenied):
            _deliver(self.request, self.params, receipt)
        read.assert_not_called()

    def test_oversized_request_is_refused(self):
        request = self.params | {'dispatch_lease': {'padding': 'a' * 17000}}
        self.assertFalse(AutomationResolveRequestSerializer(data=request).is_valid())
