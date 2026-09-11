"""Provider authorization and durability tests on the actual NetBox database.

RPC signature/ledger validation has its own suite. These tests supply the
authority result at that boundary and exercise real permission restrictions,
assignment rows, transactions, receipts and audits beneath it.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

from core.models import ObjectType
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from netbox_rpc.credential_authority import SecretResolutionAuthorization
from netbox_rpc.credential_contract import CredentialReferenceV1
from psycopg import sql
from users.models import Group, ObjectPermission

from netbox_openbao import backends
from netbox_openbao.api.automation import AutomationResolveRequestSerializer
from netbox_openbao.automation import AutomationResolutionDenied, capture_reference_identity, resolve_automation
from netbox_openbao.backends.exceptions import OpenBaoUnavailable
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.models import (
    AutomationResolutionReceipt,
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    SecretEngine,
)
from netbox_openbao.services import stage_material, write_material

from .fakes import FakeBackend

CANARY = 'openbao-provider-canary-do-not-persist'


class _AutomationFixture:
    """Shared real-database authorization fixture with selectable backend."""

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))
        # Provider-only cases substitute the RPC boundary. Every signed or
        # protected composed case explicitly stops this patch before admission.
        self.permission_recheck_patch = patch('netbox_openbao.automation._check_rpc_permissions')
        self.permission_recheck_patch.start()
        self.addCleanup(self.permission_recheck_patch.stop)
        user_model = get_user_model()
        self.actor = user_model.objects.create_user(username='initiator')
        self.executor = user_model.objects.create_user(username='executor')
        self.request = SimpleNamespace(user=self.executor)
        manufacturer = Manufacturer.objects.create(name='Provider', slug='provider')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Test', slug='test')
        role = DeviceRole.objects.create(name='Test', slug='test')
        site = Site.objects.create(name='Test', slug='test')
        self.target = Device.objects.create(name='target', device_type=device_type, role=role, site=site)
        self.engine = SecretEngine.objects.create(name='Test', slug='test', api_url='https://bao.invalid:8200')
        self.policy = CredentialPolicy.objects.create(name='Test', slug='test', engine=self.engine)
        self.credential = Credential(name='Credential', credential_type='password', policy=self.policy,
                                     engine=self.engine)
        write_material(self.credential, {'password': CANARY})
        self.assignment = CredentialAssignment.objects.create(
            credential=self.credential, assigned_object_type=ContentType.objects.get_for_model(Device),
            assigned_object_id=self.target.pk, purpose='login',
        )
        for model, actions in ((Credential, ['view', 'reveal']), (CredentialAssignment, ['view']), (Device, ['view'])):
            permission = ObjectPermission.objects.create(name=model.__name__, actions=actions)
            permission.object_types.add(ObjectType.objects.get_for_model(model))
            permission.users.add(self.actor)
        reference = CredentialReferenceV1.from_mapping({
            'schema_version': 1, 'provider': 'netbox-openbao', 'assignment_id': self.assignment.pk,
            'target': {'object_type': 'dcim.device', 'object_id': self.target.pk}, 'purpose': 'login',
            'fields': ['password'], 'version': {'policy': 'live'},
        })
        self.authority = SecretResolutionAuthorization(
            initiating_actor=self.actor, executor_id=self.executor.pk, execution_id=91, stream_version=3,
            target_object=self.target, reference=reference, reference_name='transport', step_id='',
            dispatch_nonce='unique-dispatch', correlation_id='trace-91', approval_snapshot_hash='approved',
            reason='Approved node maintenance', intent_run_id=None,
            expires_at=timezone.now() + timedelta(minutes=2),
            procedure_id=1, backend_id=1, approved_by_id=None,
            provider_identity=capture_reference_identity(
                reference=reference, initiating_actor=self.actor, target_object=self.target,
                reason='Approved node maintenance',
            ),
        )
        self.params = {'schema_version': 1, 'execution_id': 91, 'step_id': '',
                       'reference_name': 'transport', 'dispatch_lease': {}}

    def resolve(self):
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority):
            return resolve_automation(self.request, self.params)

    def assert_denied_before_read(self):
        with patch.object(FakeBackend, 'read', autospec=True) as read:
            with self.assertRaises(AutomationResolutionDenied):
                self.resolve()
            read.assert_not_called()

    def prepare_ssh_bundle(self):
        material = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.BestAvailableEncryption(CANARY.encode()),
        ).decode()
        self.credential.credential_type = 'ssh-keypair'
        write_material(self.credential, {'private_key': material, 'passphrase': CANARY}, cas=1)
        wire = self.authority.reference.to_mapping()
        wire['fields'] = ['private_key', 'passphrase']
        reference = CredentialReferenceV1.from_mapping(wire)
        self.authority = replace(
            self.authority, reference=reference,
            provider_identity=capture_reference_identity(reference=reference, initiating_actor=self.actor,
                                                        target_object=self.target, reason=self.authority.reason),
        )
        return material

    def issue_real_dispatch(self):
        """Use the installed RPC admission, signer and event ledger unchanged."""
        self.permission_recheck_patch.stop()
        from netbox_rpc import credential_authority, dispatch_lease
        from netbox_rpc.application import command_handlers
        from netbox_rpc.credential_contract import apply_credential_fingerprint, canonical_hash
        from netbox_rpc.domain.aggregate import RPCExecutionAggregate
        from netbox_rpc.models import RPCBackend, RPCExecution, RpcPluginSettings, RPCProcedure

        suffix = RPCExecution.objects.count() + 1
        backend = RPCBackend.objects.create(name=f'provider-executor-{suffix}', base_url='https://executor.invalid',
                                            executor_identity=self.executor)
        config = RpcPluginSettings.get_solo()
        config.enabled = True
        config.backend = backend
        config.save()
        procedure = RPCProcedure.objects.create(
            name=f'os.linux.test.provider{suffix}', handler_id='os.linux.test.provider', target_models=['dcim.device'],
            effect='read', params_schema={'type': 'object', 'properties': {}, 'additionalProperties': False},
        )
        for model, actions in ((RPCBackend, ['view']), (RPCProcedure, ['view', 'execute'])):
            permission = ObjectPermission.objects.create(name=model.__name__, actions=actions)
            permission.object_types.add(ObjectType.objects.get_for_model(model))
            permission.users.add(self.actor)
        self.actor = get_user_model().objects.get(pk=self.actor.pk)
        serializer = SimpleNamespace(validated_data={
            'procedure': procedure, 'assigned_object_type': ContentType.objects.get_for_model(self.target),
            'assigned_object_id': self.target.pk, 'params': {},
            'credential_references': {'transport': self.authority.reference.to_mapping()},
        })
        credential_authority.prepare_reference_execution(serializer, self.actor, backend.pk)
        execution = RPCExecution.objects.create(requested_by=self.actor, backend=backend.pk,
                                               **serializer.validated_data)
        key = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ).decode('ascii')
        settings_values = {
            dispatch_lease._SIGNING_KEYS_SETTING: [{
                'key_id': 'provider-test', 'key_version': 1, 'private_key_pem': key, 'active': True,
            }],
            dispatch_lease._AUDIENCE_SETTING: 'netbox-rpc-backend', dispatch_lease._TTL_SETTING: 120,
        }
        configured = patch.object(dispatch_lease, '_plugin_setting',
                                  side_effect=lambda name, default=None: settings_values.get(name, default))
        configured.start()
        self.addCleanup(configured.stop)
        aggregate = RPCExecutionAggregate(execution)
        aggregate.queue()
        aggregate.start()
        normalized = {'command_fingerprint': {'operation': 'read',
                                              'target_object_sha256': canonical_hash({'target': self.target.pk})}}
        apply_credential_fingerprint(execution, normalized)
        aggregate.normalize(normalized, canonical_hash(normalized['command_fingerprint']))
        lease = command_handlers._issue_dispatch_lease(execution, aggregate, normalized)
        self.params.update(execution_id=execution.pk, dispatch_lease=lease.model_dump())
        return execution


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class AutomationProviderTest(_AutomationFixture, TransactionTestCase):
    """Autocommit is intentional: the receipt must survive a failed reveal."""

    def test_delivers_requested_field_and_nonsecret_correlated_audit(self):
        result = self.resolve()
        self.assertEqual(result['fields'], {'password': CANARY})
        self.assertEqual(result['resolved_version'], 1)
        audit = CredentialAccessLog.objects.get(pk=result['access_log_id'])
        self.assertEqual((audit.user_id, audit.executor_id, audit.execution_id),
                         (self.actor.pk, self.executor.pk, 91))
        self.assertTrue(audit.success)
        for model in (Credential, CredentialAccessLog, AutomationResolutionReceipt):
            self.assertNotIn(CANARY, str(list(model.objects.values())))

    def test_old_binary_assignment_and_audit_inserts_use_database_defaults(self):
        audit = CredentialAccessLog.objects.create(action='reveal', credential_name_snapshot='rollback')
        cases = (
            (Credential, self.credential.pk, {'id', 'live_key_fingerprint', 'live_key_version',
                                             'staged_key_fingerprint', 'staged_key_version'}),
            (CredentialAssignment, self.assignment.pk, {'id', 'enabled'}),
            (CredentialAccessLog, audit.pk, {'id', 'executor', 'executor_snapshot', 'execution_id',
                                           'intent_run_id', 'step_id', 'reference_name', 'assignment_id',
                                           'resolved_version', 'purpose', 'dispatch_nonce_digest'}),
        )
        for model, original_pk, excluded in cases:
            with self.subTest(model=model.__name__), connection.cursor() as cursor:
                fields = [field for field in model._meta.concrete_fields if field.name not in excluded]
                columns = sql.SQL(', ').join(sql.Identifier(field.column) for field in fields)
                table = sql.Identifier(model._meta.db_table)
                cursor.execute(sql.SQL('SELECT {} FROM {} WHERE id = %s').format(columns, table), [original_pk])
                previous_values = cursor.fetchone()
                if model is Credential:
                    # Change only the duplicate's UUID and path; deleting the
                    # source would cascade away the assignment used below.
                    import uuid

                    previous_values = list(previous_values)
                    previous_values[[field.name for field in fields].index('uuid')] = uuid.uuid4()
                    previous_values[[field.name for field in fields].index('path')] = 'rollback-copy/credentials/test'
                else:
                    model.objects.filter(pk=original_pk).delete()
                placeholders = sql.SQL(', ').join(sql.Placeholder() for _ in fields)
                cursor.execute(sql.SQL('INSERT INTO {} ({}) VALUES ({}) RETURNING id').format(
                    table, columns, placeholders,
                ), previous_values)
                inserted = model.objects.get(pk=cursor.fetchone()[0])
                self.assert_rollback_defaults(inserted)

    def assert_rollback_defaults(self, inserted):
        if isinstance(inserted, Credential):
            self.assertEqual(inserted.live_key_fingerprint, '')
            self.assertEqual(inserted.staged_key_fingerprint, '')
            self.assertIsNone(inserted.live_key_version)
            self.assertIsNone(inserted.staged_key_version)
        elif isinstance(inserted, CredentialAssignment):
            self.assertTrue(inserted.enabled)
        else:
            self.assertEqual(inserted.executor_snapshot, '')
            self.assertEqual(inserted.dispatch_nonce_digest, '')

    def test_private_key_and_passphrase_are_one_read_of_one_version(self):
        material = self.prepare_ssh_bundle()
        with patch.object(FakeBackend, 'read', autospec=True, side_effect=FakeBackend.read) as read:
            result = self.resolve()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(result['resolved_version'], 2)
        self.assertEqual(result['fields'], {'private_key': material, 'passphrase': CANARY})
        for model in (Credential, CredentialAccessLog, AutomationResolutionReceipt):
            stored = str(list(model.objects.values()))
            self.assertNotIn(CANARY, stored)
            self.assertNotIn(material, stored)

    def test_repeat_has_no_second_backend_read(self):
        self.resolve()
        self.assert_denied_before_read()
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)

    def test_backend_failure_leaves_receipt_and_safe_refusal(self):
        with patch.object(FakeBackend, 'read', side_effect=OpenBaoUnavailable(CANARY)):
            with self.assertRaises(AutomationResolutionDenied) as caught:
                self.resolve()
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
        self.assert_denied_before_read()
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))

    def test_disabled_assignment_is_refused(self):
        CredentialAssignment.objects.filter(pk=self.assignment.pk).update(enabled=False)
        self.assert_denied_before_read()

    def test_revoked_actor_is_refused(self):
        get_user_model().objects.filter(pk=self.actor.pk).update(is_active=False)
        self.assert_denied_before_read()

    def test_object_scoped_reveal_permission_is_required(self):
        permission = ObjectPermission.objects.get(name='Credential')
        permission.constraints = {'pk': self.credential.pk + 1000}
        permission.save()
        self.assert_denied_before_read()

    def test_target_and_purpose_mismatch_are_refused(self):
        original = self.authority
        for change in ({'purpose': 'api'}, {'target': {'object_type': 'dcim.device', 'object_id': self.target.pk + 1}}):
            with self.subTest(change=change):
                wire = original.reference.to_mapping()
                wire.update(change)
                self.authority = replace(original, reference=CredentialReferenceV1.from_mapping(wire))
                self.assert_denied_before_read()

    def test_uuid_selector_cannot_bypass_assignment(self):
        wire = self.authority.reference.to_mapping()
        wire.pop('assignment_id')
        wire['credential_uuid'] = str(self.credential.uuid)
        self.authority = replace(self.authority, reference=CredentialReferenceV1.from_mapping(wire))
        self.assertEqual(self.resolve()['resolved_version'], 1)
        CredentialAssignment.objects.filter(pk=self.assignment.pk).update(enabled=False)
        self.authority = replace(self.authority, dispatch_nonce='second-dispatch')
        self.assert_denied_before_read()

    def test_staged_version_is_never_live_or_pinned_automation(self):
        stage_material(self.credential, {'password': 'staged-canary'})
        result = self.resolve()
        self.assertEqual(result['fields'], {'password': CANARY})
        wire = self.authority.reference.to_mapping()
        wire['version'] = {'policy': 'pinned', 'number': 2}
        self.authority = replace(self.authority, dispatch_nonce='next',
                                 reference=CredentialReferenceV1.from_mapping(wire))
        self.assert_denied_before_read()

    def test_missing_live_pointer_is_not_latest_fallback(self):
        Credential.objects.filter(pk=self.credential.pk).update(live_kv_version=None)
        self.assert_denied_before_read()

    def test_undeclared_field_is_refused(self):
        wire = self.authority.reference.to_mapping()
        wire['fields'] = ['private_key']
        self.authority = replace(self.authority, reference=CredentialReferenceV1.from_mapping(wire))
        self.assert_denied_before_read()

    def test_audit_failure_blocks_read_but_reservation_survives(self):
        with patch('netbox_openbao.automation.record_automation_access', side_effect=RuntimeError(CANARY)):
            self.assert_denied_before_read()
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)

    def test_ambient_transaction_is_refused(self):
        with transaction.atomic():
            self.assert_denied_before_read()
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 0)

    def test_expired_credential_is_refused(self):
        Credential.objects.filter(pk=self.credential.pk).update(valid_until=timezone.now())
        self.assert_denied_before_read()

    def test_request_rejects_caller_identity_reference_and_coerced_ids(self):
        for changes in ({'actor_id': 1}, {'reference': {}}, {'execution_id': True}, {'execution_id': '91'}):
            with self.subTest(changes=changes):
                self.assertFalse(AutomationResolveRequestSerializer(data=self.params | changes).is_valid())

    def test_identity_change_after_admission_is_refused(self):
        Credential.objects.filter(pk=self.credential.pk).update(username='different-identity')
        self.assert_denied_before_read()

    def test_same_assignment_id_cannot_substitute_another_credential(self):
        other = Credential(name='Other', credential_type='password', policy=self.policy, engine=self.engine)
        write_material(other, {'password': 'another-identity-canary'})
        CredentialAssignment.objects.filter(pk=self.assignment.pk).update(credential=other)
        self.assert_denied_before_read()

    def test_live_password_rotation_preserves_identity_and_selects_new_version(self):
        write_material(self.credential, {'password': 'rotated-value'}, cas=1)
        result = self.resolve()
        self.assertEqual(result['resolved_version'], 2)
        self.assertEqual(result['fields'], {'password': 'rotated-value'})

    def test_policy_group_membership_is_required_and_rechecked(self):
        group = Group.objects.create(name='credential-operators')
        self.policy.groups.add(group)
        self.assert_denied_before_read()
        self.actor.groups.add(group)
        self.assertEqual(self.resolve()['fields'], {'password': CANARY})

    def test_retired_and_not_yet_valid_credentials_are_refused(self):
        for changes in ({'status': 'retired'}, {'status': 'active', 'valid_from': timezone.now() + timedelta(days=1)}):
            with self.subTest(changes=changes):
                Credential.objects.filter(pk=self.credential.pk).update(**changes)
                self.assert_denied_before_read()

    def test_backend_selector_change_after_approval_is_refused(self):
        SecretEngine.objects.filter(pk=self.engine.pk).update(api_url='https://changed.invalid:8200')
        self.assert_denied_before_read()

    def test_concurrent_requests_reveal_only_once(self):
        barrier = Barrier(2)

        def attempt():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                try:
                    resolve_automation(self.request, self.params)
                    return True
                except AutomationResolutionDenied:
                    return False
            finally:
                close_old_connections()

        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority):
            with patch.object(FakeBackend, 'read', autospec=True, side_effect=FakeBackend.read) as read:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(attempt) for _ in range(2)]
                    results = [future.result(timeout=30) for future in futures]
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(read.call_count, 1)
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
