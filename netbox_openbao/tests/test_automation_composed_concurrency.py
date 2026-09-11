"""Real RPC user locks compose with provider material-audit foreign keys."""

from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from users.models import ObjectPermission

from netbox_openbao import automation
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialTypeSchema
from netbox_openbao.synchronization import lock_credential_graph

from . import test_automation_concurrency as policy_concurrency
from .test_automation import _AutomationFixture


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class ComposedRPCPermissionWaitTest(_AutomationFixture, TransactionTestCase):
    wait_for_block = policy_concurrency.AutomationPolicyConcurrencyTest.wait_for_block

    def provider_worker(self, receipt, pids):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            return automation._deliver(self.request, self.params, receipt)
        finally:
            close_old_connections()

    def custom_key_schema(self):
        self.schema = CredentialTypeSchema.objects.create(
            name='Composed key', slug='composed-key',
            schema={'type': 'object', 'properties': {
                'private_key': {'type': 'string'}, 'passphrase': {'type': 'string'},
            }, 'required': ['private_key'], 'additionalProperties': False},
            secret_fields=['private_key', 'passphrase'], extractor='ssh',
        )
        Credential.objects.filter(pk=self.credential.pk).update(credential_type=self.schema.slug)

    def revoke(self, user_id, *, action='execute', provider=False):
        close_old_connections()
        try:
            name = 'Credential' if provider else f'protected-provider-{user_id}-RPCProcedure-{action}'
            ObjectPermission.objects.filter(name=name).update(
                constraints={'id': -1},
            )
        finally:
            close_old_connections()

    def assert_exact_revocation(self, user_id, procedure_id, action):
        from netbox_rpc.models import RPCProcedure

        actor = get_user_model().objects.get(pk=user_id)
        self.assertTrue(RPCProcedure.objects.restrict(actor, 'view').filter(pk=procedure_id).exists())
        self.assertFalse(RPCProcedure.objects.restrict(actor, action).filter(pk=procedure_id).exists())

    def assert_wait_revocation(self, *, approver=False, schema=False):
        from .fakes import FakeBackend
        from .protected_dispatch import protected_bundle_round_trip

        def denied(execution, approving_actor):
            authority = automation.authorize_dispatch(self.request, self.params)
            receipt = automation._reserve(authority)
            actor_id = approving_actor.pk if approver else self.actor.pk
            action = 'approve' if approver else 'execute'
            model, pk = (CredentialTypeSchema, self.schema.pk) if schema else (Credential, self.credential.pk)
            pids = Queue()
            original_read = FakeBackend.read
            with patch.object(FakeBackend, 'read', autospec=True, side_effect=original_read) as read, \
                    ThreadPoolExecutor(max_workers=1) as pool:
                with transaction.atomic():
                    model.objects.select_for_update().get(pk=pk)
                    future = pool.submit(self.provider_worker, receipt, pids)
                    self.wait_for_block(pids.get(timeout=10))
                    ObjectPermission.objects.filter(name=f'protected-provider-{actor_id}-RPCProcedure-{action}').update(
                        constraints={'id': -1},
                    )
                self.assert_exact_revocation(actor_id, execution.procedure_id, action)
                with self.assertRaises(automation.AutomationResolutionDenied):
                    future.result(timeout=10)
                read.assert_not_called()
            self.assertFalse(CredentialAccessLog.objects.filter(execution_id=execution.pk, success=True).exists())

        protected_bundle_round_trip(self, before_admission=self.custom_key_schema if schema else None,
                                    denial_check=denied)

    def test_exact_execute_permission_revocation_during_schema_wait_denies_before_read(self):
        self.assert_wait_revocation(schema=True)

    def test_exact_approve_permission_revocation_during_credential_wait_denies_before_read(self):
        self.assert_wait_revocation(approver=True)

    def assert_post_read_revocation(self, *, approver=False, provider=False):
        from netbox_openbao.services import read_automation_bundle

        from .protected_dispatch import protected_bundle_round_trip

        def denied(execution, approving_actor):
            actor_id = approving_actor.pk if approver else self.actor.pk
            action = 'approve' if approver else 'execute'

            def waited_read(*args, **kwargs):
                result = read_automation_bundle(*args, **kwargs)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(self.revoke, actor_id, action=action, provider=provider).result(timeout=10)
                if not provider:
                    self.assert_exact_revocation(actor_id, execution.procedure_id, action)
                return result

            with patch('netbox_openbao.services.read_automation_bundle', side_effect=waited_read) as read, \
                    self.assertRaises(automation.AutomationResolutionDenied):
                automation.resolve_automation(self.request, self.params)
            read.assert_called_once()
            self.assertFalse(CredentialAccessLog.objects.filter(execution_id=execution.pk, success=True).exists())

        protected_bundle_round_trip(self, denial_check=denied)

    def test_exact_execute_permission_revocation_during_read_prevents_disclosure(self):
        self.assert_post_read_revocation()

    def test_exact_approve_permission_revocation_during_read_prevents_disclosure(self):
        self.assert_post_read_revocation(approver=True)

    def test_provider_reveal_permission_revocation_during_read_prevents_disclosure(self):
        self.assert_post_read_revocation(provider=True)


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class ComposedAuditLockTest(_AutomationFixture, TransactionTestCase):
    def test_real_rpc_actor_locks_allow_material_audit_foreign_key(self):
        self.issue_real_dispatch()
        authority = automation.authorize_dispatch(self.request, self.params)
        receipt = automation._reserve(authority)
        graph_held, authority_held = Event(), Event()
        original = automation._resolve_metadata

        def after_authority(value):
            authority_held.set()
            return original(value)

        def material_writer():
            close_old_connections()
            try:
                with transaction.atomic():
                    lock_credential_graph(self.credential.pk)
                    graph_held.set()
                    if not authority_held.wait(10):
                        raise AssertionError('RPC did not reach its provider boundary.')
                    CredentialAccessLog.objects.create(
                        credential=self.credential, user=self.actor, action='write', success=True,
                    )
            finally:
                close_old_connections()

        def provider():
            close_old_connections()
            try:
                return automation._deliver(self.request, self.params, receipt)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(material_writer)
            self.assertTrue(graph_held.wait(10))
            with patch('netbox_openbao.automation._resolve_metadata', side_effect=after_authority):
                reader = pool.submit(provider)
                writer.result(timeout=20)
                result = reader.result(timeout=20)
        self.assertEqual(result['resolved_version'], 1)
