"""Deterministic PostgreSQL proofs of policy relationship synchronization."""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from importlib import import_module
from queue import Queue
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from netbox.context import current_request
from users.models import Group, ObjectPermission

from netbox_openbao.automation import (
    AutomationResolutionDenied,
    _deliver,
    _reserve,
    _resolve_metadata,
    capture_reference_identity,
)
from netbox_openbao.forms import CredentialForm
from netbox_openbao.material_transactions import material_transaction
from netbox_openbao.models import CredentialPolicy, CredentialTypeSchema
from netbox_openbao.services import store_credential, write_material
from netbox_openbao.synchronization import lock_material_subjects

from .fakes import FakeBackend
from .test_automation import _AutomationFixture


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class AutomationPolicyConcurrencyTest(_AutomationFixture, TransactionTestCase):
    def drift_worker(self, pids, material=False):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            if material:
                with material_transaction():
                    return lock_material_subjects([self.credential])
            with transaction.atomic():
                return _resolve_metadata(self.authority)
        finally:
            close_old_connections()

    def prove_graph_drift_refused(self, *, material=False):
        destination = CredentialPolicy.objects.create(name='Changed graph', slug='changed-graph', engine=self.engine)
        pids = Queue()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                worker = pool.submit(self.drift_worker, pids, material)
                self.wait_for_block(pids.get(timeout=10))
                type(self.credential).objects.filter(pk=self.credential.pk).update(policy=destination)
            with self.assertRaises(ValidationError):
                worker.result(timeout=10)

    def test_provider_graph_drift_is_refused_after_policy_wait(self):
        self.prove_graph_drift_refused()

    def test_material_graph_drift_is_refused_after_policy_wait(self):
        self.prove_graph_drift_refused(material=True)

    def test_assignment_credential_drift_is_refused_after_policy_wait(self):
        other = type(self.credential).objects.create(
            name='Other identity', credential_type='password', policy=self.policy, engine=self.engine,
        )
        pids = Queue()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                worker = pool.submit(self.drift_worker, pids)
                self.wait_for_block(pids.get(timeout=10))
                type(self.assignment).objects.filter(pk=self.assignment.pk).update(credential=other)
            with self.assertRaises(AutomationResolutionDenied):
                worker.result(timeout=10)

    def save_staged_form_in_thread(self, destination, pids):
        close_old_connections()
        token = current_request.set(SimpleNamespace(user=self.actor, id=uuid4(), META={}))
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            credential = type(self.credential).objects.get(pk=self.credential.pk)
            form = CredentialForm(instance=credential, data={
                'name': 'Edited credential', 'credential_type': 'password', 'policy': destination.pk,
                'engine': self.engine.pk, 'status': 'active', 'password': 'staged-form-value',
                'stage_rotation': True,
            })
            self.assertTrue(form.is_valid(), form.errors)
            with material_transaction(), transaction.atomic():
                return form.save().pk
        finally:
            current_request.reset(token)
            close_old_connections()

    def test_staged_form_locks_source_and_destination_before_first_save(self):
        destination = CredentialPolicy.objects.create(name='Destination', slug='destination', engine=self.engine)
        ObjectPermission.objects.filter(name='Credential').update(actions=['view', 'reveal', 'change', 'rotate'])
        receipt = _reserve(self.authority)
        pids = Queue()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                worker = pool.submit(self.save_staged_form_in_thread, destination, pids)
                self.wait_for_block(pids.get(timeout=10))
                # A pre-lock form UPDATE would already own this row and fail
                # this actual PostgreSQL NOWAIT acquisition.
                type(self.credential).objects.select_for_update(nowait=True).get(pk=self.credential.pk)
                with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority):
                    result = _deliver(self.request, self.params, receipt)
                self.assertEqual(result['resolved_version'], 1)
            self.assertEqual(worker.result(timeout=10), self.credential.pk)
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.policy_id, self.credential.live_kv_version,
                          self.credential.staged_kv_version), (destination.pk, 1, 2))

    def prepare_custom_password(self):
        schema = CredentialTypeSchema.objects.create(
            name='Custom password', slug='custom-password',
            schema={'type': 'object', 'properties': {'password': {'type': 'string'}}, 'required': ['password']},
            secret_fields=['password'],
        )
        self.credential.credential_type = schema.slug
        self.credential.save(update_fields=['credential_type'])
        identity = capture_reference_identity(reference=self.authority.reference, initiating_actor=self.actor,
                                              target_object=self.target, reason=self.authority.reason)
        self.authority = replace(self.authority, provider_identity=identity)
        return schema

    def test_schema_wait_rechecks_assignment_permission(self):
        schema = self.prepare_custom_password()
        receipt = _reserve(self.authority)
        pids = Queue()
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority), \
                patch.object(FakeBackend, 'read', autospec=True) as read, ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialTypeSchema.objects.select_for_update().get(pk=schema.pk)
                future = pool.submit(self.deliver_in_thread, receipt, pids)
                self.wait_for_block(pids.get(timeout=10))
                ObjectPermission.objects.filter(name='CredentialAssignment').update(constraints={'pk': -1})
            self.assertEqual(future.result(timeout=10), 'denied')
            read.assert_not_called()

    def test_schema_wait_rechecks_verified_dispatch_expiry(self):
        schema = self.prepare_custom_password()
        receipt = _reserve(self.authority)
        pids = Queue()
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority), \
                patch.object(FakeBackend, 'read', autospec=True) as read, ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialTypeSchema.objects.select_for_update().get(pk=schema.pk)
                future = pool.submit(self.deliver_in_thread, receipt, pids)
                self.wait_for_block(pids.get(timeout=10))
                expired_time = self.authority.expires_at + timedelta(seconds=1)
                clock = patch('netbox_rpc.credential_authority.timezone.now', return_value=expired_time)
                clock.start()
            try:
                self.assertEqual(future.result(timeout=10), 'denied')
            finally:
                clock.stop()
            read.assert_not_called()

    def test_policy_trigger_reversal_is_transactional_and_bounded(self):
        migration = import_module('netbox_openbao.migrations.0010_live_identity_and_policy_lock')
        count_trigger = "SELECT count(*) FROM pg_trigger WHERE tgname = 'openbao_policy_groups_lock'"
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(migration.UNLOCK_POLICY_GROUPS)
                cursor.execute(count_trigger)
                self.assertEqual(cursor.fetchone()[0], 0)
            transaction.set_rollback(True)
        with connection.cursor() as cursor:
            cursor.execute(count_trigger)
            self.assertEqual(cursor.fetchone()[0], 1)

    def wait_for_block(self, worker_pid):
        holder_pid = connection.connection.info.backend_pid
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute('SELECT %s = ANY(pg_blocking_pids(%s))', [holder_pid, worker_pid])
                if cursor.fetchone()[0]:
                    return
            time.sleep(0.01)
        self.fail('The worker never waited on the expected PostgreSQL policy lock.')

    def deliver_in_thread(self, receipt, pids):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            try:
                _deliver(self.request, self.params, receipt)
            except AutomationResolutionDenied:
                return 'denied'
            return 'delivered'
        finally:
            close_old_connections()

    def prove_mutation_revokes_waiting_delivery(self, mutation):
        receipt = _reserve(self.authority)
        pids = Queue()
        with patch('netbox_openbao.automation.authorize_dispatch', return_value=self.authority), \
                patch.object(FakeBackend, 'read', autospec=True) as read, ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                policy = CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                mutation(policy)
                future = pool.submit(self.deliver_in_thread, receipt, pids)
                self.wait_for_block(pids.get(timeout=10))
            self.assertEqual(future.result(timeout=10), 'denied')
            read.assert_not_called()

    def test_group_replacement_is_rechecked_after_policy_lock_wait(self):
        allowed = Group.objects.create(name='old-allowed')
        denied = Group.objects.create(name='new-required')
        self.actor.groups.add(allowed)
        self.policy.groups.add(allowed)
        self.prove_mutation_revokes_waiting_delivery(lambda policy: policy.groups.set([denied]))

    def test_policy_slug_constraint_is_rechecked_after_policy_lock_wait(self):
        permission = ObjectPermission.objects.get(name='Credential')
        permission.constraints = {'policy__slug': 'test'}
        permission.save()

        def change_slug(policy):
            policy.slug = 'excluded'
            policy.save(update_fields=['slug'])

        self.prove_mutation_revokes_waiting_delivery(change_slug)

    def direct_relationship_write(self, group_id, pids):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            CredentialPolicy.groups.through.objects.create(credentialpolicy_id=self.policy.pk, group_id=group_id)
        finally:
            close_old_connections()

    def test_direct_through_write_waits_for_parent_policy_lock(self):
        group = Group.objects.create(name='direct-through')
        pids = Queue()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                future = pool.submit(self.direct_relationship_write, group.pk, pids)
                self.wait_for_block(pids.get(timeout=10))
                self.assertFalse(self.policy.groups.filter(pk=group.pk).exists())
            future.result(timeout=10)
        self.assertTrue(self.policy.groups.filter(pk=group.pk).exists())

    def test_direct_through_delete_rolls_back_and_releases_its_lock(self):
        group = Group.objects.create(name='rollback-through')
        self.policy.groups.add(group)
        with self.assertRaises(RuntimeError), transaction.atomic():
            CredentialPolicy.groups.through.objects.filter(credentialpolicy_id=self.policy.pk).delete()
            raise RuntimeError('Rollback the disposable relationship mutation.')
        self.assertTrue(self.policy.groups.filter(pk=group.pk).exists())
        pids = Queue()
        second_group = Group.objects.create(name='after-rollback')
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(self.direct_relationship_write, second_group.pk, pids).result(timeout=10)
        self.assertTrue(self.policy.groups.filter(pk=second_group.pk).exists())

    def update_relationship(self, relationship_pk, policy_id, pids):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            CredentialPolicy.groups.through.objects.filter(pk=relationship_pk).update(credentialpolicy_id=policy_id)
        finally:
            close_old_connections()

    def test_direct_through_update_waits_for_old_policy_lock(self):
        group = Group.objects.create(name='move-through')
        self.policy.groups.add(group)
        relation = CredentialPolicy.groups.through.objects.get(credentialpolicy_id=self.policy.pk, group_id=group.pk)
        other = CredentialPolicy.objects.create(name='Other', slug='other', engine=self.engine)
        pids = Queue()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                future = pool.submit(self.update_relationship, relation.pk, other.pk, pids)
                self.wait_for_block(pids.get(timeout=10))
            future.result(timeout=10)
        self.assertFalse(self.policy.groups.filter(pk=group.pk).exists())
        self.assertTrue(other.groups.filter(pk=group.pk).exists())

    def write_in_thread(self, pids):
        close_old_connections()
        try:
            connection.ensure_connection()
            pids.put(connection.connection.info.backend_pid)
            write_material(self.credential, {'password': 'new-write-value'}, cas=1)
        finally:
            close_old_connections()

    def test_material_writer_refreshes_backend_configuration_after_wait(self):
        from netbox_openbao.backends import get_backend

        observed = []
        metadata_before = len(FakeBackend.metadata_calls)

        def inspect_backend(engine, policy):
            observed.append((engine.api_url, policy.approle_env_prefix))
            return get_backend(engine, policy)

        pids = Queue()
        with patch('netbox_openbao.services.get_backend', side_effect=inspect_backend), \
                ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                policy = CredentialPolicy.objects.select_for_update().get(pk=self.policy.pk)
                policy.approle_env_prefix = 'UPDATED_POLICY'
                policy.save(update_fields=['approle_env_prefix'])
                type(self.engine).objects.filter(pk=self.engine.pk).update(api_url='https://new-engine.invalid')
                future = pool.submit(self.write_in_thread, pids)
                self.wait_for_block(pids.get(timeout=10))
            future.result(timeout=10)
        expected = ('https://new-engine.invalid', 'UPDATED_POLICY')
        self.assertEqual(observed, [expected, expected])
        self.assertEqual(len(FakeBackend.metadata_calls) - metadata_before, 1)

    def test_persistence_cannot_restore_stale_backend_selectors(self):
        from netbox_openbao.backends import get_backend

        stale_engine, stale_policy = self.credential.engine, self.credential.policy
        type(self.engine).objects.filter(pk=self.engine.pk).update(api_url='https://fresh-engine.invalid')
        CredentialPolicy.objects.filter(pk=self.policy.pk).update(approle_env_prefix='FRESH_POLICY')
        observed = []
        metadata_before = len(FakeBackend.metadata_calls)

        def persist(metadata):
            self.credential.engine, self.credential.policy = stale_engine, stale_policy
            self.credential.save()
            return self.credential

        def inspect_backend(engine, policy):
            observed.append((engine.api_url, policy.approle_env_prefix))
            return get_backend(engine, policy)

        with patch('netbox_openbao.services.get_backend', side_effect=inspect_backend):
            store_credential(persist, 'password', {'password': 'fresh-value'}, cas=1,
                             subject=self.credential)
        expected = ('https://fresh-engine.invalid', 'FRESH_POLICY')
        self.assertEqual(observed, [expected, expected])
        self.assertEqual(len(FakeBackend.metadata_calls) - metadata_before, 1)
