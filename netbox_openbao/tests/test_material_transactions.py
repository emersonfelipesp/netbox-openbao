"""Outer commit and compensation behavior on actual PostgreSQL transactions."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, OperationalError, connection, transaction
from django.http import HttpResponse
from django.test import TestCase, TransactionTestCase, override_settings

from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.material_transactions import MaterialAttempt, MaterialTransaction, material_transaction
from netbox_openbao.models import Credential, CredentialAccessLog
from netbox_openbao.services import discard_staged, promote_staged, rotate_material, stage_material, write_material
from netbox_openbao.synchronization import lock_material_subjects
from netbox_openbao.views import CredentialEditView

from .base import MaterialTransactionTestMixin
from .fakes import FakeBackend
from .test_automation import CANARY, _AutomationFixture


class MaterialFixtureLifecycleTest(MaterialTransactionTestMixin, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.actor = get_user_model().objects.create_user(username='material-fixture-class-data')

    def assert_fresh_class_data_and_real_commit(self, replacement):
        self.assertTrue(connection.get_autocommit())
        self.assertFalse(connection.in_atomic_block)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(self.actor.username, 'material-fixture-class-data')
        committed = []
        with transaction.atomic():
            self.actor.username = replacement
            self.actor.save(update_fields=['username'])
            transaction.on_commit(lambda: committed.append(True))
        self.assertEqual(committed, [True])

    def test_class_data_is_isolated_from_the_other_committed_test(self):
        self.assert_fresh_class_data_and_real_commit('first-committed-fixture')

    def test_class_data_is_rebuilt_after_the_other_committed_test(self):
        self.assert_fresh_class_data_and_real_commit('second-committed-fixture')


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class MaterialTransactionTest(_AutomationFixture, TransactionTestCase):
    def assert_manual_autocommit_refused(self, operation):
        refused = False
        original_write, original_delete = FakeBackend.write, FakeBackend.delete
        with patch.object(FakeBackend, 'write', autospec=True, side_effect=original_write) as write, \
                patch.object(FakeBackend, 'delete', autospec=True, side_effect=original_delete) as delete:
            connection.set_autocommit(False)
            try:
                self.assertFalse(connection.in_atomic_block)
                try:
                    operation()
                except OpenBaoError:
                    refused = True
            finally:
                connection.rollback()
                connection.set_autocommit(True)
            self.assertTrue(refused, 'A manually managed transaction must be refused.')
            write.assert_not_called()
            delete.assert_not_called()

    def test_manual_autocommit_store_is_refused_before_external_write(self):
        self.assert_manual_autocommit_refused(self.rotate)
        self.assert_original()

    def test_manual_autocommit_direct_store_entry_is_refused_before_external_write(self):
        self.assert_manual_autocommit_refused(
            lambda: write_material(self.credential, {'password': 'uncommitted-value'}, cas=1),
        )
        self.assert_original()

    def test_manual_autocommit_discard_preserves_pointer_and_material_after_outer_rollback(self):
        stage_material(self.credential, {'password': 'staged-value'})
        self.assert_manual_autocommit_refused(lambda: discard_staged(self.credential))
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, 2))
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=2), {'password': 'staged-value'})
        self.assertEqual(FakeBackend.delete_calls, [])

    def test_unconfirmed_owner_cannot_delete_staged_material(self):
        stage_material(self.credential, {'password': 'staged-value'})
        owner = MaterialTransaction(deletions=[MaterialAttempt(
            credential=self.credential, backend=FakeBackend(self.engine), path=self.credential.path,
            user=None, action='discard', version=2,
        )])
        with self.assertRaises(OpenBaoError), patch.object(FakeBackend, 'delete') as delete:
            owner.finish_deletions()
        delete.assert_not_called()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.staged_kv_version, 2)
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=2), {'password': 'staged-value'})

    def test_nested_declared_owner_commits_all_successful_participants(self):
        with material_transaction() as owner:
            self.rotate('first-new-value')
            with material_transaction() as nested:
                self.assertIs(nested, owner)
                self.assertFalse(connection.get_autocommit())
                self.rotate('second-new-value')
            self.assertFalse(owner.committed)
        self.assertTrue(owner.committed)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 3)
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=3),
                         {'password': 'second-new-value'})

    def test_api_wrapper_never_preserves_a_success_response_after_rollback(self):
        from netbox_openbao.api.transactions import material_api_operation

        @material_api_operation
        def response():
            self.rotate()
            return HttpResponse('Provisional success.')

        with patch('netbox_openbao.material_transactions.MaterialTransaction.witness',
                   side_effect=OpenBaoError('Commit witness refused.')), self.assertRaises(OpenBaoError):
            response()
        self.assert_original()

    def test_api_wrapper_never_returns_a_normal_error_after_committed_callback_failure(self):
        from netbox_openbao.api.transactions import material_api_operation

        def failed_callback():
            raise OpenBaoError('Post-commit processing failed.')

        @material_api_operation
        def response():
            self.rotate()
            transaction.on_commit(failed_callback)
            return HttpResponse('Provisional error.', status=400)

        with self.assertRaises(OpenBaoError):
            response()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 2)
        self.assertEqual(FakeBackend.delete_calls, [])

    def test_edit_view_never_returns_successful_modal_after_owner_failure(self):
        def framework_post(*args, **kwargs):
            self.rotate()
            return HttpResponse('Successful modal response.')

        with patch('netbox.views.generic.ObjectEditView.post', side_effect=framework_post), \
                patch('netbox_openbao.material_transactions.MaterialTransaction.witness',
                      side_effect=OpenBaoError('Final transaction witness refused.')):
            response = CredentialEditView().post(self.request)
        self.assertEqual(response.status_code, 503)
        self.assert_original()

    def test_edit_view_preserves_framework_caught_sanitized_form_errors(self):
        def framework_post(*args, **kwargs):
            try:
                with transaction.atomic(), material_transaction():
                    self.rotate()
                    raise OpenBaoError('The operation was refused.')
            except OpenBaoError:
                return HttpResponse('Sanitized form error.')

        with patch('netbox.views.generic.ObjectEditView.post', side_effect=framework_post):
            response = CredentialEditView().post(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'Sanitized form error.')
        self.assert_original()

    def second_credential(self):
        credential = Credential(name='Second participant', credential_type='password',
                                policy=self.policy, engine=self.engine)
        write_material(credential, {'password': 'second-original'})
        return credential

    def test_predeclared_multi_credential_owner_and_assignment_rollback(self):
        other = self.second_credential()
        original_name = self.target.name
        with self.assertRaises(ValueError), material_transaction():
            owner = type(self.target).objects.select_for_update().get(pk=self.target.pk)
            lock_material_subjects([other, self.credential])
            self.rotate()
            rotate_material(other, {'password': 'second-updated'})
            owner.name = 'Uncommitted owner'
            owner.save()
            self.assignment.credential = other
            self.assignment.save()
            raise ValueError('Final owner persistence was refused.')
        self.assert_original()
        other.refresh_from_db()
        self.target.refresh_from_db()
        self.assignment.refresh_from_db()
        self.assertEqual(other.kv_version, 1)
        self.assertEqual(self.target.name, original_name)
        self.assertEqual(self.assignment.credential_id, self.credential.pk)
        self.assertEqual(FakeBackend(other.engine).read(other.path, version=1), {'password': 'second-original'})

    def test_undeclared_existing_participant_is_refused_before_its_write(self):
        other = self.second_credential()
        with self.assertRaises(OpenBaoError), material_transaction():
            self.rotate()
            rotate_material(other, {'password': 'undeclared-update'})
        self.assert_original()
        self.assertEqual(len(FakeBackend.store[other.path]), 1)

    def test_complete_lock_scope_cannot_expand_even_before_the_first_write(self):
        other = self.second_credential()
        with self.assertRaises(OpenBaoError), material_transaction():
            lock_material_subjects([self.credential])
            lock_material_subjects([other])
        self.assert_original()

    def test_missing_material_subject_refuses_before_persistence(self):
        from netbox_openbao.services import store_credential

        with patch('netbox_openbao.models.Credential.save') as persist, self.assertRaises(OpenBaoError):
            store_credential(persist, 'password', {'password': CANARY})
        persist.assert_not_called()

    def rotate(self, value='new-value'):
        return rotate_material(self.credential, {'password': value})

    def assert_original(self):
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, 1)
        self.assertEqual(self.credential.live_kv_version, 1)
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=1), {'password': CANARY})

    def test_outer_caller_failure_compensates_two_writes_and_assignment_changes(self):
        with self.assertRaises(ValueError), material_transaction():
            self.rotate('first-new-value')
            self.rotate('second-new-value')
            self.assignment.enabled = False
            self.assignment.save(update_fields=['enabled'])
            raise ValueError('Caller refused final persistence.')
        self.assert_original()
        self.assignment.refresh_from_db()
        self.assertTrue(self.assignment.enabled)
        self.assertEqual(FakeBackend.delete_calls, [(self.credential.path, (3,)), (self.credential.path, (2,))])

    def test_deferred_foreign_key_rejects_final_commit_and_compensates(self):
        with self.assertRaises(IntegrityError), material_transaction():
            self.rotate()
            CredentialAccessLog.objects.create(credential_id=2147483647, action='write')
        self.assert_original()
        self.assertEqual(FakeBackend.delete_calls, [(self.credential.path, (2,))])
        audit = CredentialAccessLog.objects.get(resolved_version=2, success=False)
        self.assertIn('rolled back', audit.message)

    def test_unknown_commit_preserves_material_and_records_reconciliation(self):
        original_commit = connection.commit

        def lost_acknowledgement():
            original_commit()
            raise OperationalError('Commit acknowledgement unavailable.')

        with patch.object(connection, 'commit', side_effect=lost_acknowledgement), \
                self.assertRaises(OperationalError):
            self.rotate()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.kv_version, 2)
        self.assertEqual(FakeBackend.delete_calls, [])
        audit = CredentialAccessLog.objects.get(resolved_version=2, success=False)
        self.assertIn('outcome unknown', audit.message)

    def test_later_commit_callback_integrity_error_cannot_compensate_committed_write(self):
        def failed_callback():
            raise IntegrityError('A later callback failed after commit.')

        with self.assertRaises(IntegrityError), material_transaction():
            self.rotate()
            transaction.on_commit(failed_callback)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 2)
        self.assertEqual(FakeBackend.delete_calls, [])
        self.assertTrue(CredentialAccessLog.objects.filter(
            resolved_version=2, success=False, message__contains='committed; post-commit',
        ).exists())

    def test_unverified_integrity_error_after_lost_commit_acknowledgement_is_unknown(self):
        original_commit = connection.commit

        def lost_acknowledgement():
            original_commit()
            raise IntegrityError('No PostgreSQL rollback evidence is available.')

        with patch.object(connection, 'commit', side_effect=lost_acknowledgement), \
                self.assertRaises(IntegrityError):
            self.rotate()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.live_kv_version, 2)
        self.assertEqual(FakeBackend.delete_calls, [])
        self.assertTrue(CredentialAccessLog.objects.filter(
            resolved_version=2, success=False, message__contains='outcome unknown',
        ).exists())

    def test_cleanup_failure_retains_fixed_durable_reconciliation_evidence(self):
        with self.assertLogs('netbox.plugins.netbox_openbao.material_transactions') as captured:
            with patch.object(FakeBackend, 'delete', side_effect=OpenBaoError(CANARY)), \
                    self.assertRaises(ValueError), material_transaction():
                self.rotate()
                raise ValueError('Final owner save refused.')
        self.assert_original()
        self.assertEqual(len(FakeBackend.store[self.credential.path]), 2)
        self.assertNotIn(CANARY, str(captured.output))
        self.assertTrue(CredentialAccessLog.objects.filter(
            resolved_version=2, message__contains='cleanup requires reconciliation', success=False,
        ).exists())

    def test_caught_framework_savepoint_rollback_is_detected_by_witness(self):
        with self.assertRaises(OpenBaoError), material_transaction():
            try:
                with transaction.atomic():
                    self.rotate()
                    raise ValueError('Framework rejected final object permissions.')
            except ValueError:
                pass
        self.assert_original()
        self.assertEqual(FakeBackend.delete_calls, [(self.credential.path, (2,))])

    def test_unowned_ambient_transaction_refuses_before_backend_write(self):
        with transaction.atomic(), patch.object(FakeBackend, 'write') as write, self.assertRaises(OpenBaoError):
            self.rotate()
        write.assert_not_called()

    def test_concurrent_version_is_preserved_during_compensation(self):
        original_delete = FakeBackend.delete

        def concurrent_write_then_delete(backend, path, versions=None):
            backend.write(path, {'password': 'concurrent-value'}, cas=2)
            return original_delete(backend, path, versions)

        with patch.object(FakeBackend, 'delete', autospec=True, side_effect=concurrent_write_then_delete), \
                self.assertRaises(ValueError), material_transaction():
            self.rotate()
            raise ValueError('Owner persistence failed.')
        self.assert_original()
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=3),
                         {'password': 'concurrent-value'})

    def test_caught_service_failure_poisoning_rolls_back_prior_success(self):
        with self.assertRaises(OpenBaoError), material_transaction():
            self.rotate()
            with patch.object(FakeBackend, 'write', side_effect=OpenBaoError('Write refused.')):
                try:
                    self.rotate('refused-value')
                except OpenBaoError:
                    pass
        self.assert_original()
        self.assertEqual(FakeBackend.delete_calls, [(self.credential.path, (2,))])

    def test_promotion_metadata_outage_keeps_live_and_staged_versions(self):
        stage_material(self.credential, {'password': 'staged-value'})
        with patch.object(FakeBackend, 'list_versions', side_effect=OpenBaoError('Metadata unavailable.')), \
                self.assertRaises(OpenBaoError):
            promote_staged(self.credential)
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, 2))
        self.assertTrue(CredentialAccessLog.objects.filter(action='promote', success=False).exists())

    def test_discard_backend_failure_reports_committed_cleanup_incomplete(self):
        stage_material(self.credential, {'password': 'staged-value'})
        with patch.object(FakeBackend, 'delete', side_effect=OpenBaoError('Delete unavailable.')), \
                self.assertRaisesMessage(OpenBaoError, 'Discard committed; cleanup is incomplete'):
            discard_staged(self.credential)
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, None))
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=2), {'password': 'staged-value'})
        self.assertTrue(CredentialAccessLog.objects.filter(
            action='discard', success=False, message__contains='Discard committed;', resolved_version=2,
        ).exists())

    def test_discard_deferred_commit_failure_preserves_pointer_and_material(self):
        stage_material(self.credential, {'password': 'staged-value'})
        with self.assertRaises(IntegrityError), material_transaction():
            discard_staged(self.credential)
            CredentialAccessLog.objects.create(credential_id=2147483647, action='write')
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, 2))
        self.assertEqual(FakeBackend.delete_calls, [])
        self.assertEqual(FakeBackend(self.engine).read(self.credential.path, version=2), {'password': 'staged-value'})

    def test_discard_unknown_commit_does_not_delete_or_restore_a_guessed_pointer(self):
        stage_material(self.credential, {'password': 'staged-value'})
        original_commit = connection.commit

        def lost_acknowledgement():
            original_commit()
            raise OperationalError('The commit acknowledgement is unavailable.')

        with patch.object(connection, 'commit', side_effect=lost_acknowledgement), \
                self.assertRaises(OperationalError):
            discard_staged(self.credential)
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, None))
        self.assertEqual(FakeBackend.delete_calls, [])
        self.assertTrue(CredentialAccessLog.objects.filter(
            resolved_version=2, success=False, message__contains='Discard outcome unknown',
        ).exists())
