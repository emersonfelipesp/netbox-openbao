"""The provider on real KV v2, through both direct and mTLS broker transport."""

import os
import socket
import unittest
from dataclasses import replace
from unittest.mock import patch

from django.core.cache import cache
from django.test import TransactionTestCase, override_settings

from netbox_openbao import backends
from netbox_openbao.automation import AutomationResolutionDenied, capture_reference_identity, resolve_automation
from netbox_openbao.backends import get_backend
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoError
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.models import AutomationResolutionReceipt, CredentialAccessLog
from netbox_openbao.services import discard_staged, promote_staged, stage_material, write_material

from .test_automation import CANARY, _AutomationFixture
from .test_automation_key_identity import new_ssh_material

DIRECT_ADDR = os.environ.get('NETBOX_OPENBAO_TEST_ADDR')
DIRECT_TOKEN = os.environ.get('NETBOX_OPENBAO_TEST_TOKEN')
BROKER_ADDR = os.environ.get('NETBOX_OPENBAO_BROKER_ADDR')
BROKER_CERT = os.environ.get('NETBOX_OPENBAO_BROKER_CERT')
BROKER_KEY = os.environ.get('NETBOX_OPENBAO_BROKER_KEY')
BROKER_CA = os.environ.get('NETBOX_OPENBAO_BROKER_CA')


class _LiveProviderFixture(_AutomationFixture):
    def test_real_discard_commit_rejection_preserves_staged_material(self):
        from django.db import IntegrityError

        from netbox_openbao.material_transactions import material_transaction

        stage_material(self.credential, {'password': 'discard-candidate'})
        with self.assertRaises(IntegrityError), material_transaction():
            discard_staged(self.credential)
            CredentialAccessLog.objects.create(credential_id=2147483647, action='discard')
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, 2))
        backend = get_backend(self.engine, self.policy)
        self.assertEqual(backend.read(self.credential.path, version=1), {'password': CANARY})
        self.assertEqual(backend.read(self.credential.path, version=2), {'password': 'discard-candidate'})

    def test_real_discard_cleanup_failure_preserves_live_and_reports_committed_state(self):
        stage_material(self.credential, {'password': 'discard-candidate'})
        backend = get_backend(self.engine, self.policy)
        with patch.object(type(backend), 'delete', side_effect=OpenBaoError('Cleanup unavailable.')), \
                self.assertRaisesMessage(OpenBaoError, 'Discard committed; cleanup is incomplete'):
            discard_staged(self.credential)
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.live_kv_version, self.credential.staged_kv_version), (1, None))
        self.assertEqual(backend.read(self.credential.path, version=1), {'password': CANARY})
        self.assertEqual(backend.read(self.credential.path, version=2), {'password': 'discard-candidate'})
        self.assertTrue(CredentialAccessLog.objects.filter(
            resolved_version=2, success=False, message__contains='Discard committed;',
        ).exists())

    def test_real_outer_commit_failure_removes_only_its_version(self):
        from django.db import IntegrityError

        from netbox_openbao.material_transactions import material_transaction
        from netbox_openbao.models import CredentialAccessLog

        with self.assertRaises(IntegrityError), material_transaction():
            write_material(self.credential, {'password': 'uncommitted-version'}, cas=1)
            CredentialAccessLog.objects.create(credential_id=2147483647, action='write')
        self.credential.refresh_from_db()
        self.assertEqual((self.credential.kv_version, self.credential.live_kv_version), (1, 1))
        backend = get_backend(self.engine, self.policy)
        self.assertEqual(backend.read(self.credential.path, version=1), {'password': CANARY})
        with self.assertRaises(OpenBaoError):
            backend.read(self.credential.path, version=2)
        self.assertTrue(CredentialAccessLog.objects.filter(
            credential_uuid_snapshot=self.credential.uuid, resolved_version=2, success=False,
            message__contains='exact version was removed',
        ).exists())

    def test_protected_public_rpc_flow_to_real_provider(self):
        from .protected_dispatch import protected_bundle_round_trip

        protected_bundle_round_trip(self)

    broker_mode = False

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = OpenBaoBackend
        prefix = self.engine.env_prefix
        environment = {f'{prefix}_TOKEN': DIRECT_TOKEN or ''}
        self.engine.auth_method = 'token'
        self.engine.api_url = DIRECT_ADDR
        if self.broker_mode:
            self.engine.backend = 'broker'
            self.engine.api_url = BROKER_ADDR
            self.engine.ca_cert_path = BROKER_CA or ''
            environment.update({
                f'{prefix}_CLIENT_CERT': BROKER_CERT,
                f'{prefix}_CLIENT_KEY': BROKER_KEY,
            })
        self.engine.save()
        environment_patch = patch.dict(os.environ, environment)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        self.credential.engine = self.engine
        backend = get_backend(self.engine, self.policy)
        self.addCleanup(backend.delete, self.credential.path)
        write_material(self.credential, {'password': CANARY}, cas=0)
        self.authority = replace(
            self.authority,
            provider_identity=capture_reference_identity(
                reference=self.authority.reference, initiating_actor=self.actor,
                target_object=self.target, reason=self.authority.reason,
            ),
        )

    def test_real_live_read_does_not_serve_staged_version(self):
        stage_material(self.credential, {'password': 'live-suite-staged-canary'})
        result = self.resolve()
        self.assertEqual(result['resolved_version'], 1)
        self.assertEqual(result['fields'], {'password': CANARY})
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))

    def test_signed_rpc_admission_to_real_bundle_and_replay_refusal(self):
        self.prepare_ssh_bundle()
        execution = self.issue_real_dispatch()
        result = resolve_automation(self.request, self.params)
        self.assertEqual(result['resolved_version'], 2)
        self.assertEqual(result['fields']['passphrase'], CANARY)
        audit = CredentialAccessLog.objects.get(pk=result['access_log_id'])
        self.assertEqual((audit.user_id, audit.executor_id, audit.execution_id),
                         (self.actor.pk, self.executor.pk, execution.pk))
        with self.assertRaises(AutomationResolutionDenied):
            resolve_automation(self.request, self.params)
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))

    def test_signed_rpc_identity_substitution_is_refused_before_vault_read(self):
        self.issue_real_dispatch()
        type(self.credential).objects.filter(pk=self.credential.pk).update(username='substituted-identity')
        with self.assertRaises(AutomationResolutionDenied):
            resolve_automation(self.request, self.params)
        self.assertFalse(AutomationResolutionReceipt.objects.exists())

    def test_real_signed_key_lifecycle_with_public_display_disabled(self):
        with patch('netbox_openbao.secrets.registry.get_config', return_value=False):
            original = self.prepare_ssh_bundle()
            replacement = new_ssh_material()
            self.issue_real_dispatch()
            stage_material(self.credential, {'private_key': replacement, 'passphrase': CANARY})
            self.assertEqual(resolve_automation(self.request, self.params)['fields']['private_key'], original)
            discard_staged(self.credential)
            self.issue_real_dispatch()
            stage_material(self.credential, {'private_key': replacement, 'passphrase': CANARY})
            promote_staged(self.credential)
            with self.assertRaises(AutomationResolutionDenied):
                resolve_automation(self.request, self.params)
            self.issue_real_dispatch()
            result = resolve_automation(self.request, self.params)
        self.assertEqual(result['fields']['private_key'], replacement)
        self.assertEqual(result['resolved_version'], 4)
        self.assertEqual(self.credential.fingerprint, '')
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))

    def test_real_cas_conflict_preserves_existing_live_material(self):
        backend = get_backend(self.engine, self.policy)
        with self.assertRaises(OpenBaoConflict):
            backend.write(self.credential.path, {'password': 'cas-conflict-canary'}, cas=0)
        self.assertEqual(self.resolve()['fields'], {'password': CANARY})

    def test_real_deleted_version_fails_closed_and_receipt_prevents_retry(self):
        backend = get_backend(self.engine, self.policy)
        backend.delete(self.credential.path, versions=[1])
        with self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
        with self.assertRaises(AutomationResolutionDenied):
            self.resolve()

    def test_real_success_cannot_be_replayed(self):
        self.resolve()
        with self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.assertEqual(CredentialAccessLog.objects.filter(execution_id=91, success=True).count(), 1)

    def test_real_encrypted_key_and_passphrase_share_one_version(self):
        material = self.prepare_ssh_bundle()
        result = self.resolve()
        self.assertEqual(result['resolved_version'], 2)
        self.assertEqual(result['fields'], {'private_key': material, 'passphrase': CANARY})
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))

    def test_real_transport_outage_spends_receipt_without_exposing_material(self):
        # A bound but non-listening loopback socket produces a real connection
        # refusal. No production address or mocked backend participates.
        with socket.socket() as unavailable:
            unavailable.bind(('127.0.0.1', 0))
            scheme = 'https' if self.broker_mode else 'http'
            address = f'{scheme}://127.0.0.1:{unavailable.getsockname()[1]}'
            type(self.engine).objects.filter(pk=self.engine.pk).update(api_url=address)
            self.authority = replace(
                self.authority, provider_identity=capture_reference_identity(
                    reference=self.authority.reference, initiating_actor=self.actor,
                    target_object=self.target, reason=self.authority.reason,
                ),
            )
            with self.assertRaises(AutomationResolutionDenied) as caught:
                self.resolve()
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)


@unittest.skipUnless(DIRECT_ADDR and DIRECT_TOKEN, 'A real disposable OpenBao endpoint is not configured.')
@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class DirectAutomationProviderTest(_LiveProviderFixture, TransactionTestCase):
    """Exact provider behavior against a real OpenBao KV v2 server."""

    def test_real_invalid_vault_token_is_refused_and_spends_receipt(self):
        # The fixture's successful write has already populated the real token
        # cache. Expire that exact local entry so the next login uses the
        # deliberately invalid token instead of the earlier valid one.
        cache_key = get_backend(self.engine, self.policy)._cache_key
        cache.delete(cache_key)
        self.addCleanup(cache.delete, cache_key)
        with patch.dict(os.environ, {f'{self.engine.env_prefix}_TOKEN': 'invalid-disposable-test-token'}):
            with self.assertRaises(AutomationResolutionDenied):
                self.resolve()
        cache.delete(cache_key)
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
        with self.assertRaises(AutomationResolutionDenied):
            self.resolve()


@unittest.skipUnless(BROKER_ADDR and BROKER_CERT and BROKER_KEY, 'A real mTLS broker endpoint is not configured.')
@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class BrokerAutomationProviderTest(_LiveProviderFixture, TransactionTestCase):
    """The same provider cases through the actual broker and TLS boundary."""

    broker_mode = True

    def test_real_broker_path_policy_denial_spends_receipt(self):
        # This is a local metadata fixture only. The actual broker must refuse
        # the path before it can contact OpenBao, even with valid client TLS.
        type(self.credential).objects.filter(pk=self.credential.pk).update(
            path=f'denied-test-prefix/credentials/{self.credential.uuid}',
        )
        self.authority = replace(self.authority, provider_identity=capture_reference_identity(
            reference=self.authority.reference, initiating_actor=self.actor,
            target_object=self.target, reason=self.authority.reason,
        ))
        with self.assertRaises(AutomationResolutionDenied):
            self.resolve()
        self.assertEqual(AutomationResolutionReceipt.objects.count(), 1)
        self.assertNotIn(CANARY, str(list(CredentialAccessLog.objects.values())))
