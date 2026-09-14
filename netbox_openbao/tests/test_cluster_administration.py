"""Typed cluster-state and fixed administrative transport tests."""

import base64
import json
from io import BytesIO
from unittest import TestCase
from unittest.mock import Mock, patch

from django.db import transaction
from django.test import Client
from django.urls import reverse
from users.models import ObjectPermission

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.backends import BrokerAdministrationBackend, DirectAdministrationBackend
from netbox_openbao.administration.cluster import (
    MAX_SNAPSHOT_BYTES,
    BoundedSnapshotReader,
    HANode,
    HAStatus,
    InitializationResult,
    LeaderStatus,
    RaftConfiguration,
    RaftPeer,
    SealStatus,
    SnapshotDownload,
    normalize_ha_status,
    normalize_initialization_result,
    normalize_leader_status,
    normalize_raft_configuration,
    normalize_seal_status,
)
from netbox_openbao.administration.schema import CapabilitySchemaError
from netbox_openbao.backends.exceptions import BackendConfigurationError, OpenBaoConflict, OpenBaoUnavailable
from netbox_openbao.choices import BackendChoices
from netbox_openbao.models import OpenBaoAdministrationLog
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase, _Response

TEST_PGP_PUBLIC_KEY = (
    'xo0EaqhRJQEEAKGCcczkRrA7c5kI39ZOy14hcWqq6Kq24rdOgjq/Kq6b1B4DLDZms5F/BET7NVHGIilRz074WBIOJFNG4ijW/'
    'MUmm0VUHgNxoP4QtSByMtlh3dD2PzXqpxOsG8xqa0XMSojUaPtcne8NRjlbxTH5FJQRdZMCadpKhoIFnPY7LLcxABEBAAHNF0'
    '5ldEJveCBPcGVuQmFvIFRlc3QgS2V5wsACBBMBCAAsBQJqqFElAhsMAgsJAhUIAhYCAh4BFiEEJMT8/r95ddW/NPozU8y6Tjb'
    'TDgQACgkQU8y6TjbTDgQvNQP+LLEzSF455Itat19ddhWdb9gzeP0YlzBW3i9xgKg/brOdPRTR4znwLPYMzkrfEKuaSMoOkre'
    '3EbrvFk/Emh77sRv4LIYP1MigQr0U4zVPrvsrZd/jN67+uj21hZQs4+pyfcOh5VmM2xs7SNDVvPy1lbebgWgOMVPltbT4nRcK'
    'gL8='
)

TEST_PGP_SIGNING_ONLY_KEY = (
    'xo0EaqhRkQEEAKZ/txD1YIVEAkotsEAz2TaCxcNOO6et1KrJI0+VnXByvV0z63putpQDHsa/iObS7qZp777G/Wd677fZfDqU'
    'hw2wrzByNSBBuHDj6Ewr+LPkLzC+D6P2vw3o2UjHHjYhtCg0v39WiYbrUcHM3tsWe+c72/GOnoGwEVlX9Oo4Cc5hABEBAAHN'
    'G05ldEJveCBPcGVuQmFvIFNpZ25pbmcgVGVzdMK8BBMBCAAmBQJqqFGRAhsCAhUIAh4BFiEEgxm104xc3biqZ70KBQZkCyJlW'
    'bEACgkQBQZkCyJlWbHxJwP+IqN6zbGi4jdNnYNA4qGHEBiw7f3VQ5/T0lAZMSVCvvGxY1DXYE2Be0VM54kZxXhhXK1cS9YNX'
    'lqdyr0X3vOhP7th4xapdKDvqtEmahSNtuOFxn1cGF/zxUu5xfYhI3XvobcBmtXBsNoYIAVfqb2iN3xH7mTqeItFSnZ1AAySH8'
    'o='
)


class ClusterStateSchemaTest(TestCase):

    def test_seal_status_is_typed_and_bounded(self):
        result = normalize_seal_status({
            'initialized': True,
            'sealed': True,
            't': 3,
            'n': 5,
            'progress': 2,
            'version': '2.6.2',
            'type': 'shamir',
            'migration': False,
            'recovery_seal': False,
            'storage_type': 'raft',
            'cluster_name': 'openbao-cluster',
            'cluster_id': 'cluster-id',
        })

        self.assertTrue(result.initialized)
        self.assertTrue(result.sealed)
        self.assertEqual(result.threshold, 3)
        self.assertEqual(result.progress, 2)
        self.assertEqual(result.storage_type, 'raft')

    def test_malformed_seal_status_is_rejected(self):
        with self.assertRaisesRegex(CapabilitySchemaError, 'sealed state'):
            normalize_seal_status({'initialized': True, 'sealed': 'yes'})

    def test_leader_and_ha_status_are_normalized(self):
        leader = normalize_leader_status({
            'ha_enabled': True,
            'is_self': False,
            'leader_address': 'https://bao-1.example.net:8200/',
            'leader_cluster_address': 'https://bao-1.example.net:8201/',
            'active_time': '2026-09-14T12:00:00Z',
            'raft_committed_index': 42,
            'raft_applied_index': 41,
        })
        ha = normalize_ha_status({'Nodes': [{
            'hostname': 'bao-1',
            'api_address': 'https://bao-1.example.net:8200',
            'cluster_address': 'https://bao-1.example.net:8201',
            'active_node': True,
            'last_echo': None,
            'version': '2.6.2',
        }]})

        self.assertEqual(leader.raft_committed_index, 42)
        self.assertEqual(ha.nodes[0].hostname, 'bao-1')
        self.assertTrue(ha.nodes[0].active_node)

    def test_raft_peers_are_unique_and_typed(self):
        payload = {'data': {'config': {'index': 24, 'servers': [{
            'node_id': 'raft1',
            'address': '127.0.0.1:8201',
            'leader': True,
            'voter': True,
            'protocol_version': '\x03',
        }]}}}

        result = normalize_raft_configuration(payload)

        self.assertEqual(result.index, 24)
        self.assertEqual(result.peer('raft1').address, '127.0.0.1:8201')
        self.assertEqual(result.peer('raft1').protocol_version, '3')
        payload['data']['config']['servers'].append(dict(payload['data']['config']['servers'][0]))
        with self.assertRaisesRegex(CapabilitySchemaError, 'duplicate Raft node IDs'):
            normalize_raft_configuration(payload)

    def test_cluster_display_strings_reject_controls(self):
        with self.assertRaisesRegex(CapabilitySchemaError, 'cluster name'):
            normalize_seal_status({
                'initialized': True,
                'sealed': True,
                'cluster_name': 'unsafe\nname',
            })

    def test_initialization_result_repr_is_always_redacted(self):
        result = normalize_initialization_result({
            'keys': ['key-canary'],
            'keys_base64': ['base64-canary'],
            'root_token': 'token-canary',
        })

        self.assertEqual(repr(result), '<InitializationResult redacted>')
        self.assertNotIn('canary', repr(result))
        self.assertEqual(result.as_dict()['root_token'], 'token-canary')

    def test_snapshot_upload_reader_rejects_truncated_and_oversized_chunks(self):
        truncated = BoundedSnapshotReader(BytesIO(b'short'), 8)
        self.assertEqual(truncated.read(8), b'short')
        with self.assertRaisesRegex(ValueError, 'ended before its declared size'):
            truncated.read(3)

        oversized_stream = Mock(read=Mock(return_value=b'too-long'))
        oversized = BoundedSnapshotReader(oversized_stream, 8)
        with self.assertRaisesRegex(ValueError, 'requested chunk size'):
            oversized.read(4)


class DirectClusterAdministrationBackendTest(OpenBaoAdministrationTestCase):

    def setUp(self):
        super().setUp()
        self.backend = DirectAdministrationBackend(self.cluster)
        self.client = Mock(token='ephemeral-token')
        self.session = Mock()

    def response(self, payload=None, *, status_code=200):
        body = b'' if payload is None else json.dumps(payload).encode()
        return _Response(body, status_code=status_code)

    def seal_payload(self, **overrides):
        payload = {
            'initialized': True,
            'sealed': True,
            't': 3,
            'n': 5,
            'progress': 1,
            'version': '2.6.2',
            'type': 'shamir',
            'migration': False,
            'recovery_seal': False,
            'storage_type': 'raft',
        }
        payload.update(overrides)
        return payload

    def patch_transport(self):
        return (
            patch.object(self.backend.backend, '_get_client', return_value=self.client),
            patch.object(self.backend.backend, '_get_session', return_value=self.session),
        )

    def test_unauthenticated_status_never_sends_a_token(self):
        self.session.request.return_value = self.response(self.seal_payload())
        client_patch, session_patch = self.patch_transport()

        with client_patch as get_client, session_patch:
            result = self.backend.seal_status()

        self.assertTrue(result.sealed)
        get_client.assert_not_called()
        call = self.session.request.call_args
        self.assertEqual(call.args, ('GET', 'https://bao.example.net:8200/v1/sys/seal-status'))
        self.assertEqual(call.kwargs['headers'], {'X-Vault-Request': 'true'})
        self.assertFalse(call.kwargs['allow_redirects'])

    def test_initialization_material_is_returned_only_to_the_caller(self):
        self.session.request.side_effect = (
            self.response({'initialized': False}),
            self.response({'keys': ['key-canary'], 'root_token': 'token-canary'}),
        )
        client_patch, session_patch = self.patch_transport()

        with client_patch as get_client, session_patch:
            self.assertFalse(self.backend.initialization_status())
            result = self.backend.initialize({'secret_shares': 1, 'secret_threshold': 1})

        get_client.assert_not_called()
        self.assertEqual(result.as_dict()['keys'], ['key-canary'])
        self.assertEqual(self.session.request.call_args.kwargs['json']['secret_threshold'], 1)

    def test_unseal_share_is_sent_without_authentication(self):
        self.session.request.return_value = self.response(self.seal_payload(progress=2))
        client_patch, session_patch = self.patch_transport()

        with client_patch as get_client, session_patch:
            result = self.backend.unseal(key='share-canary')

        get_client.assert_not_called()
        self.assertEqual(result.progress, 2)
        self.assertEqual(self.session.request.call_args.kwargs['json']['key'], 'share-canary')

    def test_authenticated_mutation_uses_fixed_path_and_scrubbed_conflict(self):
        self.session.request.return_value = self.response(
            {'errors': ['secret-upstream-diagnostic']},
            status_code=400,
        )
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch, self.assertRaises(OpenBaoConflict) as raised:
            self.backend.remove_raft_peer('raft2')

        self.assertNotIn('secret-upstream-diagnostic', str(raised.exception))
        call = self.session.request.call_args
        self.assertEqual(call.args, ('POST', 'https://bao.example.net:8200/v1/sys/storage/raft/remove-peer'))
        self.assertEqual(call.kwargs['json'], {'server_id': 'raft2'})
        self.assertEqual(call.kwargs['headers']['X-Vault-Token'], 'ephemeral-token')
        self.assertTrue(self.session.request.return_value.closed)

    def test_broker_transport_refuses_cluster_operations(self):
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        backend = BrokerAdministrationBackend(self.cluster)

        with self.assertRaisesRegex(BackendConfigurationError, 'does not advertise'):
            backend.seal_status()

    def test_snapshot_download_is_bounded_and_streamed(self):
        response = self.response()
        response.headers = {'Content-Length': '8'}
        response.raw.stream = Mock(return_value=iter((b'snap', b'shot')))
        self.session.request.return_value = response
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch:
            snapshot = self.backend.download_raft_snapshot()
            body = b''.join(snapshot.chunks())

        self.assertEqual(body, b'snapshot')
        self.assertEqual(snapshot.declared_size, 8)
        self.assertTrue(response.closed)
        call = self.session.request.call_args
        self.assertEqual(call.args, ('GET', 'https://bao.example.net:8200/v1/sys/storage/raft/snapshot'))
        self.assertTrue(call.kwargs['stream'])
        self.assertEqual(call.kwargs['headers']['Accept-Encoding'], 'identity')

    def test_snapshot_download_refuses_encoded_upstream_body(self):
        response = self.response()
        response.headers = {'Content-Encoding': 'gzip', 'Content-Length': '8'}
        self.session.request.return_value = response
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch, self.assertRaises(OpenBaoUnavailable):
            self.backend.download_raft_snapshot()

        self.assertTrue(response.closed)

    def test_snapshot_restore_uses_raw_bounded_body_and_fixed_path(self):
        self.session.request.return_value = self.response()
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch:
            self.backend.restore_raft_snapshot(Mock(read=Mock(return_value=b'snapshot')), 8, force=True)

        call = self.session.request.call_args
        self.assertEqual(call.args, ('POST', 'https://bao.example.net:8200/v1/sys/storage/raft/snapshot-force'))
        self.assertEqual(call.kwargs['headers']['Content-Type'], 'application/octet-stream')
        self.assertEqual(call.kwargs['headers']['Content-Length'], '8')
        self.assertEqual(len(call.kwargs['data']), 8)

    def test_snapshot_download_refuses_oversized_declared_body(self):
        response = self.response()
        response.headers = {'Content-Length': str(MAX_SNAPSHOT_BYTES + 1)}
        self.session.request.return_value = response
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch, self.assertRaises(OpenBaoUnavailable):
            self.backend.download_raft_snapshot()

        self.assertTrue(response.closed)

    def test_snapshot_download_closes_upstream_when_caller_cancels(self):
        response = self.response()
        response.headers = {}
        response.raw.stream = Mock(return_value=iter((b'first', b'second')))
        self.session.request.return_value = response
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch:
            snapshot = self.backend.download_raft_snapshot()
            chunks = snapshot.chunks()
            self.assertEqual(next(chunks), b'first')
            chunks.close()

        self.assertTrue(response.closed)

    def test_snapshot_download_rejects_declared_length_mismatch(self):
        response = Mock()
        response.raw.stream.return_value = iter((b'short',))
        snapshot = SnapshotDownload(response, 8)

        with self.assertRaisesRegex(ValueError, 'declared size'):
            list(snapshot.chunks())

        response.close.assert_called_once_with()

    def test_snapshot_restore_transport_failure_is_not_retried(self):
        self.session.request.side_effect = OSError('snapshot-canary')
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch, self.assertRaises(OpenBaoUnavailable) as raised:
            self.backend.restore_raft_snapshot(Mock(read=Mock(return_value=b'snapshot')), 8)

        self.assertEqual(self.session.request.call_count, 1)
        self.assertNotIn('snapshot-canary', str(raised.exception))


class FakeLifecycleBackend:
    def __init__(self, cluster):
        self.cluster = cluster
        self.initialized = False
        self.calls = []
        self.seal_state = SealStatus(
            initialized=True,
            sealed=True,
            threshold=3,
            shares=5,
            progress=1,
            version='2.6.2',
            seal_type='shamir',
            migration=False,
            recovery_seal=False,
            storage_type='raft',
            cluster_name='openbao-cluster',
            cluster_id='cluster-id',
        )
        self.leader = LeaderStatus(
            ha_enabled=True,
            is_self=True,
            leader_address='https://bao.example.net:8200/',
            leader_cluster_address='https://bao.example.net:8201/',
            active_time='2026-09-14T12:00:00Z',
            raft_committed_index=42,
            raft_applied_index=42,
        )
        self.ha = HAStatus(nodes=(HANode(
            hostname='bao-1',
            api_address='https://bao.example.net:8200',
            cluster_address='https://bao.example.net:8201',
            active_node=True,
            last_echo='',
            version='2.6.2',
        ),))
        self.raft = RaftConfiguration(index=24, peers=(
            RaftPeer('raft1', '127.0.0.1:8201', True, True, '3'),
            RaftPeer('raft2', '127.0.0.2:8201', False, True, '3'),
            RaftPeer('raft3', '127.0.0.3:8201', False, True, '3'),
            RaftPeer('raft4', '127.0.0.4:8201', False, True, '3'),
        ))

    def initialization_status(self):
        return self.initialized

    def seal_status(self):
        return self.seal_state

    def leader_status(self):
        return self.leader

    def ha_status(self):
        return self.ha

    def raft_configuration(self):
        return self.raft

    def initialize(self, payload):
        self.calls.append(('initialize', payload))
        return InitializationResult(
            keys=('key-canary',),
            keys_base64=(),
            recovery_keys=(),
            recovery_keys_base64=(),
            root_token='token-canary',
        )

    def unseal(self, **payload):
        self.calls.append(('unseal', payload))
        return SealStatus(**{**self.seal_state.as_dict(), 'progress': 2})

    def seal(self):
        self.calls.append(('seal', None))

    def remove_raft_peer(self, server_id):
        self.calls.append(('remove-peer', server_id))

    def download_raft_snapshot(self):
        response = Mock()
        response.headers = {'Content-Length': '8'}
        response.raw.stream.return_value = iter((b'snap', b'shot'))
        return SnapshotDownload(response, 8)

    def restore_raft_snapshot(self, stream, size, *, force=False):
        remaining = size
        while remaining:
            chunk = stream.read(min(remaining, 64 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
        self.calls.append(('restore-snapshot', {'size': size, 'force': force}))


class ClusterAdministrationAPITest(OpenBaoAdministrationTestCase):

    def url(self, action):
        return reverse(
            f'plugins-api:netbox_openbao-api:openbaocluster-{action}',
            kwargs={'pk': self.cluster.pk},
        )

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_state_is_permissioned_audited_and_not_storable(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
        )

        response = self.client.get(self.url('state'), **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(response.data['raft']['index'], 24)
        self.assertEqual(response.data['ha']['nodes'][0]['hostname'], 'bao-1')
        self.assertTrue(OpenBaoAdministrationLog.objects.get(action='cluster-state').success)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_initialization_requires_exact_confirmation_and_returns_material_once(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'initialized': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )
        payload = {
            'secret_shares': 1,
            'secret_threshold': 1,
            'reason': 'Commission the new cluster.',
            'confirmation': f'INITIALIZE {self.cluster.slug}',
        }
        response = self.client.post(self.url('initialize'), payload, format='json', **self.header)

        self.assertEqual(response.status_code, 201, response.content)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(response.data['keys'], ['key-canary'])
        self.assertEqual(response.data['root_token'], 'token-canary')
        self.assertNotIn('reason', backend.calls[0][1])
        self.assertNotIn('confirmation', backend.calls[0][1])
        audit_text = ' '.join(
            str(value)
            for entry in OpenBaoAdministrationLog.objects.all().values()
            for value in entry.values()
        )
        self.assertNotIn('key-canary', audit_text)
        self.assertNotIn('token-canary', audit_text)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_stale_initialization_is_refused(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.initialized = True
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )

        response = self.client.post(self.url('initialize'), {
            'secret_shares': 1,
            'secret_threshold': 1,
            'reason': 'Commission the new cluster.',
            'confirmation': f'INITIALIZE {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_initialization_accepts_zero_recovery_shares_and_rejects_bad_pgp_cardinality(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'initialized': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )
        base = {
            'recovery_shares': 0,
            'recovery_threshold': 0,
            'reason': 'Commission the auto-unseal cluster.',
            'confirmation': f'INITIALIZE {self.cluster.slug}',
        }

        accepted = self.client.post(self.url('initialize'), base, format='json', **self.header)
        rejected = self.client.post(
            self.url('initialize'),
            {
                **base,
                'recovery_shares': 2,
                'recovery_threshold': 1,
                'recovery_pgp_keys': [TEST_PGP_PUBLIC_KEY],
            },
            format='json',
            **self.header,
        )

        self.assertEqual(accepted.status_code, 201, accepted.content)
        self.assertEqual(backend.calls[0][1]['recovery_shares'], 0)
        self.assertEqual(backend.calls[0][1]['recovery_threshold'], 0)
        self.assertEqual(rejected.status_code, 400)
        self.assertIn('exactly one PGP key', rejected.content.decode())
        self.assertEqual(len(backend.calls), 1)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_initialization_rejects_malformed_openpgp_exports_before_backend_call(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'initialized': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )
        base = {
            'secret_shares': 1,
            'secret_threshold': 1,
            'reason': 'Commission the new cluster.',
            'confirmation': f'INITIALIZE {self.cluster.slug}',
        }

        valid_export = base64.b64decode(TEST_PGP_PUBLIC_KEY)
        invalid_ecdh = b'\xc6\x0d\x04\x00\x00\x00\x00\x12\x01\xff\x00\x00\x03\x01\x08\x09'
        invalid_exports = (
            '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            base64.b64encode(b'not-pgp').decode(),
            'xgA=',
            'xgoEAAAAAAEAAAAA',
            'xgwEAAAAAAEABREAAgPCAQA=',
            base64.b64encode(b'\xc6\x0c\x04\x00').decode(),
            base64.b64encode(b'\xc6\x0c\x04\x00\x00\x00\x00\x00\x00\x05\x11\x00\x02\x03').decode(),
            base64.b64encode(invalid_ecdh).decode(),
            TEST_PGP_SIGNING_ONLY_KEY,
            base64.b64encode(valid_export + b'\xc2\x01\x00').decode(),
            base64.b64encode(valid_export + b'\xce\x01\x04').decode(),
            base64.b64encode(b'\xcd\x03uid' + valid_export).decode(),
            base64.b64encode(valid_export + b'trailing-garbage').decode(),
        )

        for value in invalid_exports:
            with self.subTest(value=value):
                response = self.client.post(
                    self.url('initialize'),
                    {**base, 'root_token_pgp_key': value},
                    format='json',
                    **self.header,
                )
                self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.log_administration')
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_post_initialization_audit_failure_never_withholds_custody_material(self, get_backend, audit):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'initialized': False})
        get_backend.return_value = backend
        audit.side_effect = (None, AdministrationAuditError('database diagnostic'))
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )

        response = self.client.post(self.url('initialize'), {
            'secret_shares': 1,
            'secret_threshold': 1,
            'reason': 'Commission the new cluster.',
            'confirmation': f'INITIALIZE {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['X-OpenBao-Audit-Status'], 'preflight-only')
        self.assertEqual(response['X-OpenBao-Operation-Outcome'], 'accepted-audit-incomplete')
        self.assertEqual(response.data['outcome'], 'accepted-audit-incomplete')
        self.assertEqual(response.data['root_token'], 'token-canary')

    @patch('netbox_openbao.api.views.log_administration')
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_post_unseal_audit_failure_reports_accepted_without_retry(self, get_backend, audit):
        backend = FakeLifecycleBackend(self.cluster)
        get_backend.return_value = backend
        audit.side_effect = (None, AdministrationAuditError('database diagnostic'))
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.unseal_openbaocluster',
        )

        response = self.client.post(self.url('unseal'), {
            'key': 'share-canary',
            'reason': 'Continue the approved unseal ceremony.',
            'confirmation': f'UNSEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['outcome'], 'accepted-audit-incomplete')
        self.assertEqual(backend.calls, [('unseal', {'key': 'share-canary', 'reset': False, 'migrate': False})])

    @patch('netbox_openbao.api.views.log_administration')
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_post_seal_audit_failure_reports_accepted_without_retry(self, get_backend, audit):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        audit.side_effect = (None, AdministrationAuditError('database diagnostic'))
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
        )

        response = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-OpenBao-Operation-Outcome'], 'accepted-audit-incomplete')
        self.assertEqual(backend.calls, [('seal', None)])

    @patch('netbox_openbao.api.views.log_administration')
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_post_remove_peer_audit_failure_reports_accepted_without_retry(self, get_backend, audit):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        audit.side_effect = (None, AdministrationAuditError('database diagnostic'))
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
        )

        response = self.client.post(self.url('remove-raft-peer'), {
            'server_id': 'raft4',
            'configuration_index': 24,
            'reason': 'Replace the failed peer.',
            'confirmation': f'REMOVE raft4 FROM {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['audit_status'], 'preflight-only')
        self.assertEqual(backend.calls, [('remove-peer', 'raft4')])

    @patch('netbox_openbao.api.views.log_administration')
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_post_restore_audit_failure_reports_accepted_without_retry(self, get_backend, audit):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        audit.side_effect = (None, AdministrationAuditError('database diagnostic'))
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )

        response = self.client.post(
            self.url('raft-snapshot-restore'),
            b'snapshot',
            content_type='application/octet-stream',
            HTTP_X_OPENBAO_REASON='Restore the reviewed recovery point.',
            HTTP_X_OPENBAO_CONFIRMATION=f'RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='24',
            **self.header,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['outcome'], 'accepted-audit-incomplete')
        self.assertEqual(backend.calls, [('restore-snapshot', {'size': 8, 'force': False})])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_unseal_share_is_not_returned_or_audited(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.unseal_openbaocluster',
        )

        response = self.client.post(self.url('unseal'), {
            'key': 'share-canary',
            'reason': 'Continue the approved unseal ceremony.',
            'confirmation': f'UNSEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn('share-canary', response.content.decode())
        audit_text = ' '.join(
            str(value)
            for entry in OpenBaoAdministrationLog.objects.all().values()
            for value in entry.values()
        )
        self.assertNotIn('share-canary', audit_text)
        self.assertEqual(backend.calls[0][1]['key'], 'share-canary')

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_seal_requires_fresh_unsealed_state(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
        )

        response = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(backend.calls, [('seal', None)])
        self.assertTrue(OpenBaoAdministrationLog.objects.filter(action='seal', success=True).exists())

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_unsupported_openbao_version_is_refused_before_mutation(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{
            **backend.seal_state.as_dict(),
            'sealed': False,
            'version': '2.6.1',
        })
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
        )

        response = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(backend.calls, [])

        backend.seal_state = SealStatus(**{
            **backend.seal_state.as_dict(),
            'version': '2.7.0',
        })
        future = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(future.status_code, 409)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_standby_refuses_seal_peer_removal_and_restore(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        backend.leader = LeaderStatus(**{**backend.leader.as_dict(), 'is_self': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
            'netbox_openbao.download_raft_snapshot_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )

        seal = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)
        remove = self.client.post(self.url('remove-raft-peer'), {
            'server_id': 'raft4',
            'configuration_index': 24,
            'reason': 'Replace the failed peer.',
            'confirmation': f'REMOVE raft4 FROM {self.cluster.slug}',
        }, format='json', **self.header)
        restore = self.client.post(
            self.url('raft-snapshot-restore'),
            b'snapshot',
            content_type='application/octet-stream',
            HTTP_X_OPENBAO_REASON='Restore the reviewed recovery point.',
            HTTP_X_OPENBAO_CONFIRMATION=f'RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='24',
            **self.header,
        )
        download = self.client.get(self.url('raft-snapshot'), **self.header)

        self.assertEqual(
            (seal.status_code, remove.status_code, restore.status_code, download.status_code),
            (409, 409, 409, 409),
        )
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_lifecycle_action_honors_dedicated_object_constraint(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions('netbox_openbao.view_openbaocluster')
        permission = ObjectPermission(
            name='other-cluster-seal',
            actions=['seal'],
            constraints={'slug': 'another-cluster'},
        )
        permission.save()
        permission.users.add(self.user)
        from core.models import ObjectType
        permission.object_types.add(
            ObjectType.objects.get(app_label='netbox_openbao', model='openbaocluster')
        )

        response = self.client.post(self.url('seal'), {
            'reason': 'Emergency containment.',
            'confirmation': f'SEAL {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_session_authenticated_mutation_requires_csrf(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)

        response = csrf_client.post(
            self.url('seal'),
            data=json.dumps({
                'reason': 'Emergency containment.',
                'confirmation': f'SEAL {self.cluster.slug}',
            }),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_mutation_refuses_ambient_transaction_before_backend_call(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.seal_openbaocluster',
        )

        with transaction.atomic():
            response = self.client.post(self.url('seal'), {
                'reason': 'Emergency containment.',
                'confirmation': f'SEAL {self.cluster.slug}',
            }, format='json', **self.header)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_session_authenticated_raw_restore_accepts_valid_csrf(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        csrf_token = 'a' * 32
        csrf_client.cookies['csrftoken'] = csrf_token

        response = csrf_client.post(
            self.url('raft-snapshot-restore'),
            data=b'snapshot',
            content_type='application/octet-stream',
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_X_OPENBAO_REASON='Restore the reviewed recovery point.',
            HTTP_X_OPENBAO_CONFIRMATION=f'RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='24',
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(backend.calls[-1], ('restore-snapshot', {'size': 8, 'force': False}))

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_remove_peer_rejects_stale_index_and_leader(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
        )
        base = {
            'server_id': 'raft2',
            'reason': 'Replace the failed peer.',
            'confirmation': f'REMOVE raft2 FROM {self.cluster.slug}',
        }

        stale = self.client.post(self.url('remove-raft-peer'), {
            **base,
            'configuration_index': 23,
        }, format='json', **self.header)
        leader = self.client.post(self.url('remove-raft-peer'), {
            **base,
            'server_id': 'raft1',
            'configuration_index': 24,
            'confirmation': f'REMOVE raft1 FROM {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(stale.status_code, 409)
        self.assertEqual(leader.status_code, 409)
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_remove_peer_succeeds_only_with_fresh_safe_configuration(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
        )

        response = self.client.post(self.url('remove-raft-peer'), {
            'server_id': 'raft4',
            'configuration_index': 24,
            'reason': 'Replace the failed peer.',
            'confirmation': f'REMOVE raft4 FROM {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(backend.calls, [('remove-peer', 'raft4')])
        self.assertEqual(response.data['configuration_index'], 24)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_remove_peer_rejects_three_voter_quorum_and_unknown_peer(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        backend.raft = RaftConfiguration(index=24, peers=backend.raft.peers[:3])
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
        )
        base = {
            'configuration_index': 24,
            'reason': 'Replace the failed peer.',
        }

        quorum = self.client.post(self.url('remove-raft-peer'), {
            **base,
            'server_id': 'raft2',
            'confirmation': f'REMOVE raft2 FROM {self.cluster.slug}',
        }, format='json', **self.header)
        unknown = self.client.post(self.url('remove-raft-peer'), {
            **base,
            'server_id': 'raft9',
            'confirmation': f'REMOVE raft9 FROM {self.cluster.slug}',
        }, format='json', **self.header)

        self.assertEqual((quorum.status_code, unknown.status_code), (409, 409))
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_snapshot_download_streams_with_safe_headers_and_audit(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.download_raft_snapshot_openbaocluster',
        )

        response = self.client.get(self.url('raft-snapshot'), **self.header)
        body = b''.join(response.streaming_content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body, b'snapshot')
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertTrue(OpenBaoAdministrationLog.objects.get(action='download-raft-snapshot').success)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_session_snapshot_download_rejects_get_and_requires_csrf_on_post(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.download_raft_snapshot_openbaocluster',
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)

        get_response = csrf_client.get(self.url('raft-snapshot'))
        post_response = csrf_client.post(self.url('raft-snapshot'), {
            'reason': 'Create the scheduled backup.',
            'confirmation': f'DOWNLOAD SNAPSHOT {self.cluster.slug}',
        })

        self.assertEqual((get_response.status_code, post_response.status_code), (405, 403))
        self.assertEqual(backend.calls, [])

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_session_snapshot_download_accepts_confirmed_csrf_post(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.download_raft_snapshot_openbaocluster',
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        csrf_token = 'a' * 32
        csrf_client.cookies['csrftoken'] = csrf_token

        response = csrf_client.post(
            self.url('raft-snapshot'),
            {
                'reason': 'Create the scheduled backup.',
                'confirmation': f'DOWNLOAD SNAPSHOT {self.cluster.slug}',
            },
            HTTP_X_CSRFTOKEN=csrf_token,
        )
        body = b''.join(response.streaming_content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body, b'snapshot')
        authorization = OpenBaoAdministrationLog.objects.get(action='download-raft-snapshot-authorized')
        self.assertEqual(authorization.method, 'POST')
        self.assertEqual(authorization.reason, 'Create the scheduled backup.')

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_snapshot_restore_requires_fresh_state_and_streams_without_audit_material(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )
        headers = {
            **self.header,
            'HTTP_X_OPENBAO_REASON': 'Restore the reviewed recovery point.',
            'HTTP_X_OPENBAO_CONFIRMATION': f'RESTORE SNAPSHOT {self.cluster.slug}',
            'HTTP_X_OPENBAO_CLUSTER_ID': 'cluster-id',
            'HTTP_X_OPENBAO_RAFT_INDEX': '24',
        }

        response = self.client.post(
            self.url('raft-snapshot-restore'),
            b'snapshot-canary',
            content_type='application/octet-stream',
            **headers,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(backend.calls[-1], ('restore-snapshot', {'size': 15, 'force': False}))
        self.assertIn('no-store', response['Cache-Control'])
        audit_text = ' '.join(
            str(value)
            for entry in OpenBaoAdministrationLog.objects.all().values()
            for value in entry.values()
        )
        self.assertNotIn('snapshot-canary', audit_text)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_snapshot_restore_refuses_stale_index_before_reading_body(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )

        response = self.client.post(
            self.url('raft-snapshot-restore'),
            b'snapshot-canary',
            content_type='application/octet-stream',
            HTTP_X_OPENBAO_REASON='Restore the reviewed recovery point.',
            HTTP_X_OPENBAO_CONFIRMATION=f'RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='23',
            **self.header,
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(backend.calls, [])

    def test_snapshot_restore_rejects_multipart_before_backend_access(self):
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )

        response = self.client.post(
            self.url('raft-snapshot-restore'),
            {'snapshot': 'snapshot-canary'},
            format='json',
            HTTP_X_OPENBAO_REASON='Restore the reviewed recovery point.',
            HTTP_X_OPENBAO_CONFIRMATION=f'RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='24',
            **self.header,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('application/octet-stream', response.content.decode())

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_force_restore_has_separate_permission_and_confirmation(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.force_restore_raft_snapshot_openbaocluster',
        )

        response = self.client.post(
            self.url('raft-snapshot-restore-force'),
            b'snapshot',
            content_type='application/octet-stream',
            HTTP_X_OPENBAO_REASON='Recover after verified seal-key loss.',
            HTTP_X_OPENBAO_CONFIRMATION=f'FORCE RESTORE SNAPSHOT {self.cluster.slug}',
            HTTP_X_OPENBAO_CLUSTER_ID='cluster-id',
            HTTP_X_OPENBAO_RAFT_INDEX='24',
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(backend.calls[-1], ('restore-snapshot', {'size': 8, 'force': True}))

    @patch('netbox_openbao.views.get_administration_backend')
    def test_web_administration_renders_guarded_raft_journey(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'sealed': False})
        backend.ha = HAStatus(nodes=(*backend.ha.nodes, HANode(
            hostname='<script>standby</script>',
            api_address='https://bao-2.example.net:8200',
            cluster_address='https://bao-2.example.net:8201',
            active_node=False,
            last_echo='2026-09-14T12:00:01Z',
            version='2.6.2',
        )))
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
            'netbox_openbao.remove_raft_peer_openbaocluster',
            'netbox_openbao.download_raft_snapshot_openbaocluster',
            'netbox_openbao.restore_raft_snapshot_openbaocluster',
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse(
            'plugins:netbox_openbao:openbaocluster_administration',
            kwargs={'pk': self.cluster.pk},
        ))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'HA nodes')
        self.assertContains(response, 'bao-1')
        self.assertContains(response, 'Active')
        self.assertContains(response, '&lt;script&gt;standby&lt;/script&gt;')
        self.assertNotContains(response, '<script>standby</script>')
        self.assertContains(response, 'Standby')
        self.assertContains(response, 'https://bao-2.example.net:8200')
        self.assertContains(response, 'https://bao-2.example.net:8201')
        self.assertContains(response, '2026-09-14T12:00:01Z')
        self.assertContains(response, 'Raft peers')
        self.assertContains(response, 'Download authenticated snapshot')
        self.assertContains(response, f'RESTORE SNAPSHOT {self.cluster.slug}')
        self.assertIn('no-store', response['Cache-Control'])

    @patch('netbox_openbao.views.get_administration_backend')
    def test_web_administration_renders_one_time_initialization_journey(self, get_backend):
        backend = FakeLifecycleBackend(self.cluster)
        backend.seal_state = SealStatus(**{**backend.seal_state.as_dict(), 'initialized': False})
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
            'netbox_openbao.initialize_openbaocluster',
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse(
            'plugins:netbox_openbao:openbaocluster_administration',
            kwargs={'pk': self.cluster.pk},
        ))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Initialize once')
        self.assertContains(response, f'INITIALIZE {self.cluster.slug}')
        self.assertNotContains(response, 'Download authenticated snapshot')
