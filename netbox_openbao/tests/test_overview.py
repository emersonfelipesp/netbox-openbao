"""OpenBao overview collection, normalization, transport, and UI tests."""

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from core.models import ObjectType
from django.core.cache import cache
from django.urls import reverse
from users.models import ObjectPermission

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.backends import BrokerAdministrationBackend, DirectAdministrationBackend
from netbox_openbao.administration.broker import CONTRACT_DIGEST, EXPECTED_FAMILIES, EXPECTED_OPERATIONS
from netbox_openbao.administration.cluster import (
    MAX_CLUSTER_JSON_BYTES,
    HANode,
    HAStatus,
    LeaderStatus,
    MetricsSnapshot,
    RaftConfiguration,
    RaftPeer,
    SealStatus,
    collect_cluster_state,
    normalize_metrics,
)
from netbox_openbao.administration.schema import CapabilitySchemaError
from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoAuthError,
    OpenBaoUnavailable,
)
from netbox_openbao.choices import BackendChoices
from netbox_openbao.models import OpenBaoCluster, SecretEngine
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase, _Response

FIXTURE = Path(__file__).with_name('data') / 'openbao-2.6.0-sys-metrics.json'


class MetricsNormalizationTest(TestCase):
    def test_real_openbao_fixture_is_allowlisted(self):
        snapshot = normalize_metrics(json.loads(FIXTURE.read_text()))

        self.assertEqual(snapshot.timestamp, '2026-11-25 14:41:10 +0000 UTC')
        self.assertEqual(snapshot.unsealed, 1)
        self.assertEqual(snapshot.auth_mounts, 1)
        self.assertEqual(snapshot.secret_mounts, 4)
        self.assertEqual(snapshot.audit_request_failures, 3)
        self.assertFalse(hasattr(snapshot, 'runtime.gc_pause_ns'))

    def test_unknown_names_and_object_keys_are_ignored(self):
        result = normalize_metrics({
            '__proto__': {'polluted': True},
            'constructor': 'ignored',
            'Gauges': [{'Name': '__proto__', 'Value': 'not inspected'}],
            'Counters': [{'Name': 'constructor', 'Count': False}],
        })
        self.assertEqual(result, MetricsSnapshot(timestamp=''))

    def test_invalid_payload_and_collection_shapes_are_rejected(self):
        invalid = (1, [], {'Gauges': {}}, {'Gauges': 'bad'}, {'Counters': {}}, {'Counters': 'bad'})
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                normalize_metrics(payload)

    def test_invalid_entries_and_names_are_rejected(self):
        for entry in (1, 'bad', {'Name': 1}, {'Name': None}):
            with self.subTest(entry=entry), self.assertRaises(CapabilitySchemaError):
                normalize_metrics({'Gauges': [entry]})

    def test_invalid_allowlisted_values_are_rejected(self):
        for value in (True, '1', float('nan'), float('inf'), -1):
            with self.subTest(value=value), self.assertRaises(CapabilitySchemaError):
                normalize_metrics({'Gauges': [{'Name': 'vault.core.active', 'Value': value}]})
            with self.subTest(count=value), self.assertRaises(CapabilitySchemaError):
                normalize_metrics({'Counters': [{
                    'Name': 'vault.audit.log_request_failure', 'Count': value,
                }]})

    def test_oversized_metric_collection_is_rejected(self):
        with self.assertRaises(CapabilitySchemaError):
            normalize_metrics({'Gauges': [{'Name': 'unknown'}] * 5_001})

    def test_hostile_allowlisted_labels_and_numbers_are_rejected(self):
        cases = (
            {'Gauges': [{'Name': 'vault.core.mount_table.num_entries', 'Labels': {'type': []}, 'Value': 1}]},
            {'Gauges': [{'Name': 'vault.core.mount_table.num_entries', 'Labels': [], 'Value': 1}]},
            {'Gauges': [{'Name': 'vault.core.active', 'Value': 10**400}]},
            {'Counters': [{'Name': 'vault.audit.log_request_failure', 'Count': 10**400}]},
            {'Gauges': [
                {'Name': 'vault.core.mount_table.num_entries', 'Labels': {'type': 'auth'}, 'Value': 2**63},
                {'Name': 'vault.core.mount_table.num_entries', 'Labels': {'type': 'auth'}, 'Value': 1},
            ]},
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                normalize_metrics(payload)


class CollectClusterStateTest(TestCase):
    def backend(self, *, sealed, initialized=True, storage_type='raft', ha_enabled=True):
        backend = Mock()
        backend.seal_status.return_value = SealStatus(
            initialized, sealed, 3, 5, 0, '2.6.2', 'shamir', False, False,
            storage_type, 'cluster', 'cluster-id',
        )
        backend.leader_status.return_value = LeaderStatus(
            ha_enabled, True, 'https://leader/', '', '', 20, 19,
        )
        backend.ha_status.return_value = HAStatus(nodes=())
        backend.raft_configuration.return_value = RaftConfiguration(index=1, peers=())
        return backend

    def test_sealed_state_requests_only_seal_status(self):
        backend = self.backend(sealed=True)
        state = collect_cluster_state(backend, timeout=5)
        self.assertIsNone(state['leader'])
        backend.seal_status.assert_called_once_with(timeout=5)
        backend.leader_status.assert_not_called()
        backend.ha_status.assert_not_called()
        backend.raft_configuration.assert_not_called()

    def test_unsealed_raft_state_requests_leader_ha_and_raft(self):
        backend = self.backend(sealed=False)
        state = collect_cluster_state(backend, timeout=5)
        self.assertIsNotNone(state['ha'])
        self.assertIsNotNone(state['raft'])
        backend.leader_status.assert_called_once_with(timeout=5)
        backend.ha_status.assert_called_once_with(timeout=5)
        backend.raft_configuration.assert_called_once_with(timeout=5)

    def test_disabled_ha_and_non_raft_skip_dependent_reads(self):
        backend = self.backend(sealed=False, storage_type='file', ha_enabled=False)
        state = collect_cluster_state(backend)
        self.assertIsNone(state['ha'])
        self.assertIsNone(state['raft'])


class DirectMetricsBackendTest(OpenBaoAdministrationTestCase):
    def test_metrics_uses_fixed_authenticated_path_and_timeout(self):
        backend = DirectAdministrationBackend(self.cluster)
        session = Mock()
        session.request.return_value = _Response(json.dumps({'Gauges': []}).encode())
        client = Mock(token='ephemeral-token')

        with patch.object(backend.backend, '_get_client', return_value=client), \
                patch.object(backend.backend, '_get_session', return_value=session):
            result = backend.metrics(timeout=5)

        self.assertEqual(result, MetricsSnapshot(timestamp=''))
        call = session.request.call_args
        self.assertEqual(call.args, ('GET', 'https://bao.example.net:8200/v1/sys/metrics'))
        self.assertEqual(call.kwargs['timeout'], 5)
        self.assertEqual(call.kwargs['headers']['X-Vault-Token'], 'ephemeral-token')

    def test_broker_backend_does_not_advertise_metrics(self):
        with self.assertRaises(BackendConfigurationError):
            BrokerAdministrationBackend(self.cluster).metrics(timeout=5)

    def test_metrics_transport_accepts_limit_and_rejects_one_byte_more(self):
        valid = b'{"Gauges":[]}'
        bodies = (
            (valid + b' ' * (MAX_CLUSTER_JSON_BYTES - len(valid)), False),
            (valid + b' ' * (MAX_CLUSTER_JSON_BYTES + 1 - len(valid)), True),
        )
        for body, rejected in bodies:
            with self.subTest(rejected=rejected):
                backend = DirectAdministrationBackend(self.cluster)
                session = Mock()
                session.request.return_value = _Response(body)
                with patch.object(backend.backend, '_get_client', return_value=Mock(token='token')), \
                        patch.object(backend.backend, '_get_session', return_value=session):
                    if rejected:
                        with self.assertRaises(OpenBaoUnavailable):
                            backend.metrics()
                    else:
                        self.assertEqual(backend.metrics(), MetricsSnapshot(timestamp=''))

    @patch('hvac.Client')
    def test_factory_timeout_reaches_cold_hvac_client_and_default(self, hvac_client):
        from netbox_openbao.administration.backends import get_administration_backend

        for timeout, expected in ((5, 5), (None, 30)):
            with self.subTest(timeout=timeout):
                backend = get_administration_backend(self.cluster, timeout=timeout)
                cache.delete(backend.backend._cache_key)
                client = Mock()
                hvac_client.return_value = client
                with patch.object(backend.backend, '_login', return_value=('token', 60)):
                    backend.backend._get_client()
                self.assertEqual(hvac_client.call_args.kwargs['timeout'], expected)

    def test_broker_administration_timeout_bounds_contract_and_execute(self):
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        self.cluster.api_url = 'https://broker.example.net:8201'
        backend = BrokerAdministrationBackend(self.cluster, timeout=5)
        contract = {
            'version': '1', 'digest': CONTRACT_DIGEST,
            'families': sorted(EXPECTED_FAMILIES),
            'operations': [
                {'name': name, 'family': family, 'framing': framing}
                for name, family, framing in EXPECTED_OPERATIONS
            ],
        }
        responses = [_Response(json.dumps(contract).encode()), _Response(b'{"data":{"initialized":true}}')]
        session = Mock()
        session.request.side_effect = responses
        with patch.object(backend.backend, '_get_session', return_value=session):
            self.assertTrue(backend.initialization_status())
        self.assertEqual([call.kwargs['timeout'] for call in session.request.call_args_list], [5, 5])
        self.assertTrue(all('broker.example.net' in call.args[1] for call in session.request.call_args_list))
        self.assertTrue(all('/v1/administration/' in call.args[1] for call in session.request.call_args_list))

    def test_broker_detail_reads_forward_the_capped_timeout(self):
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        self.cluster.api_url = 'https://broker.example.net:8201'
        backend = BrokerAdministrationBackend(self.cluster, timeout=5)
        backend.client._contract_verified = True
        leader = {'ha_enabled': True, 'is_self': True, 'leader_address': '', 'leader_cluster_address': '',
                  'active_time': '', 'raft_committed_index': 1, 'raft_applied_index': 1}
        session = Mock()
        session.request.side_effect = [
            _Response(json.dumps({'data': leader}).encode()),
            _Response(json.dumps({'data': {'nodes': []}}).encode()),
            _Response(json.dumps({'data': {'config': {'index': 1, 'servers': []}}}).encode()),
        ]
        with patch.object(backend.backend, '_get_session', return_value=session):
            backend.leader_status(timeout=0.4)
            backend.ha_status(timeout=0.3)
            backend.raft_configuration(timeout=0.2)
        self.assertEqual([call.kwargs['timeout'] for call in session.request.call_args_list], [0.4, 0.3, 0.2])
        self.assertTrue(all('broker.example.net' in call.args[1] for call in session.request.call_args_list))


class FakeOverviewBackend:
    def __init__(self, cluster, *, sealed=False, initialized=True, storage_type='raft', ha_enabled=True):
        self.cluster = cluster
        self.calls = []
        self.seal = SealStatus(
            initialized, sealed, 3, 5, 1, '2.6.2', 'shamir', False, False,
            storage_type, 'overview-cluster', 'cluster-id',
        )
        self.ha_enabled = ha_enabled

    def health(self):
        # The card must not call the 30-second health probe; the node role is
        # derived from the seal and leader state it already reads.
        raise AssertionError('The overview card must not call health().')

    def seal_status(self, *, timeout=None):
        self.calls.append(('seal', timeout))
        return self.seal

    def leader_status(self, *, timeout=None):
        self.calls.append(('leader', timeout))
        return LeaderStatus(self.ha_enabled, True, 'https://leader/', '', 'now', 42, 41)

    def ha_status(self, *, timeout=None):
        self.calls.append(('ha', timeout))
        return HAStatus(nodes=(HANode('bao-1', 'https://bao-1/', '', True, 'now', '2.6.2'),))

    def raft_configuration(self, *, timeout=None):
        self.calls.append(('raft', timeout))
        return RaftConfiguration(index=24, peers=(RaftPeer('node-1', '127.0.0.1:8201', True, True, '3'),))

    def metrics(self, *, timeout=None):
        self.calls.append(('metrics', timeout))
        return MetricsSnapshot(timestamp='now', alloc_bytes=1024, audit_request_failures=1)


class OverviewViewTest(OpenBaoAdministrationTestCase):
    def setUp(self):
        super().setUp()
        self.engine = SecretEngine.objects.create(
            name='Overview engine', slug='overview-engine', cluster=self.cluster,
            api_url='https://bao.example.net:8200',
        )
        self.overview_url = reverse('plugins:netbox_openbao:overview')
        self.card_url = reverse(
            'plugins:netbox_openbao:overview_cluster_card', kwargs={'pk': self.cluster.pk}
        )
        self.client.force_login(self.user)

    def test_anonymous_overview_and_card_redirect_to_login(self):
        self.client.logout()
        for url in (self.overview_url, self.card_url):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertIn('/login/', response['Location'])

    @patch('netbox_openbao.views.get_administration_backend')
    def test_constrained_discover_permission_returns_404_without_backend(self, get_backend):
        permission = ObjectPermission(
            name='other-cluster-discover', actions=['discover'], constraints={'slug': 'other-cluster'},
        )
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ObjectType.objects.get_for_model(OpenBaoCluster))
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 404)
        get_backend.assert_not_called()

    @patch('netbox_openbao.views.get_administration_backend')
    def test_root_overview_is_database_only_and_no_store(self, get_backend):
        self.add_permissions('netbox_openbao.view_openbaocluster', 'netbox_openbao.view_secretengine')
        response = self.client.get(self.overview_url)
        self.assertEqual(self.overview_url, '/plugins/openbao/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.cluster.name)
        self.assertContains(response, self.engine.name)
        self.assertIn('no-store', response['Cache-Control'])
        get_backend.assert_not_called()

    def test_user_without_view_permission_gets_empty_state_without_names(self):
        response = self.client.get(self.overview_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No OpenBao clusters are visible')
        self.assertNotContains(response, self.cluster.name)
        self.assertNotContains(response, self.engine.name)

    def test_object_permission_constraint_excludes_cluster(self):
        permission = ObjectPermission(
            name='other-cluster-view', actions=['view'], constraints={'slug': 'other-cluster'},
        )
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ObjectType.objects.get_for_model(OpenBaoCluster))
        response = self.client.get(self.overview_url)
        self.assertNotContains(response, self.cluster.name)

    def test_engine_cluster_name_is_redacted_without_cluster_visibility(self):
        hidden = OpenBaoCluster.objects.create(
            name='Hidden cluster canary', slug='hidden-cluster', api_url='https://hidden.invalid:8200'
        )
        SecretEngine.objects.create(
            name='Hidden cluster engine', slug='hidden-cluster-engine', cluster=hidden,
            api_url='https://hidden.invalid:8200',
        )
        permission = ObjectPermission(
            name='primary-cluster-view', actions=['view'], constraints={'slug': self.cluster.slug},
        )
        permission.save()
        permission.users.add(self.user)
        permission.object_types.add(ObjectType.objects.get_for_model(OpenBaoCluster))
        self.add_permissions('netbox_openbao.view_secretengine')
        response = self.client.get(self.overview_url)
        self.assertContains(response, self.cluster.name)
        self.assertNotContains(response, hidden.name)
        self.assertContains(response, 'Restricted cluster')

    @patch('netbox_openbao.views.get_administration_backend')
    def test_card_without_discover_permission_never_calls_backend(self, get_backend):
        self.add_permissions('netbox_openbao.view_openbaocluster')
        response = self.client.get(self.card_url)
        self.assertIn(response.status_code, (403, 404))
        get_backend.assert_not_called()

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_sealed_card_skips_leader_ha_raft_and_metrics(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster, sealed=True)
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Sealed')
        self.assertNotIn(('leader', 5), backend.calls)
        self.assertNotIn(('metrics', 5), backend.calls)
        self.assertIn('no-store', response['Cache-Control'])

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_unsealed_card_renders_live_state_and_metrics(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        for text in ('Unsealed', 'HA nodes', 'Raft peers', 'node-1', '1.0 KB', 'audit log'):
            self.assertContains(response, text)
        self.assertContains(response, 'Active')
        self.assertIn(('metrics', 5), backend.calls)
        get_backend.assert_called_once_with(self.cluster, timeout=5)

    @patch('netbox_openbao.views.time.monotonic', side_effect=[0, 13, 13, 13])
    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_deadline_skips_later_reads_and_keeps_seal(self, get_backend, _log, _monotonic):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Unsealed')
        self.assertContains(response, 'Leader, HA, and Raft details are unavailable.')
        self.assertContains(response, 'Metrics are unavailable.')
        self.assertEqual(backend.calls, [('seal', 5)])

    @patch('netbox_openbao.views.time.monotonic', side_effect=[0, 10, 11, 11.5, 11.9, 11.9])
    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_each_read_is_capped_by_the_remaining_budget(self, get_backend, _log, _monotonic):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        timeouts = dict(backend.calls)
        self.assertEqual(timeouts['seal'], 5)
        self.assertAlmostEqual(timeouts['leader'], 2)
        self.assertAlmostEqual(timeouts['ha'], 1)
        self.assertAlmostEqual(timeouts['raft'], 0.5)
        self.assertAlmostEqual(timeouts['metrics'], 0.1)

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_unavailable_backend_is_scrubbed(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        get_backend.side_effect = OpenBaoUnavailable('upstream diagnostic canary')
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenBao is unavailable.')
        self.assertNotContains(response, 'diagnostic canary')

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_metrics_auth_error_does_not_hide_seal_state(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        backend.metrics = Mock(side_effect=OpenBaoAuthError('server text', 403))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertContains(response, 'Unsealed')
        self.assertContains(response, "policy does not grant read on sys/metrics")
        self.assertNotContains(response, 'server text')
        self.assertEqual(
            _log.call_args.kwargs['message'],
            'Rendered the OpenBao overview cluster card (details: ok; metrics: policy-denied)',
        )

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_real_direct_metrics_schema_failure_degrades_only_metrics(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = DirectAdministrationBackend(self.cluster, timeout=5)
        seal = FakeOverviewBackend(self.cluster).seal
        backend.seal_status = Mock(return_value=seal)
        backend.leader_status = Mock(return_value=LeaderStatus(False, True, '', '', '', 0, 0))
        backend.raft_configuration = Mock(return_value=RaftConfiguration(index=1, peers=()))
        response_body = json.dumps({
            'Gauges': [{'Name': 'vault.core.mount_table.num_entries', 'Labels': {'type': []}, 'Value': 1}]
        }).encode()
        session = Mock()
        session.request.return_value = _Response(response_body)
        backend.backend._get_session = Mock(return_value=session)
        backend.backend._get_client = Mock(return_value=Mock(token='token'))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Unsealed')
        self.assertContains(response, 'Metrics are unavailable.')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(_log.call_args.kwargs['success'], True)

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_broker_metrics_are_reported_as_unsupported(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        self.cluster.save()
        backend = FakeOverviewBackend(self.cluster)
        backend.metrics = Mock(side_effect=BackendConfigurationError('unsupported'))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertContains(response, 'Metrics are not available through the broker.')

    @patch('netbox_openbao.views.log_administration', side_effect=AdministrationAuditError())
    @patch('netbox_openbao.views.get_administration_backend')
    def test_audit_failure_hides_collected_state(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        get_backend.return_value = FakeOverviewBackend(self.cluster)
        response = self.client.get(self.card_url)
        self.assertContains(response, 'OpenBao is unavailable.')
        self.assertNotContains(response, 'overview-cluster')

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_detail_auth_error_keeps_seal_state(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        backend.leader_status = Mock(side_effect=OpenBaoAuthError('policy canary', 403))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Unsealed')
        self.assertContains(response, 'does not grant the leader, HA, or Raft status reads')
        self.assertNotContains(response, 'policy canary')
        self.assertNotContains(response, 'OpenBao is unavailable.')
        self.assertEqual(sum(1 for call in backend.calls if call == ('seal', 5)), 1)

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_detail_unavailable_keeps_seal_state(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        backend.raft_configuration = Mock(side_effect=OpenBaoUnavailable('raft canary'))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertContains(response, 'Unsealed')
        self.assertContains(response, 'Leader, HA, and Raft details are unavailable.')
        self.assertNotContains(response, 'raft canary')

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_seal_status_failure_fails_the_card(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        backend.seal_status = Mock(side_effect=OpenBaoUnavailable('seal canary'))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenBao is unavailable.')
        self.assertNotContains(response, 'seal canary')

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_standby_node_role(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        backend = FakeOverviewBackend(self.cluster)
        backend.leader_status = Mock(return_value=LeaderStatus(True, False, 'https://leader/', '', 'now', 7, 7))
        get_backend.return_value = backend
        response = self.client.get(self.card_url)
        self.assertContains(response, 'Standby')

    @patch('netbox_openbao.views.log_administration')
    @patch('netbox_openbao.views.get_administration_backend')
    def test_administration_tab_uses_shared_collector_gating(self, get_backend, _log):
        self.add_permissions('netbox_openbao.discover_openbaocluster')
        url = reverse(
            'plugins:netbox_openbao:openbaocluster_administration', kwargs={'pk': self.cluster.pk}
        )
        cases = (
            ({'initialized': False, 'storage_type': ''}, [('seal', None)]),
            ({'sealed': True}, [('seal', None)]),
            ({'storage_type': 'file', 'ha_enabled': False}, [('seal', None), ('leader', None)]),
            ({}, [('seal', None), ('leader', None), ('ha', None), ('raft', None)]),
        )
        for options, calls in cases:
            with self.subTest(options=options):
                backend = FakeOverviewBackend(self.cluster, **options)
                get_backend.return_value = backend
                with patch('netbox_openbao.views.reverse', return_value='/api/'):
                    response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(backend.calls, calls)
