"""Administrative cluster, transport, API, UI, permission, and audit tests."""

import json
from unittest.mock import patch

from django.urls import reverse
from users.models import ObjectPermission
from utilities.testing import APITestCase

from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.administration.backends import (
    BrokerAdministrationBackend,
    DirectAdministrationBackend,
    get_administration_backend,
)
from netbox_openbao.administration.schema import CapabilityDocument, DiscoveredOperation
from netbox_openbao.backends.exceptions import BackendConfigurationError, OpenBaoUnavailable
from netbox_openbao.choices import BackendChoices
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster, SecretEngine


def _capability_document():
    return CapabilityDocument(
        openapi_version='3.0.2',
        product_version='2.6.2',
        digest='a' * 64,
        operations=(
            DiscoveredOperation(
                operation_id='sysHealth',
                method='GET',
                path_template='/sys/health',
                summary='Read health',
                tags=('system',),
                family='cluster',
                risk_level='read',
                response_class='public-metadata',
                required_permission='netbox_openbao.discover_openbaocluster',
                classified=True,
            ),
        ),
    )


class FakeAdministrationBackend:
    def __init__(self, cluster):
        self.cluster = cluster

    def health(self):
        return {'status': 'healthy', 'message': 'OpenBao is active.'}

    def discover_capabilities(self):
        return _capability_document()


class FailingAdministrationBackend(FakeAdministrationBackend):
    def discover_capabilities(self):
        raise OpenBaoUnavailable('upstream secret diagnostic')


class OpenBaoAdministrationTestCase(APITestCase):

    def setUp(self):
        super().setUp()
        self.cluster = OpenBaoCluster.objects.create(
            name='Primary cluster',
            slug='primary-cluster',
            api_url='https://bao.example.net:8200',
        )

    def capabilities_api_url(self):
        return reverse(
            'plugins-api:netbox_openbao-api:openbaocluster-capabilities',
            kwargs={'pk': self.cluster.pk},
        )

    def capabilities_ui_url(self):
        return reverse(
            'plugins:netbox_openbao:openbaocluster_capabilities',
            kwargs={'pk': self.cluster.pk},
        )


class OpenBaoClusterModelTest(OpenBaoAdministrationTestCase):

    def test_cluster_has_no_auth_material_fields(self):
        names = {field.name for field in OpenBaoCluster._meta.get_fields()}
        for forbidden in ('role_id', 'secret_id', 'token', 'password', 'private_key'):
            self.assertNotIn(forbidden, names)

    def test_cluster_env_prefix_is_derived_from_slug(self):
        self.assertEqual(self.cluster.env_prefix, 'NETBOX_BAO_PRIMARY_CLUSTER')

    def test_engine_can_reference_a_cluster(self):
        engine = SecretEngine.objects.create(
            name='KV',
            slug='kv',
            api_url='https://bao.example.net:8200',
            cluster=self.cluster,
        )

        self.assertEqual(engine.cluster, self.cluster)

    def test_administration_log_exposes_only_a_view_permission(self):
        self.assertEqual(OpenBaoAdministrationLog._meta.default_permissions, ('view',))


class _RawBody:
    def __init__(self, body):
        self.body = body

    def read(self, maximum, decode_content=False):
        del decode_content
        return self.body[:maximum]


class _Response:
    def __init__(self, body, status_code=200):
        self.status_code = status_code
        self.raw = _RawBody(body)
        self.closed = False

    def close(self):
        self.closed = True


class AdministrationBackendTest(OpenBaoAdministrationTestCase):

    @patch('netbox_openbao.administration.backends.OpenBaoBackend._get_session')
    @patch('netbox_openbao.administration.backends.OpenBaoBackend._get_client')
    def test_direct_discovery_uses_fixed_safe_request_contract(self, get_client, get_session):
        document = {
            'openapi': '3.0.2',
            'info': {'version': '2.6.2'},
            'paths': {
                '/v1/sys/health': {
                    'get': {
                        'operationId': 'sysHealth',
                        'summary': 'Read health',
                        'tags': ['system'],
                    },
                },
            },
        }
        response = _Response(json.dumps(document).encode())
        get_client.return_value.token = 'ephemeral-token'
        get_session.return_value.get.return_value = response
        self.cluster.namespace = 'team-a'

        discovered = DirectAdministrationBackend(self.cluster).discover_capabilities()

        self.assertEqual(discovered.product_version, '2.6.2')
        self.assertFalse(discovered.operations[0].executable)
        get_session.return_value.get.assert_called_once_with(
            'https://bao.example.net:8200/v1/sys/internal/specs/openapi',
            headers={
                'X-Vault-Request': 'true',
                'X-Vault-Token': 'ephemeral-token',
                'X-Vault-Namespace': 'team-a',
            },
            params={'generic_mount_paths': 'true'},
            verify=True,
            timeout=30,
            allow_redirects=False,
            stream=True,
        )
        self.assertTrue(response.closed)

    @patch('netbox_openbao.administration.backends.OpenBaoBackend._get_session')
    @patch('netbox_openbao.administration.backends.OpenBaoBackend._get_client')
    def test_direct_discovery_scrubs_invalid_upstream_content(self, get_client, get_session):
        get_client.return_value.token = None
        response = _Response(b'{"server_secret":')
        get_session.return_value.get.return_value = response

        with self.assertRaisesRegex(
            OpenBaoUnavailable,
            '^OpenBao returned an invalid capability document\\.$',
        ):
            DirectAdministrationBackend(self.cluster).discover_capabilities()

        request_headers = get_session.return_value.get.call_args.kwargs['headers']
        self.assertNotIn('X-Vault-Token', request_headers)
        self.assertTrue(response.closed)

    def test_factory_selects_direct_and_broker_transports(self):
        self.assertIsInstance(
            get_administration_backend(self.cluster),
            DirectAdministrationBackend,
        )
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        broker = get_administration_backend(self.cluster)
        self.assertIsInstance(broker, BrokerAdministrationBackend)
        with self.assertRaisesRegex(
            BackendConfigurationError,
            'does not advertise the administrative capability contract',
        ):
            broker.discover_capabilities()


class AdministrationAPITest(OpenBaoAdministrationTestCase):

    def test_view_permission_does_not_grant_capability_discovery(self):
        self.add_permissions('netbox_openbao.view_openbaocluster')

        response = self.client.get(self.capabilities_api_url(), **self.header)

        self.assertEqual(response.status_code, 404)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_discovery_is_bounded_non_executable_audited_and_not_storable(self, get_backend):
        get_backend.side_effect = FakeAdministrationBackend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
        )

        response = self.client.get(self.capabilities_api_url(), **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertFalse(response.data['operations'][0]['executable'])
        self.assertEqual(response.data['operations'][0]['operation_key'], 'GET /sys/health')
        self.assertNotIn('upstream secret diagnostic', response.content.decode())
        entry = OpenBaoAdministrationLog.objects.get(action='discover-capabilities')
        self.assertTrue(entry.success)
        self.assertEqual(entry.capability_digest, 'a' * 64)
        self.assertEqual(entry.username_snapshot, self.user.username)
        self.cluster.refresh_from_db()
        self.assertEqual(self.cluster.openbao_version, '2.6.2')
        self.assertEqual(self.cluster.capability_digest, 'a' * 64)
        self.assertIsNotNone(self.cluster.capabilities_checked)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_upstream_failure_returns_only_a_fixed_error_and_is_audited(self, get_backend):
        get_backend.side_effect = FailingAdministrationBackend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
        )

        response = self.client.get(self.capabilities_api_url(), **self.header)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data['detail'], 'OpenBao administration is unavailable.')
        self.assertNotIn('upstream secret diagnostic', response.content.decode())
        entry = OpenBaoAdministrationLog.objects.get(action='discover-capabilities')
        self.assertFalse(entry.success)
        self.assertEqual(entry.message, 'OpenBao administration is unavailable.')

    @patch(
        'netbox_openbao.administration.observations.log_administration',
        side_effect=AdministrationAuditError('database diagnostic'),
    )
    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_audit_failure_rolls_back_observed_capability_metadata(self, get_backend, _log):
        get_backend.side_effect = FakeAdministrationBackend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
        )

        response = self.client.get(self.capabilities_api_url(), **self.header)

        self.assertEqual(response.status_code, 503)
        self.cluster.refresh_from_db()
        self.assertEqual(self.cluster.openbao_version, '')
        self.assertEqual(self.cluster.capability_digest, '')
        self.assertIsNone(self.cluster.capabilities_checked)

    @patch('netbox_openbao.api.views.get_administration_backend')
    def test_health_updates_safe_observed_metadata(self, get_backend):
        get_backend.side_effect = FakeAdministrationBackend
        self.add_permissions('netbox_openbao.view_openbaocluster')
        url = reverse(
            'plugins-api:netbox_openbao-api:openbaocluster-health',
            kwargs={'pk': self.cluster.pk},
        )

        response = self.client.get(url, **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('no-store', response['Cache-Control'])
        self.cluster.refresh_from_db()
        self.assertEqual(self.cluster.status, 'healthy')
        self.assertEqual(self.cluster.status_message, 'OpenBao is active.')
        self.assertIsNotNone(self.cluster.last_checked)

    def test_administration_log_api_is_read_only(self):
        log_administration(self.cluster, self.user, action='health')
        self.add_permissions('netbox_openbao.view_openbaoadministrationlog')
        url = reverse('plugins-api:netbox_openbao-api:openbaoadministrationlog-list')

        self.assertEqual(self.client.get(url, **self.header).status_code, 200)
        self.assertIn(
            self.client.post(url, {}, format='json', **self.header).status_code,
            (403, 405),
        )

    def test_log_serializer_contains_no_connection_or_auth_material(self):
        log_administration(self.cluster, self.user, action='health')
        self.add_permissions('netbox_openbao.view_openbaoadministrationlog')
        url = reverse('plugins-api:netbox_openbao-api:openbaoadministrationlog-list')

        response = self.client.get(url, **self.header)

        rendered = response.content.decode()
        for forbidden in ('role_id', 'secret_id', 'client_token', 'request_body', 'response_body'):
            self.assertNotIn(forbidden, rendered)


class AdministrationUITest(OpenBaoAdministrationTestCase):

    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_view_permission_does_not_grant_ui_discovery(self):
        self.add_permissions('netbox_openbao.view_openbaocluster')

        response = self.client.get(self.capabilities_ui_url())

        self.assertIn(response.status_code, (403, 404))

    @patch('netbox_openbao.views.get_administration_backend')
    def test_ui_discovery_is_escaped_audited_and_not_storable(self, get_backend):
        document = _capability_document()
        hostile_operation = DiscoveredOperation(
            operation_id='safeIdentifier',
            method='GET',
            path_template='/safe/{name}',
            summary='<script>alert(1)</script>',
            tags=('example',),
            family='unclassified',
            risk_level='read',
            response_class='unreviewed',
            required_permission='',
            classified=False,
        )
        document = CapabilityDocument(
            openapi_version=document.openapi_version,
            product_version=document.product_version,
            digest=document.digest,
            operations=(hostile_operation,),
        )
        backend = FakeAdministrationBackend(self.cluster)
        backend.discover_capabilities = lambda: document
        get_backend.return_value = backend
        self.add_permissions(
            'netbox_openbao.view_openbaocluster',
            'netbox_openbao.discover_openbaocluster',
        )

        response = self.client.get(self.capabilities_ui_url())

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertNotContains(response, '<script>alert(1)</script>')
        self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')
        self.assertContains(response, 'safeIdentifier')
        self.assertContains(response, '<td>No</td>', html=True)
        self.assertTrue(OpenBaoAdministrationLog.objects.filter(success=True).exists())


class AdministrationAuditFailureTest(OpenBaoAdministrationTestCase):

    @patch('netbox_openbao.models.OpenBaoAdministrationLog.objects.create')
    def test_audit_write_failure_raises_a_fixed_error(self, create):
        create.side_effect = RuntimeError('database diagnostic')

        with self.assertRaisesRegex(
            AdministrationAuditError,
            '^OpenBao administration access could not be audited\\.$',
        ):
            log_administration(self.cluster, self.user, action='health')


class ConstrainedAdministrationPermissionTest(OpenBaoAdministrationTestCase):

    def test_discovery_constraint_hides_other_clusters(self):
        permission = ObjectPermission(
            name='primary-cluster-discovery',
            actions=['view', 'discover'],
            constraints={'slug': 'another-cluster'},
        )
        permission.save()
        permission.users.add(self.user)
        from core.models import ObjectType

        permission.object_types.add(
            ObjectType.objects.get(app_label='netbox_openbao', model='openbaocluster')
        )

        response = self.client.get(self.capabilities_api_url(), **self.header)

        self.assertEqual(response.status_code, 404)
