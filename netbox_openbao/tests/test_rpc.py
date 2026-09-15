"""Behavioral tests for netbox-rpc integration."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.urls import reverse
from rest_framework.exceptions import PermissionDenied
from utilities.testing import APITestCase

from netbox_openbao.models import OpenBaoProcedureRun
from netbox_openbao.rpc import dispatch_openbao_procedure

from .base import OpenBaoTestCase

User = get_user_model()


def _make_device(name: str = 'openbao-host'):
    from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

    site, _ = Site.objects.get_or_create(name='OpenBao Test Site', slug='openbao-test-site')
    mfr, _ = Manufacturer.objects.get_or_create(name='OpenBao Test Mfr', slug='openbao-test-mfr')
    dtype, _ = DeviceType.objects.get_or_create(
        manufacturer=mfr, model='OpenBao Test Model', slug='openbao-test-model',
    )
    role, _ = DeviceRole.objects.get_or_create(name='OpenBao Test Role', slug='openbao-test-role')
    device, _ = Device.objects.get_or_create(
        name=name, defaults={'device_type': dtype, 'role': role, 'site': site},
    )
    return device


def _make_procedure(name: str = 'service.openbao.1.health'):
    from netbox_rpc.models import RPCProcedure

    proc, _ = RPCProcedure.objects.get_or_create(
        name=name,
        defaults={'handler_id': name, 'effect': RPCProcedure.EFFECT_READ},
    )
    return proc


def _grant_rpc_execute(user) -> None:
    from django.contrib.contenttypes.models import ContentType
    from netbox_rpc.models import RPCProcedure
    from users.models import ObjectPermission

    permission = ObjectPermission.objects.create(
        name=f'OpenBao RPC execution {user.pk}',
        actions=['execute'],
    )
    permission.users.add(user)
    permission.object_types.add(ContentType.objects.get_for_model(RPCProcedure))
    if hasattr(user, '_object_perm_cache'):
        del user._object_perm_cache


class DispatchOpenBaoProcedureTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('openbao-rpc', password='test')
        _grant_rpc_execute(self.user)
        self.device = _make_device()
        self.engine.host_device = self.device
        self.engine.save(update_fields=['host_device'])
        self.procedure = _make_procedure()

    def test_missing_host_device_raises_validation_error(self):
        self.engine.host_device = None
        self.engine.save(update_fields=['host_device'])

        with self.assertRaises(ValidationError) as ctx:
            dispatch_openbao_procedure(
                engine=self.engine,
                procedure_name='service.openbao.1.health',
                user=self.user,
            )
        self.assertIn('host_device', ctx.exception.message_dict)

    def test_disallowed_procedure_raises_validation_error(self):
        with self.assertRaises(ValidationError) as ctx:
            dispatch_openbao_procedure(
                engine=self.engine,
                procedure_name='service.openbao.1.destroy_everything',
                user=self.user,
            )
        self.assertIn('procedure', ctx.exception.message_dict)

    def test_engine_bound_params_cannot_be_overridden(self):
        with self.assertRaises(ValidationError) as ctx:
            dispatch_openbao_procedure(
                engine=self.engine,
                procedure_name='service.openbao.1.health',
                user=self.user,
                params={'mount': 'evil'},
            )
        self.assertIn('params', ctx.exception.message_dict)

    @patch('netbox_rpc.application.command_handlers.create_execution')
    def test_provision_defaults_restart_netbox_true(self, mock_create_execution):
        from django.contrib.contenttypes.models import ContentType
        from netbox_rpc.models import RPCExecution

        proc = _make_procedure('service.openbao.1.provision_netbox_approle')
        device_ct = ContentType.objects.get(app_label='dcim', model='device')
        execution = RPCExecution.objects.create(
            procedure=proc,
            assigned_object_type=device_ct,
            assigned_object_id=self.device.pk,
            requested_by=self.user,
        )
        mock_create_execution.return_value = execution

        dispatch_openbao_procedure(
            engine=self.engine,
            procedure_name='service.openbao.1.provision_netbox_approle',
            user=self.user,
        )

        payload = mock_create_execution.call_args.kwargs['serializer'].initial_data['params']
        self.assertTrue(payload['restart_netbox'])
        self.assertEqual(payload['engine_slug'], self.engine.slug)

    def test_unregistered_procedure_raises_validation_error_not_does_not_exist(self):
        self.procedure.delete()

        with self.assertRaises(ValidationError) as ctx:
            dispatch_openbao_procedure(
                engine=self.engine,
                procedure_name='service.openbao.1.health',
                user=self.user,
            )
        self.assertIn('procedure', ctx.exception.message_dict)

    def test_missing_execute_permission_raises_permission_denied(self):
        user = User.objects.create_user('no-rpc-perm', password='test')

        with self.assertRaises(PermissionDenied):
            dispatch_openbao_procedure(
                engine=self.engine,
                procedure_name='service.openbao.1.health',
                user=user,
            )

    @patch('netbox_rpc.application.command_handlers.create_execution')
    def test_success_creates_audit_row(self, mock_create_execution):
        from django.contrib.contenttypes.models import ContentType
        from netbox_rpc.models import RPCExecution

        device_ct = ContentType.objects.get(app_label='dcim', model='device')
        execution = RPCExecution.objects.create(
            procedure=self.procedure,
            assigned_object_type=device_ct,
            assigned_object_id=self.device.pk,
            requested_by=self.user,
        )
        mock_create_execution.return_value = execution

        result_execution, run = dispatch_openbao_procedure(
            engine=self.engine,
            procedure_name='service.openbao.1.health',
            user=self.user,
        )

        self.assertEqual(result_execution, execution)
        self.assertIsInstance(run, OpenBaoProcedureRun)
        self.assertEqual(run.engine_id, self.engine.pk)
        self.assertEqual(run.procedure_name, 'service.openbao.1.health')
        self.assertEqual(run.initiated_by_id, self.user.pk)
        mock_create_execution.assert_called_once()


class RunProcedureAPITest(APITestCase):

    def setUp(self):
        super().setUp()
        from netbox_openbao import backends
        from netbox_openbao.backends.openbao import OpenBaoBackend
        from netbox_openbao.models import SecretEngine

        from .fakes import FakeBackend

        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.device = _make_device()
        self.engine = SecretEngine.objects.create(
            name='Primary',
            slug='primary',
            api_url='https://bao.example.net:8200',
            is_default=True,
            host_device=self.device,
        )
        self.procedure = _make_procedure()
        self.run_url = reverse(
            'plugins-api:netbox_openbao-api:secretengine-run-procedure',
            kwargs={'pk': self.engine.pk},
        )

    def test_run_procedure_rejects_engine_bound_param_overrides(self):
        self.add_permissions(
            'netbox_openbao.change_secretengine',
            'netbox_rpc.execute_rpcprocedure',
        )
        response = self.client.post(
            self.run_url,
            {
                'procedure_name': 'service.openbao.1.health',
                'params': {'engine_slug': 'other-engine'},
            },
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('params', response.data)

    @patch('netbox_openbao.api.views.dispatch_openbao_procedure')
    def test_run_procedure_returns_202(self, mock_dispatch):
        from django.contrib.contenttypes.models import ContentType
        from netbox_rpc.models import RPCExecution

        device_ct = ContentType.objects.get(app_label='dcim', model='device')
        execution = RPCExecution.objects.create(
            procedure=self.procedure,
            assigned_object_type=device_ct,
            assigned_object_id=self.device.pk,
            requested_by=self.user,
        )
        run = OpenBaoProcedureRun.objects.create(
            engine=self.engine,
            rpc_execution=execution,
            procedure_name='service.openbao.1.health',
            initiated_by=self.user,
        )
        mock_dispatch.return_value = (execution, run)

        self.add_permissions(
            'netbox_openbao.change_secretengine',
            'netbox_rpc.execute_rpcprocedure',
        )
        response = self.client.post(
            self.run_url,
            {'procedure_name': 'service.openbao.1.health'},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(response.data['procedure_name'], 'service.openbao.1.health')
        mock_dispatch.assert_called_once()

    def test_run_procedure_missing_host_device_is_400(self):
        self.engine.host_device = None
        self.engine.save(update_fields=['host_device'])

        self.add_permissions(
            'netbox_openbao.change_secretengine',
            'netbox_rpc.execute_rpcprocedure',
        )
        response = self.client.post(
            self.run_url,
            {'procedure_name': 'service.openbao.1.health'},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('host_device', response.data)

    def test_run_procedure_missing_permission_is_403(self):
        self.add_permissions('netbox_openbao.change_secretengine')
        response = self.client.post(
            self.run_url,
            {'procedure_name': 'service.openbao.1.health'},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 403)

    def test_procedure_runs_list_requires_view_permission(self):
        url = reverse('plugins-api:netbox_openbao-api:openbaoprocedurerun-list')
        response = self.client.get(url, **self.header)
        self.assertEqual(response.status_code, 403)

        self.add_permissions('netbox_openbao.view_openbaoprocedurerun')
        response = self.client.get(url, **self.header)
        self.assertEqual(response.status_code, 200)
