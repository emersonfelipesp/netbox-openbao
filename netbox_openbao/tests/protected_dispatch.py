"""Actual protected public RPC flow; only the managed-action transport is replaced."""

from types import SimpleNamespace
from unittest.mock import patch

from core.models import ObjectType
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from netbox_rpc import capabilities, dispatch_lease
from netbox_rpc import staging_rotation_contract as contract
from netbox_rpc.api.serializers import RPCExecutionSerializer
from netbox_rpc.application import command_handlers
from netbox_rpc.models import RPCBackend, RPCExecution, RpcPluginSettings, RPCProcedure
from users.models import ObjectPermission

from netbox_openbao.automation import resolve_automation


def grant(user, model, actions, constraints=None):
    name = f'protected-provider-{user.pk}-{model.__name__}-{"-".join(actions)}'
    permission = ObjectPermission.objects.create(name=name, actions=actions, constraints=constraints)
    permission.object_types.add(ObjectType.objects.get_for_model(model))
    permission.users.add(user)


def prepare_catalog(fixture):
    fixture.target.name = 'nms-front-door'
    fixture.target.save()
    backend = RPCBackend.objects.create(name='protected-provider', base_url='https://executor.invalid',
                                        executor_identity=fixture.executor)
    settings = RpcPluginSettings.get_solo()
    settings.enabled, settings.backend = True, backend
    settings.save()
    defaults = {name: value for name, value in contract.PROCEDURE_POLICY.items()
                if name not in {'name', 'command_contract_sha256'}}
    defaults.update(params_schema=contract.PARAMS_SCHEMA, result_schema=contract.RESULT_SCHEMA)
    procedure, _ = RPCProcedure.objects.update_or_create(name=contract.PROCEDURE_NAME, defaults=defaults)
    command = dict(contract.COMMAND_CONTRACT[0])
    sequence = command.pop('sequence')
    procedure.commands.update_or_create(sequence=sequence, defaults=command)
    grant(fixture.actor, RPCProcedure, ['view'], {'id': procedure.pk})
    grant(fixture.actor, RPCProcedure, ['execute'], {'id': procedure.pk})
    grant(fixture.actor, RPCBackend, ['view'])
    approver = get_user_model().objects.create_user(username='protected-provider-approver')
    grant(approver, RPCProcedure, ['view'], {'id': procedure.pk})
    grant(approver, RPCProcedure, ['approve'], {'id': procedure.pk})
    grant(approver, type(fixture.target), ['view'])
    return procedure, approver


def configure_signer(fixture):
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode('ascii')
    settings = {
        dispatch_lease._SIGNING_KEYS_SETTING: [{
            'key_id': 'protected-provider-test', 'key_version': 1, 'private_key_pem': key, 'active': True,
        }],
        dispatch_lease._AUDIENCE_SETTING: 'netbox-rpc-backend', dispatch_lease._TTL_SETTING: 120,
    }
    configured = patch.object(dispatch_lease, '_plugin_setting',
                              side_effect=lambda name, default=None: settings.get(name, default))
    configured.start()
    fixture.addCleanup(configured.stop)


def protected_bundle_round_trip(fixture, *, before_admission=None, denial_check=None):
    fixture.permission_recheck_patch.stop()
    procedure, approver = prepare_catalog(fixture)
    configure_signer(fixture)
    original = fixture.prepare_ssh_bundle()
    if before_admission is not None:
        before_admission()
    manifest = capabilities.BackendCapabilityManifest(
        envelope_version=1, credential_reference_versions=[1],
        credential_provider_versions={'netbox-openbao': [1]}, dispatch_lease_versions=[1],
        handlers=[capabilities.HandlerCapability(
            handler_id=procedure.handler_id, version=1, effect='destructive',
            contract_hash=capabilities.derive_command_contract_hash(procedure),
        )],
    )
    serializer = RPCExecutionSerializer(data={
        'procedure_id': procedure.pk, 'assigned_object_type': 'dcim.device',
        'assigned_object_id': fixture.target.pk, 'params': {},
        'credential_references': {'transport': fixture.authority.reference.to_mapping()},
    })
    resolved = []
    assertion_errors = []

    def backend(target, execution, *, lease):
        # This callback replaces only dispatch to a managed host. Admission,
        # approval, signing, authority and both provider transports are real.
        fixture.params.update(execution_id=execution.pk, dispatch_lease=lease.model_dump())
        if denial_check is not None:
            try:
                denial_check(execution, approver)
            except Exception as exc:
                assertion_errors.append(exc)
            return {'ok': False, 'error': 'The test authorization was refused.'}
        bundle = resolve_automation(fixture.request, fixture.params)
        fixture.assertEqual(bundle['fields']['private_key'], original)
        resolved.append(bundle['access_log_id'])
        return {'ok': True, 'result': {
            'ok': True, 'procedure': contract.HANDLER_ID, 'target': 'nms-front-door',
            'rotated': True, 'stage': 'complete',
        }}

    with patch.object(capabilities, 'fetch_backend_capabilities', return_value=manifest), \
            patch('netbox_rpc.jobs.RPCExecutionJob.enqueue', return_value=SimpleNamespace(pk=59)), \
            patch('netbox_rpc.jobs._call_backend', side_effect=backend) as transport:
        execution = command_handlers.create_execution(serializer=serializer, user=fixture.actor)
        fixture.assertEqual(execution.status, RPCExecution.STATUS_PENDING_APPROVAL)
        command_handlers.approve_execution(execution, approver)
        command_handlers.run_execution(execution)
    execution.refresh_from_db()
    if assertion_errors:
        raise assertion_errors[0]
    expected = RPCExecution.STATUS_FAILED if denial_check is not None else RPCExecution.STATUS_SUCCEEDED
    fixture.assertEqual(execution.status, expected)
    fixture.assertEqual(len(resolved), 0 if denial_check is not None else 1)
    transport.assert_called_once()
