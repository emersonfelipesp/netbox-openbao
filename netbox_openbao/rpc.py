"""
Dispatch OpenBao host operations through netbox-rpc.

Every call creates an audited ``RPCExecution`` row targeted at the engine's
``host_device``. The plugin never shells out to ``bao`` or SSH directly.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import PermissionDenied

from netbox_openbao.config import get_config

# Read-only catalogue entries the plugin exposes. Destructive and approval-gated
# writes stay on netbox-rpc's own UI until a dedicated workflow lands here.
OPENBAO_READ_PROCEDURES = frozenset({
    'service.openbao.1.inspect',
    'service.openbao.1.seal_status',
    'service.openbao.1.health',
    'service.openbao.1.policies_list',
    'service.openbao.1.auth_list',
    'service.openbao.1.secrets_list',
    'service.openbao.1.audit_list',
    'service.openbao.1.raft_list_peers',
    'service.openbao.1.raft_autopilot_state',
    'service.openbao.1.snapshots_list',
})

OPENBAO_WRITE_PROCEDURES = frozenset({
    'service.openbao.1.provision_netbox_approle',
})

ENGINE_BOUND_PARAM_KEYS = frozenset({
    'mount',
    'role_name',
    'engine_slug',
    'path_prefix',
})


def _require_rpc_permissions(user) -> None:
    for permission in (
        'netbox_rpc.execute_rpcprocedure',
    ):
        if not user.has_perm(permission):
            raise PermissionDenied(f'{permission} permission is required.')


def _device_content_type():
    from dcim.models import Device

    return ContentType.objects.get_for_model(Device, for_concrete_model=False)


def build_procedure_params(engine, procedure_name: str, overrides: dict | None = None) -> dict:
    """Build params for seeded OpenBao procedures from engine inventory."""
    overrides = dict(overrides or {})
    if bound := ENGINE_BOUND_PARAM_KEYS & overrides.keys():
        raise ValidationError({
            'params': _(
                'The following parameters are derived from the selected engine and cannot be overridden: %(keys)s'
            ) % {'keys': ', '.join(sorted(bound))},
        })
    if procedure_name in OPENBAO_READ_PROCEDURES:
        return overrides
    if procedure_name == 'service.openbao.1.provision_netbox_approle':
        config = get_config()
        return {
            'mount': engine.kv_mount,
            'role_name': f'netbox-{engine.slug}',
            'engine_slug': engine.slug,
            'path_prefix': config.get('path_prefix') or 'netbox',
            'restart_netbox': overrides.get('restart_netbox', True),
        }
    return overrides


def dispatch_openbao_procedure(*, engine, procedure_name: str, user, request=None, params=None):
    """
    Queue an OpenBao RPC procedure against ``engine.host_device``.

    Returns the created ``RPCExecution`` and the plugin's ``OpenBaoProcedureRun``
    audit row.
    """
    from netbox_rpc.api.serializers import RPCExecutionSerializer
    from netbox_rpc.application.command_handlers import create_execution
    from netbox_rpc.models import RPCProcedure

    from netbox_openbao.models import OpenBaoProcedureRun

    if engine.host_device_id is None:
        raise ValidationError({
            'host_device': _('An OpenBao host device must be configured before running RPC procedures.'),
        })

    allowed = OPENBAO_READ_PROCEDURES | OPENBAO_WRITE_PROCEDURES
    if procedure_name not in allowed:
        raise ValidationError({'procedure': _('Procedure is not exposed by netbox-openbao.')})

    _require_rpc_permissions(user)

    try:
        procedure = RPCProcedure.objects.get(name=procedure_name)
    except RPCProcedure.DoesNotExist as exc:
        raise ValidationError({
            'procedure': _('Procedure is not registered in netbox-rpc.'),
        }) from exc
    if procedure.approval_required and not user.has_perm('netbox_rpc.approve_rpcprocedure'):
        raise PermissionDenied('This procedure requires approval (approve_rpcprocedure permission).')

    payload = build_procedure_params(engine, procedure_name, params)
    device_ct = _device_content_type()
    serializer = RPCExecutionSerializer(
        data={
            'procedure_id': procedure.pk,
            'assigned_object_type': device_ct.pk,
            'assigned_object_id': engine.host_device_id,
            'params': payload,
        },
        context={'request': request} if request is not None else {},
    )
    execution = create_execution(serializer=serializer, user=user)
    run = OpenBaoProcedureRun.objects.create(
        engine=engine,
        rpc_execution=execution,
        procedure_name=procedure_name,
        initiated_by=user,
    )
    return execution, run
