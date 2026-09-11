"""Execution-bound credential authorization and durable one-use resolution.

RPC owns the signed execution authority. This module owns the credential and
assignment checks. Only services.read_automation_bundle touches material.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, connection, transaction
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from netbox_openbao.choices import CredentialStatusChoices
from netbox_openbao.config import assignable_model_labels
from netbox_openbao.models import (
    AutomationResolutionReceipt,
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
)
from netbox_openbao.secrets.identity import live_key_fingerprint
from netbox_openbao.secrets.registry import get_schema
from netbox_openbao.synchronization import lock_credential_graph


class AutomationResolutionDenied(PermissionDenied):
    """A deliberately value-free refusal suitable for API and audit use."""

    def __init__(self) -> None:
        super().__init__('Automation credential resolution was refused.')


def authorize_dispatch(request: Any, params: dict[str, Any]) -> Any:
    """Load authority exclusively through the compatible RPC implementation."""
    try:
        from netbox_rpc.credential_authority import validate_secret_resolution_dispatch
        from netbox_rpc.models import RPCExecution

        execution = RPCExecution.objects.only('pk').get(pk=params['execution_id'])
        return validate_secret_resolution_dispatch(
            execution=execution,
            dispatch_lease=params['dispatch_lease'],
            authenticated_executor=request.user,
            step_id=params['step_id'],
            reference_name=params['reference_name'],
        )
    except Exception:
        # Includes absent/incompatible RPC support. Never expose import errors,
        # authority internals or a vendor exception chain through the API.
        raise AutomationResolutionDenied() from None


def _nonce_digest(authority: Any) -> str:
    return hashlib.sha256(authority.dispatch_nonce.encode('utf-8')).hexdigest()


def _check_lifetime(authority: Any) -> None:
    try:
        from netbox_rpc.credential_authority import check_authorization_lifetime

        check_authorization_lifetime(authority)
    except Exception:
        raise AutomationResolutionDenied() from None


def _check_rpc_permissions(authority: Any) -> None:
    try:
        from netbox_rpc.credential_authority import check_authorization_permissions

        check_authorization_permissions(authority)
    except Exception:
        raise AutomationResolutionDenied() from None


def _check_dispatch(authority: Any) -> None:
    _check_lifetime(authority)
    _check_rpc_permissions(authority)
    _check_lifetime(authority)


def _actor(authority: Any) -> Any:
    user = get_user_model().objects.filter(pk=authority.initiating_actor.pk, is_active=True).first()
    if user is None:
        raise AutomationResolutionDenied()
    return user


def _target(authority: Any, actor: Any) -> ContentType:
    reference = authority.reference
    target = authority.target_object
    content_type = ContentType.objects.get_for_model(target, for_concrete_model=False)
    label = f'{content_type.app_label}.{content_type.model}'
    if label != reference.target.object_type or target.pk != reference.target.object_id:
        raise AutomationResolutionDenied()
    if label not in assignable_model_labels():
        raise AutomationResolutionDenied()
    manager = type(target).objects
    if not manager.restrict(actor, 'view').filter(pk=target.pk).exists():
        raise AutomationResolutionDenied()
    return content_type


def _assignment_rows(authority: Any, content_type: ContentType) -> Any:
    reference = authority.reference
    rows = CredentialAssignment.objects.filter(
        assigned_object_type=content_type, assigned_object_id=reference.target.object_id,
        purpose=reference.purpose, enabled=True,
    )
    if reference.assignment_id is not None:
        rows = rows.filter(pk=reference.assignment_id)
    else:
        rows = rows.filter(credential__uuid=reference.credential_uuid)
    return rows


def _lock_metadata(authority: Any) -> tuple[CredentialAssignment, Credential]:
    """Lock policy, engine, credential, assignment before authorization reads.

    Candidate lookup confers no authority. A changed relationship after a wait
    is refused, not followed while holding locks in a different order.
    Policy-group through-table triggers synchronize relationship writes with
    the parent policy lock, including removals and replacement operations.
    """
    content_type = ContentType.objects.get_for_model(authority.target_object, for_concrete_model=False)
    matches = list(_assignment_rows(authority, content_type).order_by('pk')[:2])
    if len(matches) != 1:
        raise AutomationResolutionDenied()
    candidate = matches[0]
    credential = lock_credential_graph(candidate.credential_id)
    assignment = CredentialAssignment.objects.select_for_update().get(pk=candidate.pk)
    if assignment.credential_id != credential.pk:
        raise AutomationResolutionDenied()
    stored = get_schema(credential.credential_type).get('stored')
    if stored is not None:
        type(stored).objects.select_for_update().get(pk=stored.pk)
    return assignment, credential


def _check_credential(credential: Credential, actor: Any) -> None:
    # A new statement after all lock waits is essential: NetBox restrictions
    # can contain subqueries through mutable policy fields such as slug.
    if not Credential.objects.restrict(actor, 'reveal').filter(pk=credential.pk).exists():
        raise AutomationResolutionDenied()
    valid_statuses = (CredentialStatusChoices.STATUS_ACTIVE, CredentialStatusChoices.STATUS_STAGED)
    now = timezone.now()
    if credential.status not in valid_statuses:
        raise AutomationResolutionDenied()
    if credential.valid_from and credential.valid_from > now:
        raise AutomationResolutionDenied()
    if credential.valid_until and credential.valid_until <= now:
        raise AutomationResolutionDenied()
    groups = credential.policy.groups.values_list('pk', flat=True)
    if groups.exists() and not actor.is_superuser and not actor.groups.filter(pk__in=groups).exists():
        raise AutomationResolutionDenied()


def _version(credential: Credential, authority: Any) -> int:
    version = credential.live_kv_version
    if not version or version == credential.staged_kv_version:
        raise AutomationResolutionDenied()
    policy = authority.reference.version
    # A pinned reference is an approval precondition, not a historical reveal
    # capability. Rotation changes that precondition and requires redispatch.
    if policy.policy == 'pinned' and policy.number != version:
        raise AutomationResolutionDenied()
    return version


def _fields(credential: Credential, authority: Any) -> dict[str, dict[str, Any]]:
    schema = get_schema(credential.credential_type)
    declared = schema.get('vault_fields', {})
    fields = authority.reference.fields
    if not fields or any(field not in declared for field in fields):
        raise AutomationResolutionDenied()
    return {field: declared[field] for field in fields}


def _resolve_metadata(authority: Any) -> tuple[CredentialAssignment, Credential, int, dict[str, Any]]:
    assignment, credential = _lock_metadata(authority)
    actor = _actor(authority)
    content_type = _target(authority, actor)
    if not _assignment_rows(authority, content_type).restrict(actor, 'view').filter(pk=assignment.pk).exists():
        raise AutomationResolutionDenied()
    _check_credential(credential, actor)
    if credential.policy.require_reason and not authority.reason.strip():
        raise AutomationResolutionDenied()
    return assignment, credential, _version(credential, authority), _fields(credential, authority)


def _metadata_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _identity(assignment: CredentialAssignment, credential: Credential, authority: Any) -> dict[str, Any]:
    """Snapshot identity and backend selectors, never material or its digest."""
    policy = credential.policy
    engine = credential.engine
    if policy.engine_id != engine.pk:
        raise AutomationResolutionDenied()
    selectors = {
        name: getattr(engine, name)
        for name in ('backend', 'api_url', 'namespace', 'kv_mount', 'kv_version',
                     'auth_method', 'tls_verify', 'ca_cert_path', 'env_prefix')
    }
    selectors.update(policy_prefix=policy.approle_env_prefix, credential_path=credential.path)
    schema = get_schema(credential.credential_type)
    return {
        'credential_uuid': str(credential.uuid), 'assignment_id': assignment.pk,
        'target': {'object_type': authority.reference.target.object_type,
                   'object_id': authority.reference.target.object_id}, 'purpose': assignment.purpose,
        'username': credential.username, 'fingerprint': live_key_fingerprint(credential, schema),
        'credential_type': credential.credential_type, 'policy_id': credential.policy_id,
        'engine_id': credential.engine_id, 'engine_identity_sha256': _metadata_digest(selectors),
        'schema_sha256': _metadata_digest({
            'vault_fields': schema.get('vault_fields', {}), 'json_schema': schema.get('json_schema', {}),
            'extractor': schema.get('extractor'),
        }),
    }


def capture_reference_identity(
    *, reference: Any, initiating_actor: Any, target_object: Any, reason: str,
) -> dict[str, Any]:
    """Capture approved metadata for RPC admission without reading the vault.

    RPC freezes this result in its signed authorization snapshot. Live material
    may rotate without changing identity; assignment, username, fingerprint,
    schema or backend-selector changes require a new authorization.
    """
    authority = SimpleNamespace(reference=reference, initiating_actor=initiating_actor,
                                target_object=target_object, reason=reason)
    try:
        with transaction.atomic():
            assignment, credential, _, _ = _resolve_metadata(authority)
            return _identity(assignment, credential, authority)
    except Exception:
        raise AutomationResolutionDenied() from None


def _require_identity(assignment: CredentialAssignment, credential: Credential, authority: Any) -> None:
    if _identity(assignment, credential, authority) != authority.provider_identity:
        raise AutomationResolutionDenied()


def record_automation_access(
    request: Any, params: dict[str, Any], *, authority: Any = None,
    credential: Credential | None = None, receipt: AutomationResolutionReceipt | None = None,
    success: bool = False,
) -> CredentialAccessLog:
    """Write fixed, value-free evidence; failure is fatal to automation delivery."""
    authenticated = getattr(request.user, 'is_authenticated', False)
    values = {
        'credential': credential,
        'credential_name_snapshot': '',
        'credential_uuid_snapshot': getattr(credential, 'uuid', None),
        'executor': request.user if authenticated else None,
        'executor_snapshot': str(getattr(request.user, 'username', ''))[:150],
        'execution_id': params['execution_id'],
        'step_id': params['step_id'],
        'reference_name': params['reference_name'],
        'action': 'reveal',
        'success': success,
        'message': 'Automation bundle delivered.' if success else 'Automation bundle refused or outcome unknown.',
    }
    if authority is not None:
        values.update(
            user=authority.initiating_actor,
            username_snapshot=str(authority.initiating_actor.username)[:150],
            reason=authority.reason[:500],
            request_id=authority.correlation_id[:64],
            intent_run_id=authority.intent_run_id,
            purpose=authority.reference.purpose,
            dispatch_nonce_digest=_nonce_digest(authority),
        )
    if receipt is not None:
        values.update(assignment_id=receipt.assignment_id, resolved_version=receipt.resolved_version)
    return CredentialAccessLog.objects.create(**values)


def _reserve(authority: Any) -> AutomationResolutionReceipt:
    """Commit the selected version before any possible read of secret material."""
    try:
        with transaction.atomic():
            assignment, credential, version, _ = _resolve_metadata(authority)
            _check_dispatch(authority)
            _require_identity(assignment, credential, authority)
            return AutomationResolutionReceipt.objects.create(
                execution_id=authority.execution_id, dispatch_nonce_digest=_nonce_digest(authority),
                step_id=authority.step_id, reference_name=authority.reference_name,
                credential_uuid=credential.uuid, assignment_id=assignment.pk, resolved_version=version,
            )
    except IntegrityError:
        raise AutomationResolutionDenied() from None


@sensitive_variables()
def _deliver(request: Any, params: dict[str, Any], receipt: AutomationResolutionReceipt) -> dict[str, Any]:
    from netbox_openbao.services import read_automation_bundle

    with transaction.atomic():
        authority = authorize_dispatch(request, params)
        assignment, credential, version, fields = _resolve_metadata(authority)
        _check_dispatch(authority)
        _require_identity(assignment, credential, authority)
        identity = (credential.uuid, assignment.pk, version, _nonce_digest(authority))
        reserved = (receipt.credential_uuid, receipt.assignment_id, receipt.resolved_version,
                    receipt.dispatch_nonce_digest)
        if identity != reserved:
            raise AutomationResolutionDenied()
        # Verify audit availability before touching the vault, and persist the
        # successful delivery record before material leaves this function.
        audit = record_automation_access(request, params, authority=authority, credential=credential, receipt=receipt)
        _check_dispatch(authority)
        material, ttl = read_automation_bundle(
            credential, version=version, fields=fields,
            expected_fingerprint=authority.provider_identity['fingerprint'],
        )
        final_assignment, final_credential, final_version, _ = _resolve_metadata(authority)
        _require_identity(final_assignment, final_credential, authority)
        if final_version != version:
            raise AutomationResolutionDenied()
        _check_dispatch(authority)
        audit.success = True
        audit.message = 'Automation bundle delivered.'
        audit.save(update_fields=['success', 'message'])
        result = {
            'schema_version': 1, 'credential_uuid': str(credential.uuid), 'assignment_id': assignment.pk,
            'resolved_version': version, 'ttl': ttl, 'secret': True,
            'fields': material, 'access_log_id': audit.pk,
        }
    return result


@sensitive_variables()
def resolve_automation(request: Any, params: dict[str, Any]) -> dict[str, Any]:
    """Resolve one named frozen reference; all errors and repeats fail closed.

    Requires an autocommit caller so a failed outer transaction cannot erase
    the receipt and turn an unknown reveal outcome into an unpinned retry.
    """
    if connection.in_atomic_block or not connection.get_autocommit():
        raise AutomationResolutionDenied()
    authority = None
    receipt = None
    try:
        authority = authorize_dispatch(request, params)
        receipt = _reserve(authority)
        return _deliver(request, params, receipt)
    except Exception:
        try:
            record_automation_access(request, params, authority=authority, receipt=receipt)
        except Exception:
            # Do not log exceptions: an outage must not trigger an exception
            # reporter that captures provider locals or request bodies.
            raise AutomationResolutionDenied() from None
        raise AutomationResolutionDenied() from None
