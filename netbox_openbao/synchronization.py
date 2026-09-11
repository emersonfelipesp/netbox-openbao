"""Shared row-lock order for provider reads and supported material writers."""

from __future__ import annotations

from functools import wraps
from inspect import signature
from typing import Any

from django.core.exceptions import ValidationError
from django.views.decorators.debug import sensitive_variables

from netbox_openbao.material_transactions import current_material_transaction, material_transaction


def lock_credential_graph(credential_id: int, *, additional_policy_id: int | None = None) -> Any:
    """Policy IDs, engine IDs, credential, then caller-owned assignment locks.

    Policy-group relationship triggers take the same parent policy locks.
    Selectors can drift before locks are acquired; a drift is refused so no
    caller follows it while holding a differently ordered graph.
    """
    from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

    selectors = Credential.objects.values('policy_id', 'engine_id').get(pk=credential_id)
    policy_ids = {selectors['policy_id']}
    if additional_policy_id:
        policy_ids.add(additional_policy_id)
    policies = {row.pk: row for row in CredentialPolicy.objects.select_for_update().filter(
        pk__in=policy_ids,
    ).order_by('pk')}
    engine_ids = {row.engine_id for row in policies.values()} | {selectors['engine_id']}
    engines = {row.pk: row for row in SecretEngine.objects.select_for_update().filter(
        pk__in=engine_ids,
    ).order_by('pk')}
    credential = Credential.objects.select_for_update().get(pk=credential_id)
    if (credential.policy_id, credential.engine_id) != (selectors['policy_id'], selectors['engine_id']):
        raise ValidationError('Credential relationships changed during authorization.')
    credential.policy = policies[credential.policy_id]
    credential.engine = engines[credential.engine_id]
    return credential


def lock_material_subject(subject: Any, target_policy: Any = None) -> None:
    """Refresh observed version state without discarding requested metadata edits."""
    from netbox_openbao.models import CredentialPolicy, SecretEngine

    if subject is None:
        if target_policy is None:
            from netbox_openbao.backends.exceptions import OpenBaoError

            raise OpenBaoError('A material subject or destination policy must be declared before persistence.')
        lock_material_subjects([], additional_policy_ids={target_policy.pk})
        return
    policy_id = target_policy.pk if target_policy is not None else subject.policy_id
    locked = lock_material_subjects([subject], additional_policy_ids={policy_id})
    if subject.pk is None:
        refresh_material_selectors(subject)
        return
    fresh = locked[subject.pk]
    fields = ('kv_version', 'live_kv_version', 'staged_kv_version', 'live_key_fingerprint',
              'live_key_version', 'staged_key_fingerprint', 'staged_key_version')
    for name in fields:
        setattr(subject, name, getattr(fresh, name))
    # The caller may carry cached related objects from before the lock wait.
    # Rebind them to locked, current configuration without losing its intended
    # policy move or ordinary editable credential metadata.
    subject.policy = CredentialPolicy.objects.get(pk=subject.policy_id)
    subject.engine = SecretEngine.objects.get(pk=subject.engine_id)
    if target_policy is not None:
        target_policy.refresh_from_db()
        target_policy.engine = SecretEngine.objects.get(pk=target_policy.engine_id)


def _participant_selectors(subjects: list[Any], additional_policy_ids: set[int] | None) -> tuple:
    from netbox_openbao.models import Credential

    ids = {subject.pk for subject in subjects if subject.pk is not None}
    selectors = {row['id']: row for row in Credential.objects.filter(pk__in=ids).values(
        'id', 'policy_id', 'engine_id',
    )}
    if selectors.keys() != ids:
        raise ValidationError('A material participant no longer exists.')
    policy_ids = {row['policy_id'] for row in selectors.values()}
    policy_ids.update(subject.policy_id for subject in subjects)
    policy_ids.update(additional_policy_ids or ())
    return ids, selectors, policy_ids


def lock_material_subjects(subjects: list[Any], *, additional_policy_ids: set[int] | None = None) -> dict:
    """Declare the complete existing-credential graph before any material write.

    Callers hold their owner row first. Include every source/destination
    credential and policy for a multi-material owner/assignment change.
    """
    from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

    ids, selectors, policy_ids = _participant_selectors(subjects, additional_policy_ids)
    owner = current_material_transaction()
    owner.declare_graph(credential=ids, policy=policy_ids)
    policies = {row.pk: row for row in CredentialPolicy.objects.select_for_update().filter(
        pk__in=policy_ids,
    ).order_by('pk')}
    engine_ids = {row.engine_id for row in policies.values()} | {row['engine_id'] for row in selectors.values()}
    engine_ids.update(subject.engine_id for subject in subjects)
    owner.declare_graph(engine=engine_ids)
    engines = {row.pk: row for row in SecretEngine.objects.select_for_update().filter(
        pk__in=engine_ids,
    ).order_by('pk')}
    locked = {row.pk: row for row in Credential.objects.select_for_update().filter(pk__in=ids).order_by('pk')}
    _check_material_participants(locked, selectors, policies, engines)
    owner.graph_frozen = True
    return locked


def _check_material_participants(locked: dict, selectors: dict, policies: dict, engines: dict) -> None:
    for pk, credential in locked.items():
        expected = selectors[pk]
        if (credential.policy_id, credential.engine_id) != (expected['policy_id'], expected['engine_id']):
            raise ValidationError('Material participant relationships changed while acquiring locks.')
        credential.policy = policies[credential.policy_id]
        credential.engine = engines[credential.engine_id]


def refresh_material_selectors(credential: Any) -> None:
    """Discard related-object caches restored by serializer persistence."""
    from netbox_openbao.models import CredentialPolicy, SecretEngine

    credential.policy = CredentialPolicy.objects.get(pk=credential.policy_id)
    credential.engine = SecretEngine.objects.get(pk=credential.engine_id)


def synchronized_material_change(function: Any) -> Any:
    """Stage/promote/discard/rotate hold their graph locks through backend I/O."""
    @wraps(function)
    @sensitive_variables()
    def synchronized(credential: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            with material_transaction():
                locked = lock_material_subjects([credential])[credential.pk]
                credential.refresh_from_db()
                credential.policy = locked.policy
                credential.engine = locked.engine
                return function(credential, *args, **kwargs)
        except Exception:
            # Inner audit writes rolled back with the mutation. Retain a
            # value-free refusal outside that transaction, including when the
            # caller supplied user/request positionally.
            from netbox_openbao.services import log_access

            arguments = signature(function).bind(credential, *args, **kwargs).arguments
            action = function.__name__.split('_', 1)[0]
            log_access(
                credential, arguments.get('user'), action, request=arguments.get('request'),
                success=False, message='Material operation did not complete; inspect its reconciliation records.',
            )
            raise
    return synchronized
