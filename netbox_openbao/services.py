"""
Coordination between the NetBox database, the secret backend, and the audit log.

Everything that touches secret material funnels through this module, so there
is exactly one place to audit for leaks. Views, serializers, and forms call
these functions; they never call a backend directly.

**On the write path and atomicity.** OpenBao writes are not transactional with
PostgreSQL, and Django provides no rollback hook — `transaction.on_commit`
fires only on commit, so there is no callback that runs when a transaction
unwinds. Compensation is therefore explicit: the backend write happens inside
the atomic block, the written path is recorded, and the enclosing `except`
deletes the now-orphaned path before re-raising. If the compensating delete
itself fails, that is logged at ERROR and `CredentialVerifyJob` reports the
residue as an orphan on its next pass.

The persistence step is injected as a callback rather than performed here so
the same rollback machinery serves both callers: the REST API needs
`serializer.save()` (which handles tags, custom fields, and m2m), while forms
and internal callers just need `instance.save()`.
"""

import logging

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends import get_backend
from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.choices import AccessActionChoices, CredentialStatusChoices
from netbox_openbao.config import get_config
from netbox_openbao.material_transactions import MaterialAttempt, current_material_transaction, material_operation
from netbox_openbao.secrets.registry import extract_metadata, validate_payload
from netbox_openbao.synchronization import (
    lock_material_subject,
    refresh_material_selectors,
    synchronized_material_change,
)

__all__ = (
    'build_custom_metadata',
    'delete_material',
    'discard_staged',
    'enforce_policy_access',
    'enforce_update_access',
    'promote_staged',
    'stage_material',
    'log_access',
    'prepare_material',
    'reveal_material',
    'rotate_material',
    'store_credential',
    'write_material',
)

logger = logging.getLogger('netbox.plugins.netbox_openbao')


# ----------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------

def _request_context(request):
    """Extract the non-secret request attributes the audit log records."""
    if request is None:
        return {'source_ip': None, 'request_id': ''}

    from utilities.request import get_client_ip

    try:
        client_ip = get_client_ip(request)
        # get_client_ip() returns a netaddr.IPAddress, which
        # GenericIPAddressField cannot adapt ("argument of type 'IPAddress' is
        # not iterable"). Left unconverted this raises inside the audit write,
        # which is swallowed by design — so every HTTP-originated access would
        # go unrecorded, silently, with no error visible to the caller.
        source_ip = str(client_ip) if client_ip else None
    except Exception:
        source_ip = None

    return {
        'source_ip': source_ip,
        'request_id': str(getattr(request, 'id', '') or ''),
    }


def log_access(credential, user, action, success=True, reason='', message='', request=None, link=True):
    """
    Append a `CredentialAccessLog` row.

    Written **synchronously**, deliberately. The architecture plan proposed
    deferring this to RQ to keep it off the reveal latency path, but a single
    indexed INSERT costs on the order of a millisecond against an OpenBao
    round-trip of tens of milliseconds, and an audit record a queue failure can
    silently drop is not an audit record. The latency saved does not pay for
    the evidence lost.

    Never records the value — only that an access occurred, by whom, and
    whether it succeeded.

    `link=False` records the credential by snapshot only, without the foreign
    key. That is required after a rolled-back write: the in-memory object still
    carries the primary key the aborted INSERT was assigned, but no such row
    exists, so linking would raise a deferred foreign-key violation at commit —
    and lose the audit record for the very failure it was meant to capture.
    """
    from netbox_openbao.models import CredentialAccessLog

    context = _request_context(request)
    try:
        # A savepoint, so a failed audit insert cannot poison an enclosing
        # transaction that the caller is still relying on.
        with transaction.atomic():
            return CredentialAccessLog.objects.create(
                credential=credential if (link and getattr(credential, 'pk', None)) else None,
                credential_name_snapshot=(getattr(credential, 'name', '') or '')[:200],
                credential_uuid_snapshot=getattr(credential, 'uuid', None),
                user=user if (user is not None and user.is_authenticated) else None,
                username_snapshot=(getattr(user, 'username', '') or '')[:150],
                action=action,
                success=success,
                reason=reason or '',
                message=(message or '')[:500],
                **context,
            )
    except Exception:
        # An audit write must never mask the operation's own outcome, but it
        # must also never vanish quietly.
        logger.exception('Failed to write credential access log for action %s', action)
        return None


def log_settings_change(user, request=None, changed_fields=None, success=True, message=None):
    """
    Record a settings change alongside the credential accesses it governs.

    NetBox's own changelog already records *what* changed on the row. This
    records it where an operator investigating a leak is already looking: the
    same table as the reveals. A lowered `reveal_rate_limit` is the control that
    bounds how fast a stolen token drains the store, so "who widened it, from
    where, and when" belongs in the timeline next to the reveals it permitted —
    not in a second place they would have to think to open.

    `credential` is null and the snapshot names the settings row instead. The
    column is already nullable for the rolled-back-write case, so this needs no
    schema change.

    **Field names only, never values.** The access log's standing contract is
    that it carries no configuration or secret values, and a rate limit is not
    secret but the contract is worth more than the convenience of recording it.
    """
    from netbox_openbao.models import CredentialAccessLog

    context = _request_context(request)
    names = ', '.join(sorted(changed_fields or [])) or 'settings'
    summary = message or f'Changed: {names}'
    try:
        with transaction.atomic():
            return CredentialAccessLog.objects.create(
                credential=None,
                credential_name_snapshot='OpenBao settings',
                credential_uuid_snapshot=None,
                user=user if (user is not None and getattr(user, 'is_authenticated', False)) else None,
                username_snapshot=(getattr(user, 'username', '') or '')[:150],
                action=AccessActionChoices.ACTION_CONFIGURE,
                success=success,
                reason='',
                message=summary[:500],
                **context,
            )
    except Exception:
        logger.exception('Failed to write settings-change audit record')
        return None


# ----------------------------------------------------------------------
# Authorization
# ----------------------------------------------------------------------

def enforce_policy_access(credential, user, action=None, request=None):
    """
    Apply the policy tier's coarse group gate.

    `CredentialPolicy.groups` is documented as authorization layer 2 — applied
    in addition to object permissions, never instead of them. It lives here,
    with the rest of the material path, rather than in a view, because there
    are five surfaces that reach a credential: the REST actions, the full-page
    UI reveal, the HTMX UI reveal, the UI promote/discard, and the edit form's
    staged rotation. A gate implemented in one of them is a gate that is
    missing from the other four.

    It was. The check lived only in `api/views.CredentialViewSet._authorize`,
    so a user in none of the tier's groups was refused by the API and served
    by the web UI — which is the drift `CLAUDE.md` warns about, and a
    disclosure bug rather than an inconsistency.

    An empty group list means the tier does not use the gate, which is the
    default. `user=None` is an internal caller — a management command, a
    background job — and there is no group membership to consult.
    """
    if user is None or getattr(user, 'is_superuser', False):
        return

    permitted = list(credential.policy.groups.values_list('pk', flat=True))
    if not permitted:
        return

    if user.groups.filter(pk__in=permitted).exists():
        return

    if action is not None:
        log_access(
            credential, user, action, success=False,
            message='Policy group membership required.', request=request,
        )
    raise PermissionDenied(
        'Your groups are not permitted to access credentials under this policy.'
    )


def enforce_update_access(credential, user, action=None, request=None):
    """
    Gate an update against the tier the credential is on **in the database**.

    `enforce_policy_access` reads `credential.policy`, and by the time an
    update reaches the service layer that attribute is already the *incoming*
    tier rather than the one the caller has to satisfy. Both layers mutate the
    instance in place before any of this runs:

    * NetBox's `ValidatedModelSerializer.validate()` `setattr()`s every
      validated attribute onto `self.instance` so it can `full_clean()` it.
    * Django's `ModelForm._post_clean()` calls `construct_instance()`.

    That is not a detail — it is the whole bug. `policy` is a writable field,
    so a caller outside a tier's groups could move a credential to a tier they
    *are* in and then reveal it, and the paths are UUID-derived under one
    shared prefix, so the receiving tier's AppRole reads the very same secret.
    Checking the mutated instance would compare the caller against the tier
    they chose, which they always satisfy.

    So the committed row is re-read. One indexed query, on an operation that is
    already writing to two systems.
    """
    if credential is None or getattr(credential, 'pk', None) is None:
        return

    committed = type(credential).objects.filter(pk=credential.pk).select_related('policy').first()
    if committed is None:
        # Mid-rollback, or deleted concurrently. There is no tier left to
        # satisfy, and the update is going to fail on its own.
        return

    enforce_policy_access(committed, user, action, request=request)


# ----------------------------------------------------------------------
# Metadata
# ----------------------------------------------------------------------

def build_custom_metadata(credential):
    """
    Build the KV v2 `custom_metadata` envelope for a credential.

    This is what makes secrets discoverable from outside NetBox: tooling can
    list the mount and filter on these keys. `managed_by` also lets the health
    job recognise material under the plugin's prefix that NetBox no longer has
    a row for — an orphan.

    All values must be non-empty strings. OpenBao rejects both other JSON types
    and empty values:

        custom_metadata validation failed: length of value for key "x" is 0
        but must be 0 < len(value) <= 512

    which matters because `netbox_assignments` is empty for a credential that
    has no assignments yet — that is, every credential at the moment it is
    created, since assignments can only be added afterwards. Sending it made
    every create fail against a real server. An absent key and an empty one
    mean the same thing to every consumer of this metadata, and only one of
    them is legal.
    """
    assignments = ','.join(
        f'{a.assigned_object_type.app_label}.{a.assigned_object_type.model}:{a.assigned_object_id}'
        for a in credential.assignments.select_related('assigned_object_type').all()
    )
    metadata = {
        'managed_by': 'netbox-openbao',
        'netbox_credential_id': str(credential.pk),
        'netbox_credential_uuid': str(credential.uuid),
        'netbox_credential_type': credential.credential_type,
        'netbox_policy': credential.policy.slug if credential.policy_id else '',
        'netbox_assignments': assignments,
    }
    if credential.import_source:
        metadata['netbox_import_source'] = credential.import_source

    from django.conf import settings

    base = (getattr(settings, 'SITE_URL', '') or '').rstrip('/')
    if base:
        try:
            metadata['netbox_url'] = f'{base}{credential.get_absolute_url()}'
        except Exception:
            # A missing URL is cosmetic; it must not fail the write.
            logger.debug('Could not resolve absolute URL for credential %s', credential.pk)

    # Drop empties. OpenBao refuses a zero-length value, and an absent key
    # means the same thing to every consumer of this metadata.
    return {key: value for key, value in metadata.items() if value}


@sensitive_variables()
def prepare_material(credential_type, payload):
    """
    Validate a payload and derive its non-secret metadata.

    Pure: no database and no network. Runs before anything is persisted so a
    malformed key fails the request outright rather than leaving material in
    OpenBao with no metadata in NetBox.

    Returns `(cleaned_payload, metadata_fields)`.
    """
    cleaned = validate_payload(credential_type, payload)
    metadata = extract_metadata(credential_type, cleaned)
    return cleaned, metadata


# ----------------------------------------------------------------------
# Write path
# ----------------------------------------------------------------------

@material_operation
@sensitive_variables()
def store_credential(persist, credential_type, payload, *, cas=0, user=None, request=None, action=None,
                     subject=None, promote=True, target_policy=None):
    """
    Persist a credential row and its material as one unit.

    Args:
        persist (Callable[[dict], Credential]): Takes the extracted metadata
            dict and returns the saved `Credential`. The REST API passes
            `serializer.save`; forms and internal callers pass a closure over
            `instance.save()`.
        subject (Credential | None): The credential this operation concerns,
            used only to identify the audit entry when `persist` itself fails
            and never returns one.
        promote (bool): Whether the new version becomes the one consumers are
            served.
            False writes it alongside the live version instead — which is the
            whole point of staging, and the reason resolution has to consult
            `live_kv_version` rather than always taking latest.
        cas (int | None): Check-and-set precondition. `0` requires the path not to exist,
            which is what stops a create silently overwriting an existing
            secret at a colliding path. Pass the current `kv_version` when
            updating.

    Returns `(credential, version)`.
    """
    action = action or AccessActionChoices.ACTION_WRITE
    cleaned, metadata = prepare_material(credential_type, payload)
    from netbox_openbao.secrets.identity import derive_key_fingerprint, record_key_version

    fingerprint = derive_key_fingerprint(credential_type, cleaned)

    lock_material_subject(subject, target_policy)
    credential = persist(metadata)
    refresh_material_selectors(credential)
    owner = current_material_transaction()
    owner.graph_ids.setdefault('credential', set()).add(credential.pk)
    backend = get_backend(credential.engine, credential.policy)
    attempt = MaterialAttempt(credential, backend, credential.path, user, action)
    owner.attempts.append(attempt)
    version = backend.write(credential.path, cleaned, cas=cas)
    attempt.version = version
    backend.set_metadata(credential.path, build_custom_metadata(credential))

    credential.kv_version = version
    credential.last_verified = timezone.now()
    update_fields = ['kv_version', 'last_verified']
    update_fields += record_key_version(credential, fingerprint, version, promote=promote)
    if promote:
        credential.live_kv_version = version
        credential.staged_kv_version = None
        update_fields += ['live_kv_version', 'staged_kv_version']
    else:
        credential.staged_kv_version = version
        update_fields.append('staged_kv_version')
    if action == AccessActionChoices.ACTION_ROTATE:
        credential.last_rotated = timezone.now()
        update_fields.append('last_rotated')
    if action == AccessActionChoices.ACTION_STAGE:
        credential.status = CredentialStatusChoices.STATUS_STAGED
        update_fields.append('status')
    credential.save(update_fields=update_fields)
    audit = log_access(credential, user, action, success=True, request=request)
    attempt.audit_id = getattr(audit, 'pk', None)
    return credential, version


def _row_exists(credential):
    """True if `credential` corresponds to a row that is actually committed."""
    if credential is None or credential.pk is None:
        return False
    try:
        return type(credential).objects.filter(pk=credential.pk).exists()
    except Exception:
        return False


def write_material(credential, payload, *, cas=0, user=None, request=None, action=None, promote=True):
    """
    Convenience wrapper for callers holding an unsaved or already-built
    `Credential` instance (forms, quick-add, management commands).
    """
    def persist(metadata):
        for field, value in metadata.items():
            setattr(credential, field, value)
        credential.full_clean()
        credential.save()
        return credential

    return store_credential(
        persist,
        credential.credential_type,
        payload,
        cas=cas,
        user=user,
        request=request,
        action=action,
        subject=credential,
        promote=promote,
    )


@synchronized_material_change
def rotate_material(credential, payload, user=None, request=None):
    """
    Write a new version of a credential's material.

    Uses the recorded `kv_version` as the check-and-set precondition so a
    rotation cannot clobber a concurrent write it never saw.
    """
    enforce_policy_access(credential, user, AccessActionChoices.ACTION_ROTATE, request=request)

    return write_material(
        credential,
        payload,
        cas=credential.kv_version,
        user=user,
        request=request,
        action=AccessActionChoices.ACTION_ROTATE,
    )


# ----------------------------------------------------------------------
# Read and delete
# ----------------------------------------------------------------------

def reveal_material(credential, user, request=None, reason='', version=None):
    """
    Return `(secret_payload, ttl)` for `credential`.

    Authorization is the caller's responsibility and is enforced in the view;
    this function assumes it has passed. It owns the checks that are properties
    of the credential rather than of the user: a policy-mandated reason, and
    the tier's reveal ceiling.
    """
    enforce_policy_access(credential, user, AccessActionChoices.ACTION_REVEAL, request=request)

    policy = credential.policy
    if policy.require_reason and not (reason or '').strip():
        log_access(
            credential, user, AccessActionChoices.ACTION_REVEAL, success=False,
            message='Reason required by policy.', request=request,
        )
        raise ValidationError({'reason': _("This credential's policy requires a reason for every reveal.")})

    # Resolution order: an explicitly requested version, then the promoted
    # one, then latest. The middle step is what keeps a staged rotation from
    # being served before anyone has confirmed it works.
    effective_version = version if version is not None else credential.live_kv_version

    backend = get_backend(credential.engine, policy)
    try:
        data = backend.read(credential.path, version=effective_version)
    except OpenBaoError as exc:
        log_access(
            credential, user, AccessActionChoices.ACTION_REVEAL, success=False,
            reason=reason, message=str(exc), request=request,
        )
        raise

    log_access(credential, user, AccessActionChoices.ACTION_REVEAL, success=True, reason=reason, request=request)

    ttl = min(int(get_config('reveal_ttl') or 300), policy.max_reveal_ttl)
    return data, ttl


@sensitive_variables()
def read_automation_bundle(
    credential, *, version: int, fields: dict, expected_fingerprint: str | None = None,
) -> tuple[dict, int]:
    """Read one explicit KV version and project an already-authorized bundle.

    Internal primitive for ``automation.resolve_automation`` only. The caller
    owns actor, executor, target, assignment, schema and receipt checks. It also
    owns the required correlated audit; ordinary reveal audit is not reused.
    """
    backend = get_backend(credential.engine, credential.policy)
    data = backend.read(credential.path, version=version)
    if not isinstance(data, dict):
        raise OpenBaoError('The credential payload is invalid.')
    from netbox_openbao.secrets.identity import verify_bundle_identity

    verify_bundle_identity(credential, data, expected_fingerprint)
    result = {}
    for field, specification in fields.items():
        if field not in data:
            if specification.get('required'):
                raise OpenBaoError('The credential payload is invalid.')
            continue
        value = data[field]
        if not isinstance(value, str) or len(value.encode('utf-8')) > 262144:
            raise OpenBaoError('The credential payload is invalid.')
        result[field] = value
    ttl = min(int(get_config('reveal_ttl') or 300), credential.policy.max_reveal_ttl)
    return result, ttl


@synchronized_material_change
def stage_material(credential, payload, user=None, request=None):
    """
    Write replacement material *without* putting it into service.

    The previous version stays live, so every consumer keeps working while the
    new one is verified. That is the entire reason this exists: rotating a key
    that is deployed to hundreds of hosts by flipping it in one write leaves no
    verification step and no way back except reading an old version by number.
    """
    enforce_policy_access(credential, user, AccessActionChoices.ACTION_STAGE, request=request)

    if credential.has_staged_version:
        raise ValidationError({
            'status': _('This credential already has a staged version. Promote or discard it first.'),
        })

    # A credential written before staged rotation existed has no live pointer,
    # which means "serve latest". Staging under that rule would put the new,
    # unverified version straight into service — the exact outcome staging
    # exists to prevent. Pin the pointer to what is live *now* first.
    if credential.live_kv_version is None and credential.kv_version is not None:
        credential.live_kv_version = credential.kv_version
        credential.save(update_fields=['live_kv_version'])

    return write_material(
        credential,
        payload,
        cas=credential.kv_version,
        user=user,
        request=request,
        action=AccessActionChoices.ACTION_STAGE,
        promote=False,
    )


@synchronized_material_change
def promote_staged(credential, user=None, request=None, verified=False, note=''):
    """
    Put the staged version into service.

    Nothing is written to the backend here — the material is already there.
    Promotion is purely the NetBox-side decision about which version consumers
    are handed, which is why it cannot fail halfway and needs no compensator.
    """
    enforce_policy_access(credential, user, AccessActionChoices.ACTION_PROMOTE, request=request)

    if not credential.has_staged_version:
        raise ValidationError({'status': _('This credential has no staged version to promote.')})

    # Promotion is the moment consumers are committed to a version, so confirm
    # it is actually still there. Flipping the pointer to a version that was
    # destroyed out of band would break every consumer at once — the precise
    # failure this whole workflow exists to avoid — and would do it silently,
    # because nothing reads the material during promotion.
    backend = get_backend(credential.engine, credential.policy)
    try:
        versions = {v['version']: v for v in backend.list_versions(credential.path)}
    except OpenBaoError as exc:
        log_access(
            credential, user, AccessActionChoices.ACTION_PROMOTE, success=False,
            message=str(exc), request=request,
        )
        raise

    staged = versions.get(credential.staged_kv_version)
    if staged is None or staged.get('destroyed') or staged.get('deletion_time'):
        log_access(
            credential, user, AccessActionChoices.ACTION_PROMOTE, success=False,
            message='Staged version is no longer present.', request=request,
        )
        raise ValidationError({
            'status': _('Version {version} is no longer present in OpenBao and cannot be promoted.').format(
                version=credential.staged_kv_version,
            ),
        })

    from netbox_openbao.secrets.identity import promote_key_identity

    identity_fields = promote_key_identity(credential)
    credential.live_kv_version = credential.staged_kv_version
    credential.staged_kv_version = None
    credential.status = CredentialStatusChoices.STATUS_ACTIVE
    credential.last_rotated = timezone.now()
    credential.save(update_fields=['live_kv_version', 'staged_kv_version', 'status', 'last_rotated', *identity_fields])

    # `verified` records that a human or a job confirmed the new material works
    # before it went live. Actually testing it against the device belongs to
    # whatever drives your devices; this is the place that remembers someone
    # did, so the access log can answer "was this rotation checked?" later.
    reason = note or ''
    if verified:
        reason = f'verified: {reason}'.strip().rstrip(':')
    log_access(
        credential, user, AccessActionChoices.ACTION_PROMOTE, success=True,
        reason=reason, request=request,
    )
    return credential


@synchronized_material_change
def discard_staged(credential, user=None, request=None):
    """
    Commit clearing the staged pointer, then remove its exact old version.

    Deletes *only* the staged version. `kv_version` is deliberately left where
    it is: OpenBao's current-version counter does not go backwards when a
    version is deleted, so check-and-set on the next write must still compare
    against the highest number ever issued. That divergence is exactly why
    "is something staged?" needs its own field rather than being inferred from
    a comparison of the two.
    """
    enforce_policy_access(credential, user, AccessActionChoices.ACTION_DISCARD, request=request)

    if not credential.has_staged_version:
        raise ValidationError({'status': _('This credential has no staged version to discard.')})

    staged_version = credential.staged_kv_version
    backend = get_backend(credential.engine, credential.policy)

    from netbox_openbao.secrets.identity import clear_staged_key

    identity_fields = clear_staged_key(credential)
    credential.staged_kv_version = None
    credential.status = CredentialStatusChoices.STATUS_ACTIVE
    credential.save(update_fields=['staged_kv_version', 'status', *identity_fields])

    audit = log_access(
        credential, user, AccessActionChoices.ACTION_DISCARD, success=False,
        reason=f'discarded version {staged_version}', request=request,
        message='Staged pointer cleared; exact-version cleanup is pending commit.',
    )
    current_material_transaction().deletions.append(MaterialAttempt(
        credential, backend, credential.path, user, AccessActionChoices.ACTION_DISCARD,
        version=staged_version, audit_id=getattr(audit, 'pk', None),
    ))
    return credential


def delete_material(credential, user=None, request=None):
    """
    Destroy a credential's material and every version of it.

    Called after the row's deletion has **committed**, so removing a
    `Credential` never leaves its secret behind on the mount — and, equally
    important, never destroys the secret for a deletion that then rolls back.
    Destroying it before the commit made the irreversible half of the operation
    happen first: a later failure in the same transaction restored the row and
    left it pointing at material that no longer existed. Bulk deletion, where
    N rows share one transaction, made that a routine rather than an exotic
    failure.

    `link` is resolved rather than assumed. By the time this runs the row is
    normally gone, so a foreign key to it would raise a deferred violation at
    commit — losing the audit record for the deletion it exists to record.
    """
    backend = get_backend(credential.engine, credential.policy)
    link = _row_exists(credential)
    try:
        backend.delete(credential.path)
    except OpenBaoError as exc:
        log_access(
            credential, user, AccessActionChoices.ACTION_DELETE, success=False,
            message=str(exc), request=request, link=link,
        )
        raise
    log_access(
        credential, user, AccessActionChoices.ACTION_DELETE, success=True, request=request, link=link,
    )
