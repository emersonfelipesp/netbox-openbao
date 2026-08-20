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

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from netbox_openbao.backends import get_backend
from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.choices import AccessActionChoices, CredentialStatusChoices
from netbox_openbao.config import get_config
from netbox_openbao.secrets.registry import extract_metadata, validate_payload

__all__ = (
    'build_custom_metadata',
    'delete_material',
    'discard_staged',
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

    All values must be strings; OpenBao rejects other JSON types here.
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

    from django.conf import settings

    base = (getattr(settings, 'SITE_URL', '') or '').rstrip('/')
    if base:
        try:
            metadata['netbox_url'] = f'{base}{credential.get_absolute_url()}'
        except Exception:
            # A missing URL is cosmetic; it must not fail the write.
            logger.debug('Could not resolve absolute URL for credential %s', credential.pk)
    return metadata


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

def store_credential(persist, credential_type, payload, *, cas=0, user=None, request=None, action=None,
                     subject=None, promote=True):
    """
    Persist a credential row and its material as one unit.

    Args:
        persist: Callable taking the extracted metadata dict and returning the
            saved `Credential`. The REST API passes `serializer.save`; forms
            and internal callers pass a closure over `instance.save()`.
        subject: The Credential this operation concerns, used only to identify
            the audit entry when `persist` itself fails and never returns one.
        promote: Whether the new version becomes the one consumers are served.
            False writes it alongside the live version instead — which is the
            whole point of staging, and the reason resolution has to consult
            `live_kv_version` rather than always taking latest.
        cas: Check-and-set precondition. `0` requires the path not to exist,
            which is what stops a create silently overwriting an existing
            secret at a colliding path. Pass the current `kv_version` when
            updating.

    Returns `(credential, version)`.
    """
    action = action or AccessActionChoices.ACTION_WRITE
    cleaned, metadata = prepare_material(credential_type, payload)

    credential = subject
    written = None  # (backend, path, version) once the material has landed

    try:
        with transaction.atomic():
            credential = persist(metadata)

            backend = get_backend(credential.engine, credential.policy)
            version = backend.write(credential.path, cleaned, cas=cas)
            written = (backend, credential.path, version)

            backend.set_metadata(credential.path, build_custom_metadata(credential))

            credential.kv_version = version
            credential.last_verified = timezone.now()
            update_fields = ['kv_version', 'last_verified']

            if promote:
                # The ordinary path: what was just written is what consumers get.
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

    except Exception as exc:
        # The database has already rolled back by the time we get here. If the
        # backend write landed, its path is now orphaned; remove it.
        if written is not None:
            backend, path, written_version = written
            # Scope of the rollback matters enormously. `cas=0` means the write
            # was only permitted if the path did not already exist, so
            # destroying it wholesale is safe and correct. Any other `cas` is a
            # rotation over material that was already there — removing the
            # whole path would take the working secret with it, turning a
            # recoverable failure into data loss far worse than the orphan the
            # compensator exists to prevent. Remove only what this write added.
            destroy_everything = cas == 0
            try:
                if destroy_everything:
                    backend.delete(path)
                    logger.warning(
                        'Rolled back orphaned OpenBao path %s after a failed credential write', path
                    )
                else:
                    backend.delete(path, versions=[written_version])
                    logger.warning(
                        'Rolled back OpenBao version %s at %s after a failed rotation; '
                        'earlier versions were left intact',
                        written_version, path,
                    )
            except OpenBaoError:
                logger.error(
                    'ORPHANED SECRET: wrote version %s at %s but could not roll it back after a failed '
                    'transaction. CredentialVerifyJob will report it.',
                    written_version, path,
                )
        # The transaction has unwound. A create leaves an in-memory object
        # holding the primary key of an INSERT that no longer exists, so the
        # audit entry must not link to it; an update's original row does still
        # exist, so that one should link. Ask the database which case this is.
        log_access(
            credential, user, action, success=False,
            message=str(exc) if isinstance(exc, OpenBaoError) else 'Credential write failed.',
            request=request,
            link=_row_exists(credential),
        )
        raise

    log_access(credential, user, action, success=True, request=request)
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


def rotate_material(credential, payload, user=None, request=None):
    """
    Write a new version of a credential's material.

    Uses the recorded `kv_version` as the check-and-set precondition so a
    rotation cannot clobber a concurrent write it never saw.
    """
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


def stage_material(credential, payload, user=None, request=None):
    """
    Write replacement material *without* putting it into service.

    The previous version stays live, so every consumer keeps working while the
    new one is verified. That is the entire reason this exists: rotating a key
    that is deployed to hundreds of hosts by flipping it in one write leaves no
    verification step and no way back except reading an old version by number.
    """
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


def promote_staged(credential, user=None, request=None, verified=False, note=''):
    """
    Put the staged version into service.

    Nothing is written to the backend here — the material is already there.
    Promotion is purely the NetBox-side decision about which version consumers
    are handed, which is why it cannot fail halfway and needs no compensator.
    """
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

    credential.live_kv_version = credential.staged_kv_version
    credential.staged_kv_version = None
    credential.status = CredentialStatusChoices.STATUS_ACTIVE
    credential.last_rotated = timezone.now()
    credential.save(update_fields=['live_kv_version', 'staged_kv_version', 'status', 'last_rotated'])

    # `verified` records that a human or a job confirmed the new material works
    # before it went live. Actually testing it against a device belongs to
    # netbox-rpc; this is the place that remembers someone did.
    reason = note or ''
    if verified:
        reason = f'verified: {reason}'.strip().rstrip(':')
    log_access(
        credential, user, AccessActionChoices.ACTION_PROMOTE, success=True,
        reason=reason, request=request,
    )
    return credential


def discard_staged(credential, user=None, request=None):
    """
    Destroy the staged version and leave the live one untouched.

    Deletes *only* the staged version. `kv_version` is deliberately left where
    it is: OpenBao's current-version counter does not go backwards when a
    version is deleted, so check-and-set on the next write must still compare
    against the highest number ever issued. That divergence is exactly why
    "is something staged?" needs its own field rather than being inferred from
    a comparison of the two.
    """
    if not credential.has_staged_version:
        raise ValidationError({'status': _('This credential has no staged version to discard.')})

    staged_version = credential.staged_kv_version
    backend = get_backend(credential.engine, credential.policy)
    try:
        backend.delete(credential.path, versions=[staged_version])
    except OpenBaoError as exc:
        log_access(
            credential, user, AccessActionChoices.ACTION_DISCARD, success=False,
            message=str(exc), request=request,
        )
        raise

    credential.staged_kv_version = None
    credential.status = CredentialStatusChoices.STATUS_ACTIVE
    credential.save(update_fields=['staged_kv_version', 'status'])

    log_access(
        credential, user, AccessActionChoices.ACTION_DISCARD, success=True,
        reason=f'discarded version {staged_version}', request=request,
    )
    return credential


def delete_material(credential, user=None, request=None):
    """
    Destroy a credential's material and every version of it.

    Called from the pre-delete signal so removing a `Credential` row never
    leaves its secret behind on the mount.
    """
    backend = get_backend(credential.engine, credential.policy)
    try:
        backend.delete(credential.path)
    except OpenBaoError as exc:
        log_access(
            credential, user, AccessActionChoices.ACTION_DELETE, success=False,
            message=str(exc), request=request,
        )
        raise
    log_access(credential, user, AccessActionChoices.ACTION_DELETE, success=True, request=request)
