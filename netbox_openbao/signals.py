"""
Signal handlers keeping NetBox and OpenBao from drifting apart.
"""

import logging

from django.db import transaction
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver

from .backends.exceptions import OpenBaoError
from .models import Credential, CredentialAssignment, OpenBaoSettings

logger = logging.getLogger('netbox.plugins.netbox_openbao')


@receiver(pre_delete, sender=Credential)
def serialize_material_delete(instance, using, **kwargs):
    """Order credential deletion against any in-flight metadata publisher."""
    from .services import lock_custom_metadata_projection

    lock_custom_metadata_projection(instance.pk, using)


@receiver(pre_delete, sender=OpenBaoSettings)
def prevent_settings_delete(instance, using, **kwargs):
    """Apply the model deletion guard to QuerySet.delete() as well."""
    if not getattr(instance, '_settings_delete_guard_checked', False):
        instance._lock_for_prefix_write(using)
        instance._ensure_deletable(using)


@receiver(post_save, sender=OpenBaoSettings)
def audit_settings_change(instance, created, **kwargs):
    """
    Record a settings change where the reveals it governs are recorded.

    On the **signal**, not in the edit view, and deliberately. `ObjectEditView`
    builds its form directly and calls `form.save()` inside its own transaction
    — it never routes through `get_form()` or `form_valid()`, and reimplementing
    `post()` is what an earlier revision of this plugin did before silently
    losing `restrict_form_fields()` and changelog snapshots. More importantly a
    signal covers **every** write: the UI, the REST API, and a management
    command alike. `change_openbaosettings` can widen the reveal rate limit,
    which bounds how fast a leaked token drains the store, so an audit that only
    saw one of those surfaces would be the wrong audit.

    The actor comes from NetBox's request context, which `forms.py` already
    relies on. A save with no request — a migration, a shell — records no user,
    which is accurate rather than convenient.
    """
    from netbox.context import current_request

    from .choices import AccessActionChoices  # noqa: F401  (documents the action used)
    from .services import log_settings_change

    request = current_request.get()
    changed = sorted(getattr(instance, '_openbao_changed_fields', ()) or ())

    if not created and not changed:
        # A save that altered nothing is not a configuration change. Recording
        # it would dilute the log this exists to make readable.
        return

    log_settings_change(
        getattr(request, 'user', None),
        request=request,
        changed_fields=changed or ['created'],
    )


@receiver(post_delete, sender=OpenBaoSettings)
def audit_settings_deletion(instance, **kwargs):
    """
    Deleting the row is a configuration change, not an absence of one.

    Configuration falls back to `PLUGINS_CONFIG` and then the built-in defaults,
    which can mean a different path prefix and weaker values such as generation
    being permitted again. That is exactly the kind of change the log exists to
    show, so it is recorded rather than leaving a gap where a settings row used
    to be.
    """
    from netbox.context import current_request

    from .services import log_settings_change

    request = current_request.get()
    log_settings_change(
        getattr(request, 'user', None),
        request=request,
        message='Settings row deleted; configuration falls back to PLUGINS_CONFIG',
    )


@receiver([post_save, post_delete], sender=OpenBaoSettings)
def clear_settings_memo(using, **kwargs):
    """Make the next read observe a saved row or the restored fallback."""
    from .config import clear_config

    # Signals run before their surrounding transaction commits. Record an
    # in-flight write so reads until it ends bypass the memo instead of caching
    # a row that may still be rolled back.
    clear_config(pending_write=True, using=using)


@receiver(post_delete, sender=Credential)
def destroy_material_on_delete(instance, **kwargs):
    """
    Destroy a credential's material once its deletion has committed.

    Without this, deleting a credential in NetBox would leave the secret on the
    mount with nothing referencing it — an orphan that no longer appears in any
    inventory but is still readable by anything holding the tier's AppRole.

    **`post_delete` plus `on_commit`, not `pre_delete`.** Destroying a secret
    cannot be undone and a database transaction can be, so doing the
    irreversible half first gets the ordering exactly backwards: any later
    failure in the same transaction restores the row and leaves it pointing at
    material that no longer exists. Bulk deletion makes that routine rather
    than exotic — `perform_bulk_destroy()` puts N deletions in one transaction,
    so one failure at the end destroyed the material of every credential before
    it while restoring all their rows.

    Deferring to commit trades that for the opposite residue: if the backend
    call then fails, the row is already gone and the material is not. That
    residue is *recoverable* — the secret is still there to be found and
    removed — where the other is not, so it is the right way round. It is
    logged at ERROR with the engine and path, because nothing else can find it:
    `CredentialVerifyJob` iterates existing rows, and by then there is no row
    to iterate. Finding it means listing the mount for `managed_by:
    netbox-openbao` material with no matching credential, which is a follow-up.

    A backend failure is logged rather than raised for the same reason it
    always was: by the time this runs the deletion is committed, so raising
    could not undo it and would only turn a logged residue into a 500.
    """
    from .services import delete_material

    # Captured now, not read inside the callback. Django's Collector sets
    # `instance.pk = None` as part of deleting it, so by the time this runs the
    # log line below would name no credential at all — losing the one
    # identifier an operator needs to go and find the residue.
    identity = {
        'pk': instance.pk,
        'uuid': instance.uuid,
        'path': instance.path,
        'engine': instance.engine.slug,
    }

    def destroy():
        try:
            delete_material(instance)
        except OpenBaoError:
            logger.error(
                'ORPHANED SECRET: credential %s (%s) was deleted but its material at %s on engine '
                '%s could not be destroyed. It is still readable by anything holding that tier\'s '
                'AppRole, and no job will find it — there is no row left to scan from. '
                'Remove it by hand.',
                identity['pk'], identity['uuid'], identity['path'], identity['engine'],
            )
        except Exception:
            # Deliberately broad, and deliberately not re-raised. This runs
            # from `run_and_clear_commit_hooks()`, *after* the deletion has
            # committed — an exception escaping here becomes a 500 on a request
            # whose database change already succeeded, and cannot undo it.
            # Anything the backends failed to translate lands here.
            logger.exception(
                'ORPHANED SECRET: credential %s (%s) was deleted and destroying its material at '
                '%s on engine %s raised an untranslated error. Remove it by hand.',
                identity['pk'], identity['uuid'], identity['path'], identity['engine'],
            )

    transaction.on_commit(destroy)


@receiver(pre_save, sender=CredentialAssignment)
def capture_previous_credential(instance, using, **kwargs):
    """Capture the durable previous owner before Django mutates the instance."""
    if instance.pk is None:
        instance._openbao_previous_credential_id = None
        return
    previous = (
        CredentialAssignment.objects.using(using)
        .filter(pk=instance.pk)
        .values_list('credential_id', flat=True)
        .first()
    )
    instance._openbao_previous_credential_id = previous


@receiver([post_save, post_delete], sender=CredentialAssignment)
def refresh_custom_metadata(instance, using, **kwargs):
    """
    Keep the KV `custom_metadata` assignment list current.

    That list is what lets tooling outside NetBox discover which objects a
    secret belongs to; if it went stale on every reassignment it would be worse
    than absent, because it would be confidently wrong.

    Publishing is deferred until commit, reloads the final database state, and
    uses durable IDs only. A rollback therefore publishes nothing; a
    reassignment refreshes both the old and new owners.
    """
    from .services import defer_custom_metadata

    previous_id = getattr(instance, '_openbao_previous_credential_id', None)
    defer_custom_metadata((previous_id, instance.credential_id), using=using)
