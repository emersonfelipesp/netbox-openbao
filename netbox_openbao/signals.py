"""
Signal handlers keeping NetBox and OpenBao from drifting apart.
"""

import logging

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .backends.exceptions import OpenBaoError
from .models import Credential, CredentialAssignment

logger = logging.getLogger('netbox.plugins.netbox_openbao')


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


@receiver([post_save, post_delete], sender=CredentialAssignment)
def refresh_custom_metadata(instance, **kwargs):
    """
    Keep the KV `custom_metadata` assignment list current.

    That list is what lets tooling outside NetBox discover which objects a
    secret belongs to; if it went stale on every reassignment it would be worse
    than absent, because it would be confidently wrong.

    Best-effort: a metadata refresh must never fail an assignment change.
    """
    from .backends import get_backend
    from .services import build_custom_metadata

    credential = instance.credential
    try:
        backend = get_backend(credential.engine, credential.policy)
        backend.set_metadata(credential.path, build_custom_metadata(credential))
    except OpenBaoError:
        logger.warning(
            'Could not refresh OpenBao custom metadata for credential %s; it is now stale.',
            credential.pk,
        )
    except Exception:
        logger.exception('Unexpected error refreshing OpenBao custom metadata for credential %s', credential.pk)
