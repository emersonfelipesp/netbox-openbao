"""
Signal handlers keeping NetBox and OpenBao from drifting apart.
"""

import logging

from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver

from .backends.exceptions import OpenBaoError
from .models import Credential, CredentialAssignment

logger = logging.getLogger('netbox.plugins.netbox_openbao')


@receiver(pre_delete, sender=Credential)
def destroy_material_on_delete(instance, **kwargs):
    """
    Destroy a credential's material when its row is deleted.

    Without this, deleting a credential in NetBox would leave the secret on the
    mount with nothing referencing it — an orphan that no longer appears in any
    inventory but is still readable by anything holding the tier's AppRole.

    A backend failure is logged rather than raised: blocking the delete would
    leave the operator unable to remove a credential whose engine is
    unreachable, and `CredentialVerifyJob` reports the residue either way.
    """
    from .services import delete_material

    try:
        delete_material(instance)
    except OpenBaoError:
        logger.error(
            'ORPHANED SECRET: could not destroy %s on engine %s while deleting credential %s. '
            'CredentialVerifyJob will report it.',
            instance.path,
            instance.engine.slug,
            instance.pk,
        )


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
