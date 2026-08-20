"""
Quick-add: give a device or VM SSH access in one action.

Doing this by hand means three forms — create an `ipam.Service`, create a
`Credential`, create a `CredentialAssignment` — for what is, in practice, the
single most common thing anyone does with this plugin.

Everything here goes through `services.store_credential`, so the write-path
compensator covers it. A bespoke write here would be a second place for
material to leak and a second source of orphaned secrets, which is exactly what
the single-chokepoint design exists to prevent.
"""

import logging

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import CredentialTypeChoices, PurposeChoices, SSHKeyTypeChoices
from netbox_openbao.config import assignable_model_labels, get_config
from netbox_openbao.models import Credential, CredentialAssignment
from netbox_openbao.secrets.generators import generate_ssh_keypair
from netbox_openbao.services import store_credential

__all__ = ('SSH_SERVICE_NAME', 'quick_add_ssh')

logger = logging.getLogger('netbox.plugins.netbox_openbao.quickadd')

SSH_SERVICE_NAME = 'ssh'
DEFAULT_SSH_PORT = 22


def _service_model():
    from ipam.models import Service

    return Service


def _services_are_assignable():
    return 'ipam.service' in assignable_model_labels()


def _get_or_create_service(target, port, ip_addresses=None):
    """
    Find or create the SSH service on `target`.

    NetBox 4.7 changed both halves of this. A service's protocol and port are
    now a single `port_mappings` array of `"tcp/22"` strings, and it binds to
    its parent through a GenericForeignKey rather than a device or VM foreign
    key. Code written against 4.6 fails on both counts.
    """
    from django.contrib.contenttypes.models import ContentType

    Service = _service_model()
    mapping = f'tcp/{port}'
    parent_type = ContentType.objects.get_for_model(target)

    existing = Service.objects.filter(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=SSH_SERVICE_NAME,
    ).first()
    if existing is not None:
        if mapping not in existing.port_mappings:
            existing.port_mappings = [*existing.port_mappings, mapping]
            existing.full_clean()
            existing.save()
        return existing, False

    service = Service(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=SSH_SERVICE_NAME,
        port_mappings=[mapping],
    )
    service.full_clean()
    service.save()
    if ip_addresses:
        service.ipaddresses.set(ip_addresses)
    return service, True


def quick_add_ssh(
    target,
    policy,
    *,
    username,
    name=None,
    existing_credential=None,
    private_key=None,
    passphrase=None,
    generate=False,
    key_type=None,
    port=DEFAULT_SSH_PORT,
    create_service=True,
    ip_addresses=None,
    purpose=PurposeChoices.PURPOSE_LOGIN,
    user=None,
    request=None,
):
    """
    Give `target` SSH access, in one transaction.

    Exactly one of `existing_credential`, `private_key`, or `generate` decides
    where the material comes from.

    Returns `(credential, service, public_key)`. `public_key` is only populated
    when a key was generated here — it is returned so the operator can paste it
    straight into `authorized_keys`, and it is the *only* half of a generated
    pair that ever leaves this function.
    """
    sources = [bool(existing_credential), bool(private_key), bool(generate)]
    if sum(sources) != 1:
        raise ValidationError(
            _('Choose exactly one of: reuse an existing credential, paste a private key, or generate one.')
        )

    generated_public_key = ''

    with transaction.atomic():
        service = None
        if create_service and _services_are_assignable():
            service, _created = _get_or_create_service(target, port, ip_addresses)
        elif create_service:
            # Configured out rather than failed: an estate that does not model
            # services still wants the credential on the device.
            logger.info(
                'ipam.service is not in assignable_models; skipping service creation for %s', target
            )

        if existing_credential is not None:
            credential = existing_credential
        else:
            if generate:
                # Falling through to generate_ssh_keypair's own default is not
                # enough: passing None explicitly overrides it. Honour the
                # deployment's configured type, which is what an operator who
                # set it expects.
                pair = generate_ssh_keypair(
                    key_type or get_config('default_ssh_key_type') or SSHKeyTypeChoices.TYPE_ED25519
                )
                payload = {'private_key': pair['private_key']}
                generated_public_key = pair['public_key']
            else:
                payload = {'private_key': private_key}
                if passphrase:
                    payload['passphrase'] = passphrase

            credential = Credential(
                name=name or f'{target} ssh',
                credential_type=CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                policy=policy,
                engine=policy.engine,
                username=username,
            )

            def persist(metadata, credential=credential):
                for field, value in metadata.items():
                    setattr(credential, field, value)
                credential.full_clean()
                credential.save()
                return credential

            credential, _version = store_credential(
                persist,
                CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                payload,
                cas=0,
                user=user,
                request=request,
                subject=credential,
            )

        # Bind to the service when there is one, and to the object itself
        # otherwise — the point of the action is that the target ends up with a
        # credential attached, not that a service exists.
        assignment_target = service if service is not None else target
        _assign(credential, assignment_target, purpose)

        if service is not None and _is_assignable(target):
            _assign(credential, target, purpose)

    return credential, service, generated_public_key


def _is_assignable(obj):
    label = f'{obj._meta.app_label}.{obj._meta.model_name}'
    return label in assignable_model_labels()


def _assign(credential, obj, purpose):
    from django.contrib.contenttypes.models import ContentType

    assignment, created = CredentialAssignment.objects.get_or_create(
        credential=credential,
        assigned_object_type=ContentType.objects.get_for_model(obj),
        assigned_object_id=obj.pk,
        purpose=purpose,
    )
    return assignment, created
