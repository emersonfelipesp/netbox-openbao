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
from netbox_openbao.material_transactions import material_operation
from netbox_openbao.models import Credential, CredentialAssignment
from netbox_openbao.nms_bridge import sync_ssh_password_to_nms
from netbox_openbao.secrets.generators import generate_ssh_keypair
from netbox_openbao.services import store_credential

__all__ = ('SSH_SERVICE_NAME', 'quick_add_ssh')

logger = logging.getLogger('netbox.plugins.netbox_openbao.quickadd')

SSH_SERVICE_NAME = 'ssh'
DEFAULT_SSH_PORT = 22


def _accept_credential(_credential):
    """Default late-conformance callback for non-HTTP callers."""


def _service_model():
    from ipam.models import Service

    return Service


def _services_are_assignable():
    return 'ipam.service' in assignable_model_labels()


def _service_uses_port_mappings():
    """Whether this NetBox represents a service's ports as `port_mappings`.

    4.7 replaced `protocol` + `ports` with a single `port_mappings` array of
    `"tcp/22"` strings. Detected from the model's own field set rather than
    from a version string, because the field is the thing actually being used —
    a version comparison would be a second, weaker statement of the same fact,
    and would need editing again at 4.8.
    """
    Service = _service_model()
    return any(field.name == 'port_mappings' for field in Service._meta.get_fields())


def _service_port_kwargs(port):
    """Model kwargs describing "TCP on `port`", in whichever shape this NetBox uses."""
    if _service_uses_port_mappings():
        return {'port_mappings': [f'tcp/{port}']}

    from ipam.choices import ServiceProtocolChoices

    return {'protocol': ServiceProtocolChoices.PROTOCOL_TCP, 'ports': [port]}


def _service_has_port(service, port):
    if _service_uses_port_mappings():
        return f'tcp/{port}' in service.port_mappings
    from ipam.choices import ServiceProtocolChoices

    return service.protocol == ServiceProtocolChoices.PROTOCOL_TCP and port in service.ports


def _add_port_to_service(service, port):
    """Widen an existing service to also cover `port`.

    On 4.6 a service carries one protocol and a list of ports, so a service
    that is not already TCP cannot be widened to a TCP port by appending — the
    protocol itself would have to change, silently altering what the existing
    service means. That is left alone and reported, rather than repurposed.
    """
    if _service_uses_port_mappings():
        service.port_mappings = [*service.port_mappings, f'tcp/{port}']
        return True

    from ipam.choices import ServiceProtocolChoices

    if service.protocol != ServiceProtocolChoices.PROTOCOL_TCP:
        logger.warning(
            'Service %s on %s is %s, not TCP; leaving it alone rather than '
            'changing the protocol of an existing service.',
            service.name, service.parent, service.protocol,
        )
        return False

    service.ports = [*service.ports, port]
    return True


def _get_or_create_service(target, port, ip_addresses=None):
    """
    Find or create the SSH service on `target`.

    Supports both port representations. NetBox 4.7 replaced `protocol` +
    `ports` with a single `port_mappings` array; the parent GenericForeignKey
    is common to 4.6 and 4.7, so only the ports differ.
    """
    from django.contrib.contenttypes.models import ContentType

    Service = _service_model()
    parent_type = ContentType.objects.get_for_model(target)

    existing = Service.objects.filter(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=SSH_SERVICE_NAME,
    ).first()
    if existing is not None:
        if not _service_has_port(existing, port) and _add_port_to_service(existing, port):
            existing.full_clean()
            existing.save()
        return existing, False

    service = Service(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=SSH_SERVICE_NAME,
        **_service_port_kwargs(port),
    )
    service.full_clean()
    service.save()
    if ip_addresses:
        service.ipaddresses.set(ip_addresses)
    return service, True


@material_operation
def quick_add_ssh(
    target,
    policy,
    *,
    username,
    name=None,
    existing_credential=None,
    private_key=None,
    passphrase=None,
    password=None,
    auth_method='keypair',
    generate=False,
    key_type=None,
    port=DEFAULT_SSH_PORT,
    create_service=True,
    ip_addresses=None,
    purpose=PurposeChoices.PURPOSE_LOGIN,
    user=None,
    request=None,
    sync_nms=True,
    conform=_accept_credential,
):
    """
    Give `target` SSH access, in one transaction.

    Password auth stores ``TYPE_SSH_PASSWORD`` in OpenBao. Keypair auth uses
    exactly one of ``existing_credential``, ``private_key``, or ``generate``.

    Returns ``(credential, service, public_key)``. ``public_key`` is only
    populated when a key was generated here.
    """
    auth_method = auth_method or 'keypair'
    if auth_method == 'password':
        if not password:
            raise ValidationError(_('An SSH login password is required.'))
        sources = [False, False, False]
    else:
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
        elif auth_method == 'password':
            credential = Credential(
                name=name or f'{target} ssh',
                credential_type=CredentialTypeChoices.TYPE_SSH_PASSWORD,
                policy=policy,
                engine=policy.engine,
                username=username,
            )
            payload = {'password': password}

            def persist(metadata, credential=credential):
                for field, value in metadata.items():
                    setattr(credential, field, value)
                credential.full_clean()
                credential.save()
                return credential

            credential, _version = store_credential(
                persist,
                CredentialTypeChoices.TYPE_SSH_PASSWORD,
                payload,
                cas=0,
                user=user,
                request=request,
                subject=credential,
            )
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

        if auth_method == 'password' and sync_nms:
            sync_ssh_password_to_nms(
                target,
                username=username,
                password=password,
                name=name or f'{target} ssh',
                port=port,
                user=user,
                request=request,
            )

        # Authorization constraints on a newly created credential can only be
        # evaluated after its final metadata and assignments exist. Invoke the
        # caller's check here, after every mutation but before the database
        # transaction and material owner can commit, so refusal compensates the
        # owned backend version and rolls back the entire graph.
        conform(credential)

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
