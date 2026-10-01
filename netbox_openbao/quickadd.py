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

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import CredentialTypeChoices, PurposeChoices, SSHKeyTypeChoices
from netbox_openbao.config import get_config
from netbox_openbao.material_transactions import material_operation
from netbox_openbao.models import Credential, CredentialAssignment
from netbox_openbao.secrets.generators import generate_ssh_keypair
from netbox_openbao.services import store_credential

__all__ = ('SSH_SERVICE_NAME', 'SSH_TEMPLATE_NAME', 'get_ssh_service_template', 'quick_add_ssh')

logger = logging.getLogger('netbox.plugins.netbox_openbao.quickadd')

SSH_SERVICE_NAME = 'ssh'
DEFAULT_SSH_PORT = 22
SSH_TEMPLATE_NAME = 'SSH'


def _accept_credential(_credential):
    """Default late-conformance callback for non-HTTP callers."""


def _service_model():
    from ipam.models import Service

    return Service


def get_ssh_service_template():
    """The seeded `SSH` service template, or None if an operator removed it."""
    from ipam.models import ServiceTemplate

    return ServiceTemplate.objects.filter(name__iexact=SSH_TEMPLATE_NAME).first()


def _port_mappings(template, port):
    """
    `port_mappings` for a new service: the template's, with `port` applied.

    NetBox 4.7 stores a service's ports as one `protocol/port` array. The first
    TCP mapping of the template is replaced by the chosen port; a template with
    no TCP mapping gains one. `port=None` keeps the template exactly as it is.
    """
    mappings = list(template.port_mappings) if template is not None else []
    if port is None:
        return mappings or [f'tcp/{DEFAULT_SSH_PORT}']

    chosen = f'tcp/{port}'
    for index, mapping in enumerate(mappings):
        if mapping.lower().startswith('tcp/'):
            mappings[index] = chosen
            return list(dict.fromkeys(mappings))
    return [*mappings, chosen]


def _require_service_permission(user, action, service):
    """Creating or widening a Service needs the caller's own IPAM permission.

    Credential-creation rights do not confer IPAM mutation. `user=None` is a
    non-HTTP caller that has already been authorized by its own code path.
    """
    if user is None:
        return
    if not user.has_perm(f'ipam.{action}_service'):
        raise PermissionDenied(f'ipam.{action}_service is required to manage the SSH service.')
    if service is not None:
        from ipam.models import Service

        if not Service.objects.restrict(user, action).filter(pk=service.pk).exists():
            raise PermissionDenied(f'ipam.{action}_service does not permit this service.')


def _get_or_create_service(target, template, port, name, ip_addresses=None, user=None):
    """
    Find or create the Application Service on `target` that holds the credential.

    An existing service of the same name on the same parent is reused and
    widened to cover the chosen port, never replaced.
    """
    from django.contrib.contenttypes.models import ContentType

    Service = _service_model()
    parent_type = ContentType.objects.get_for_model(target)
    mappings = _port_mappings(template, port)
    if not any(m.lower().startswith('tcp/') for m in mappings):
        raise ValidationError(_('The service template must define a TCP port for SSH.'))

    # Service has no uniqueness constraint on (parent, name), so concurrent
    # quick-adds are serialized on the parent row. The lookup then locks the
    # existing service, so concurrent widening cannot drop a requested port.
    type(target).objects.select_for_update().filter(pk=target.pk).first()
    existing = Service.objects.select_for_update().filter(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=name,
    ).first()
    if existing is not None:
        if not any(m.lower().startswith('tcp/') for m in existing.port_mappings):
            raise ValidationError(
                _('A service named "%(name)s" already exists on this object and is not a TCP service.')
                % {'name': name}
            )
        missing = [m for m in mappings if m not in existing.port_mappings]
        if missing:
            _require_service_permission(user, 'change', existing)
            existing.port_mappings = [*existing.port_mappings, *missing]
            existing.full_clean()
            existing.save()
        return existing, False

    _require_service_permission(user, 'add', None)
    service = Service(
        parent_object_type=parent_type,
        parent_object_id=target.pk,
        name=name,
        port_mappings=mappings,
    )
    if template is not None and template.description:
        service.description = template.description
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
    port=None,
    service_template=None,
    service_name=None,
    ip_addresses=None,
    purpose=PurposeChoices.PURPOSE_LOGIN,
    user=None,
    request=None,
    conform=_accept_credential,
):
    """
    Give `target` SSH access, in one transaction.

    The credential is tied to an SSH Application Service (`ipam.Service`) on
    `target`, created from `service_template` (default: the seeded ``SSH``
    template) and `port`. The credential is assigned to that service only —
    the chain is Credential > Application Service > Device or VM.

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
        template = service_template or get_ssh_service_template()
        if template is not None and user is not None:
            from ipam.models import ServiceTemplate

            if not ServiceTemplate.objects.restrict(user, 'view').filter(pk=template.pk).exists():
                raise PermissionDenied('The selected service template is not permitted.')
        service, _created = _get_or_create_service(
            target,
            template,
            port,
            service_name or (template.name.lower() if template is not None else SSH_SERVICE_NAME),
            ip_addresses,
            user,
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

        _assign(credential, service, purpose)

        # Authorization constraints on a newly created credential can only be
        # evaluated after its final metadata and assignments exist. Invoke the
        # caller's check here, after every mutation but before the database
        # transaction and material owner can commit, so refusal compensates the
        # owned backend version and rolls back the entire graph.
        conform(credential)

    return credential, service, generated_public_key


def _assign(credential, obj, purpose):
    from django.contrib.contenttypes.models import ContentType

    assignment, created = CredentialAssignment.objects.get_or_create(
        credential=credential,
        assigned_object_type=ContentType.objects.get_for_model(obj),
        assigned_object_id=obj.pk,
        purpose=purpose,
    )
    return assignment, created
