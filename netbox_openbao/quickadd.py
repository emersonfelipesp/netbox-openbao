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


def _visible_ip_addresses(user, ip_addresses):
    """Return the IPs the caller may view, or refuse. Never attach an address the caller cannot see."""
    from ipam.models import IPAddress

    ids = [getattr(ip, 'pk', ip) for ip in ip_addresses]
    if user is None:
        return list(IPAddress.objects.filter(pk__in=ids))
    visible = list(IPAddress.objects.restrict(user, 'view').filter(pk__in=ids))
    if len(visible) != len(set(ids)):
        raise PermissionDenied(_('You do not have permission to use that IP address.'))
    return visible


def _primary_ip_addresses(user, target):
    """The target's own primary IP, when the caller may view it; the default connection address."""
    from ipam.models import IPAddress

    primary = getattr(target, 'primary_ip', None)
    if primary is None:
        return []
    # A default, not a request: a primary IP the caller cannot view is simply not used, so it
    # never blocks reusing a service that already has an address.
    visible = IPAddress.objects.filter(pk=primary.pk)
    if user is not None:
        visible = visible.restrict(user, 'view')
    return list(visible)


def _new_ip_address(user, cidr):
    """Create the connection IP, or reuse the visible no-VRF address with the same CIDR.

    NetBox allows duplicate addresses, so a quick-add that always created one
    would leave a second row beside the existing one and make the service
    ambiguous. Creating needs the caller's own IPAM permission, never the
    credential one.
    """
    import netaddr
    from ipam.models import IPAddress

    try:
        network = netaddr.IPNetwork(str(cidr).strip())
    except (netaddr.AddrFormatError, ValueError, TypeError):
        raise ValidationError(
            _('Enter the IP address as an address with a prefix length, for example 10.0.0.5/24.')
        ) from None
    if '/' not in str(cidr):
        raise ValidationError(_('Enter the IP address as an address with a prefix length, for example 10.0.0.5/24.'))
    # Two requests for the same address must not both miss the lookup and both insert, so
    # same-CIDR lookup and creation are serialized for the rest of the transaction.
    from django.db import connection

    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', [f'netbox_openbao.quickadd.ip:{network}'])
    existing = IPAddress.objects.filter(vrf__isnull=True, address=str(network))
    if user is not None:
        existing = existing.restrict(user, 'view')
    matches = list(existing[:2])
    if len(matches) > 1:
        raise ValidationError(_('More than one IP address %(address)s exists; choose one.') % {'address': network})
    if matches:
        return matches
    if user is not None:
        if not user.has_perm('ipam.add_ipaddress'):
            raise PermissionDenied('ipam.add_ipaddress is required to create the IP address.')
    created = IPAddress(address=str(network), status='active', description='SSH access (quick-add)')
    created.full_clean()
    created.save()
    if user is not None and not IPAddress.objects.restrict(user, 'add').filter(pk=created.pk).exists():
        raise PermissionDenied('ipam.add_ipaddress does not permit this IP address.')
    return [created]


def _connection_ip_addresses(user, target, ip_addresses, new_ip_address):
    """Pick the IP for the new service: given, newly created, or the target's primary IP."""
    if ip_addresses and new_ip_address:
        raise ValidationError(_('Choose an existing IP address or enter a new one, not both.'))
    if new_ip_address:
        return _new_ip_address(user, new_ip_address)
    if ip_addresses:
        return ip_addresses
    return _primary_ip_addresses(user, target)


def _require_requested_ip_on_existing_service(service, ip_addresses):
    """Refuse an explicitly requested address that a reused service does not have.

    A reused service keeps the address it already has, so quietly connecting through
    that address while a different one was asked for (and possibly just created)
    would commit an unattached IP and send the credential to another host.
    """
    attached = set(service.ipaddresses.values_list('pk', flat=True))
    if attached and not {ip.pk for ip in ip_addresses} <= attached:
        raise ValidationError(
            _('The existing "%(name)s" service already has a different IP address; change it in NetBox, '
              'or leave the address empty to keep it.') % {'name': service.name}
        )


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
    if ip_addresses:
        ip_addresses = _visible_ip_addresses(user, ip_addresses)
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
        if ip_addresses and not existing.ipaddresses.exists():
            _require_service_permission(user, 'change', existing)
            existing.ipaddresses.set(ip_addresses)
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
    new_ip_address=None,
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

    The service needs exactly one IP to be usable. Pass an existing ``ip_addresses``
    list, or ``new_ip_address`` (a CIDR string) to create the address here in the
    same transaction; with neither, the target's primary IP is used when it has one.

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
        explicit_ip = bool(ip_addresses or new_ip_address)
        ip_addresses = _connection_ip_addresses(user, target, ip_addresses, new_ip_address)
        service, _created = _get_or_create_service(
            target,
            template,
            port,
            service_name or (template.name.lower() if template is not None else SSH_SERVICE_NAME),
            ip_addresses,
            user,
        )
        if explicit_ip and not _created:
            _require_requested_ip_on_existing_service(service, ip_addresses)

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
