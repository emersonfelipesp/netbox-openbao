"""
Create or update a service endpoint together with its credential, atomically.

Composing "create a credential, then create the endpoint that uses it" in a
client leaves persisted secret material behind whenever the second request
fails, and a retry creates a duplicate. This module does both inside one
database transaction and one material write, the same way `quickadd` does for
SSH access: the credential goes through `services.store_credential`, so the
write-path compensator removes the OpenBao version if anything after it fails.

It also refuses a credential whose type cannot serve the endpoint's protocol,
so a service is never left configured with material its consumers cannot use.
"""

import hashlib
import json

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import CredentialTypeChoices, ServiceTypeChoices
from netbox_openbao.models import Credential, ServiceEndpoint
from netbox_openbao.services import store_credential

__all__ = ('COMPATIBLE_CREDENTIAL_TYPES', 'check_credential_compatible', 'upsert_endpoint_with_credential')

_LOGIN_TYPES = frozenset({
    CredentialTypeChoices.TYPE_PASSWORD,
    CredentialTypeChoices.TYPE_SSH_PASSWORD,
    'ssh_password',
})

#: Credential types each service protocol can use. Seeded import schemas
#: (``ssh_password``, ``ssh_key``, ``snmp_v2c``, ``snmp_v3``) sit beside the
#: built-in types so imported credentials stay usable.
COMPATIBLE_CREDENTIAL_TYPES = {
    ServiceTypeChoices.TYPE_SSH: _LOGIN_TYPES | {CredentialTypeChoices.TYPE_SSH_KEYPAIR, 'ssh_key'},
    ServiceTypeChoices.TYPE_TELNET: _LOGIN_TYPES,
    ServiceTypeChoices.TYPE_NETCONF: _LOGIN_TYPES | {CredentialTypeChoices.TYPE_SSH_KEYPAIR, 'ssh_key'},
    ServiceTypeChoices.TYPE_RESTCONF: _LOGIN_TYPES,
    ServiceTypeChoices.TYPE_GNMI: _LOGIN_TYPES,
    ServiceTypeChoices.TYPE_HTTP: _LOGIN_TYPES | {CredentialTypeChoices.TYPE_API_TOKEN},
    ServiceTypeChoices.TYPE_SNMP: frozenset({'snmp_v2c', 'snmp_v3'}),
}


def _accept(_credential):
    """Default late-conformance callback for non-HTTP callers."""


def check_credential_compatible(service_type, credential_type):
    """Raise ValidationError unless `credential_type` can serve `service_type`."""
    allowed = COMPATIBLE_CREDENTIAL_TYPES.get(service_type, frozenset())
    if credential_type not in allowed:
        raise ValidationError({
            'credential_type': _('A %(ctype)s credential cannot be used for a %(stype)s service.') % {
                'ctype': credential_type,
                'stype': service_type,
            }
        })


def _create_credential(new_credential, *, import_source, user, request):
    credential = Credential(
        import_source=import_source,
        name=new_credential['name'],
        credential_type=new_credential['credential_type'],
        policy=new_credential['policy'],
        engine=new_credential['policy'].engine,
        username=new_credential.get('username') or '',
    )

    def persist(metadata, credential=credential):
        for field, value in metadata.items():
            setattr(credential, field, value)
        credential.full_clean()
        credential.save()
        return credential

    credential, _version = store_credential(
        persist,
        new_credential['credential_type'],
        new_credential['secret_data'],
        cas=0,
        user=user,
        request=request,
        subject=credential,
    )
    return credential


def _request_fingerprint(target, endpoint_fields, new_credential):
    """A digest of the request's non-secret shape, so a key cannot be reused for another request."""
    canonical = json.dumps({
        'target': [target._meta.label_lower, target.pk],
        'service_type': endpoint_fields['service_type'],
        'port': endpoint_fields['port'],
        'credential_type': new_credential['credential_type'],
        'policy': new_credential['policy'].pk,
        'name': new_credential['name'],
        'username': new_credential.get('username') or '',
    }, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _idempotency_prefix(idempotency_key, user):
    return f'idempotency:{getattr(user, "pk", "system")}:{idempotency_key}:'


def _claim_replay(idempotency_key, user, fingerprint):
    """Serialize claims on one key and return the credential it already created, if any.

    The key is scoped to the acting user, and bound to the request's
    fingerprint: replaying it with a different request is refused rather than
    silently binding the first request's credential.
    """
    prefix = _idempotency_prefix(idempotency_key, user)
    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))', [prefix])
    existing = Credential.objects.filter(import_source__startswith=prefix).first()
    if existing is not None and existing.import_source != prefix + fingerprint:
        raise ValidationError({'idempotency_key': _('This key was already used for a different request.')})
    return existing


def _conform_endpoint(endpoint, created, user):
    """Enforce constrained add/change ObjectPermissions on the saved endpoint."""
    if user is None:
        return
    # The endpoint row lock may have been waited on; re-read permissions.
    user.__dict__.pop('_object_perm_cache', None)
    action = 'add' if created else 'change'
    if not ServiceEndpoint.objects.restrict(user, action).filter(pk=endpoint.pk).exists():
        raise PermissionDenied(_('The service endpoint is outside the permitted scope.'))


def _save_endpoint(target, endpoint_fields, credential, user=None):
    content_type = ContentType.objects.get_for_model(target)
    queryset = ServiceEndpoint.objects.restrict(user, 'change') if user is not None else ServiceEndpoint.objects
    if user is not None and ServiceEndpoint.objects.filter(
        assigned_object_type=content_type, assigned_object_id=target.pk,
        service_type=endpoint_fields['service_type'], port=endpoint_fields['port'],
    ).exclude(pk__in=queryset.values('pk')).exists():
        raise PermissionDenied(_('The existing service endpoint is outside the permitted scope.'))
    endpoint = queryset.select_for_update().filter(
        assigned_object_type=content_type,
        assigned_object_id=target.pk,
        service_type=endpoint_fields['service_type'],
        port=endpoint_fields['port'],
    ).first()
    created = endpoint is None
    if created:
        endpoint = ServiceEndpoint(assigned_object_type=content_type, assigned_object_id=target.pk)
    for field, value in endpoint_fields.items():
        setattr(endpoint, field, value)
    endpoint.credential = credential
    endpoint.full_clean()
    endpoint.save()
    _conform_endpoint(endpoint, created, user)
    return endpoint, created


def upsert_endpoint_with_credential(
    target,
    endpoint_fields,
    *,
    existing_credential=None,
    new_credential=None,
    idempotency_key=None,
    user=None,
    request=None,
    conform=_accept,
    reauthorize=None,
):
    """
    Bind a new or existing credential to `target`'s endpoint in one transaction.

    `endpoint_fields` holds `service_type`, `port`, and optionally `host`,
    `options`, `ssh_known_hosts_entry`, `ssh_strict_host_key_checking`.
    Exactly one of `existing_credential` or `new_credential` (a dict with
    `name`, `credential_type`, `policy`, `username`, `secret_data`) is given.
    The endpoint is matched on (target, service_type, port) and updated in
    place; the credential it previously used is left untouched.

    Returns `(endpoint, credential, endpoint_created)`.
    """
    if (existing_credential is None) == (new_credential is None):
        raise ValidationError(_('Provide exactly one of an existing credential or a new credential.'))

    with transaction.atomic():
        credential = existing_credential
        import_source = ''
        if credential is None and idempotency_key:
            fingerprint = _request_fingerprint(target, endpoint_fields, new_credential)
            # A replay of a request whose response was lost reuses the
            # credential the first attempt created instead of writing a second.
            credential = _claim_replay(idempotency_key, user, fingerprint)
            import_source = _idempotency_prefix(idempotency_key, user) + fingerprint
        if reauthorize is not None:
            # Re-check authorization now that the idempotency lock is held.
            reauthorize()
        # Validate the credential that will actually be bound, including a replayed one.
        check_credential_compatible(
            endpoint_fields['service_type'],
            credential.credential_type if credential is not None else new_credential['credential_type'],
        )
        if credential is None:
            credential = _create_credential(new_credential, import_source=import_source, user=user, request=request)
        endpoint, created = _save_endpoint(target, endpoint_fields, credential, user=user)
        # Evaluated after every mutation and before commit, so a refusal rolls
        # back the endpoint and compensates the new material version.
        conform(credential)
    return endpoint, credential, created
