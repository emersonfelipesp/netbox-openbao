"""
Credential type registry.

Each credential type declares which payload fields OpenBao accepts and which
non-secret attributes are extracted into NetBox. `secret: False` marks a field
as public material — it still goes to OpenBao so the payload stays whole, but
it may also be mirrored into a NetBox column.

Types are Python for now. Operator-defined types backed by a stored JSON Schema
(`CredentialTypeSchema`) are a follow-up; shipping them as data before the
built-ins have settled would freeze a schema format prematurely.
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.config import get_config

from .extractors import extract_certificate_metadata, extract_ssh_metadata

__all__ = (
    'CREDENTIAL_SCHEMAS',
    'extract_metadata',
    'get_schema',
    'validate_payload',
)

# Fields on Credential that extraction is permitted to populate. Anything an
# extractor returns that is not listed here is dropped rather than written,
# so a future extractor cannot accidentally introduce a secret-bearing column.
EXTRACTABLE_FIELDS = frozenset({
    'public_key',
    'fingerprint',
    'key_type',
    'cert_serial',
    'cert_subject',
    'cert_issuer',
    'valid_from',
    'valid_until',
})

CREDENTIAL_SCHEMAS = {
    CredentialTypeChoices.TYPE_PASSWORD: {
        'vault_fields': {
            'password': {'required': True, 'secret': True},
        },
        'extractor': None,
    },
    CredentialTypeChoices.TYPE_SSH_PASSWORD: {
        'vault_fields': {
            'password': {'required': True, 'secret': True},
        },
        'extractor': None,
    },
    CredentialTypeChoices.TYPE_API_TOKEN: {
        'vault_fields': {
            'token': {'required': True, 'secret': True},
        },
        'extractor': None,
    },
    CredentialTypeChoices.TYPE_SSH_KEYPAIR: {
        'vault_fields': {
            'private_key': {'required': True, 'secret': True},
            'passphrase': {'required': False, 'secret': True},
            'public_key': {'required': False, 'secret': False},
        },
        'extractor': 'ssh',
    },
    CredentialTypeChoices.TYPE_X509_KEYPAIR: {
        'vault_fields': {
            'private_key': {'required': True, 'secret': True},
            'certificate': {'required': True, 'secret': False},
            'chain': {'required': False, 'secret': False},
        },
        'extractor': 'x509',
    },
    CredentialTypeChoices.TYPE_X509_CA: {
        'vault_fields': {
            'private_key': {'required': False, 'secret': True},
            'certificate': {'required': True, 'secret': False},
        },
        'extractor': 'x509',
    },
    CredentialTypeChoices.TYPE_SNMP_V3: {
        'vault_fields': {
            'auth_password': {'required': True, 'secret': True},
            'priv_password': {'required': False, 'secret': True},
            'auth_protocol': {'required': False, 'secret': False},
            'priv_protocol': {'required': False, 'secret': False},
        },
        'extractor': None,
    },
    CredentialTypeChoices.TYPE_WIREGUARD: {
        'vault_fields': {
            'private_key': {'required': True, 'secret': True},
            'preshared_key': {'required': False, 'secret': True},
            'public_key': {'required': False, 'secret': False},
        },
        'extractor': None,
    },
    CredentialTypeChoices.TYPE_GENERIC_KV: {
        'vault_fields': {},
        'extractor': None,
        'allow_arbitrary_keys': True,
    },
}


def get_schema(credential_type):
    try:
        return CREDENTIAL_SCHEMAS[credential_type]
    except KeyError:
        raise ValidationError({
            'credential_type': _('Unknown credential type: {value}.').format(value=credential_type),
        })


def validate_payload(credential_type, data):
    """
    Validate a secret payload against its type schema and return it cleaned.

    Rejects unknown keys rather than silently storing them, so a typo in
    `private_key` cannot leave a credential whose material is present but
    unreachable by the field name every consumer will ask for.
    """
    schema = get_schema(credential_type)
    fields = schema['vault_fields']

    if not isinstance(data, dict):
        raise ValidationError({'secret_data': _('Secret data must be an object.')})

    cleaned = {key: value for key, value in data.items() if value not in (None, '')}

    missing = [name for name, spec in fields.items() if spec['required'] and not cleaned.get(name)]
    if missing:
        raise ValidationError({
            'secret_data': _('Missing required field(s) for this credential type: {fields}.').format(
                fields=', '.join(sorted(missing)),
            ),
        })

    if not schema.get('allow_arbitrary_keys'):
        unknown = sorted(set(cleaned) - set(fields))
        if unknown:
            raise ValidationError({
                'secret_data': _('Unsupported field(s) for this credential type: {fields}.').format(
                    fields=', '.join(unknown),
                ),
            })

    if not cleaned:
        raise ValidationError({'secret_data': _('Secret data must not be empty.')})

    return cleaned


def extract_metadata(credential_type, payload):
    """
    Return the non-secret Credential attributes derivable from `payload`.

    Returns an empty dict when the deployment has opted out of storing public
    material, and only ever returns keys in `EXTRACTABLE_FIELDS`.
    """
    if not get_config('store_public_material', True):
        return {}

    schema = get_schema(credential_type)
    extractor = schema.get('extractor')
    if not extractor:
        return {}

    if extractor == 'ssh':
        extracted = extract_ssh_metadata(
            payload['private_key'],
            passphrase=payload.get('passphrase'),
        )
    elif extractor == 'x509':
        extracted = extract_certificate_metadata(payload['certificate'])
    else:
        return {}

    return {key: value for key, value in extracted.items() if key in EXTRACTABLE_FIELDS}
