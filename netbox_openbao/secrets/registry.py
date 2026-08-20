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

import logging

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.config import get_config

from .extractors import extract_certificate_metadata, extract_ssh_metadata

logger = logging.getLogger('netbox.plugins.netbox_openbao.registry')

__all__ = (
    'CREDENTIAL_SCHEMAS',
    'EXTRACTORS',
    'credential_type_choices',
    'extract_metadata',
    'get_schema',
    'is_known_credential_type',
    'validate_payload',
)

# The complete set of extractors a stored credential type may name. This is a
# fixed mapping from a short name to a vetted function, and it is the reason
# `CredentialTypeSchema.extractor` is safe: an operator picks from this list.
# If it ever becomes a dotted path resolved with import_string, the model turns
# into remote code execution with a JSON Schema attached.
EXTRACTORS = {
    'ssh': lambda payload: extract_ssh_metadata(
        payload['private_key'], passphrase=payload.get('passphrase'),
    ),
    'x509': lambda payload: extract_certificate_metadata(payload['certificate']),
}

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


def _stored_schema(credential_type):
    """Return the `CredentialTypeSchema` for `credential_type`, or None."""
    from netbox_openbao.models import CredentialTypeSchema

    try:
        return CredentialTypeSchema.objects.filter(slug=credential_type).first()
    except Exception:
        # The table may not exist yet during migrations; a built-in type must
        # still resolve in that window.
        logger.debug('Stored credential types are not readable yet')
        return None


def get_schema(credential_type):
    """
    Return the schema for `credential_type`, built-in or stored.

    Built-ins win. A stored type cannot shadow one — `CredentialTypeSchema.clean`
    refuses the slug — so this ordering is an assertion of that rule rather
    than a precedence decision.
    """
    if credential_type in CREDENTIAL_SCHEMAS:
        return CREDENTIAL_SCHEMAS[credential_type]

    stored = _stored_schema(credential_type)
    if stored is not None:
        return _as_schema(stored)

    raise ValidationError({
        'credential_type': _('Unknown credential type: {value}.').format(value=credential_type),
    })


def _as_schema(stored):
    """Adapt a stored type into the same shape the built-ins use."""
    properties = stored.schema.get('properties', {})
    required = set(stored.schema.get('required', []))
    return {
        'vault_fields': {
            name: {'required': name in required, 'secret': name in stored.secret_fields}
            for name in properties
        },
        'extractor': stored.extractor or None,
        'json_schema': stored.schema,
        'stored': stored,
    }


def is_known_credential_type(value):
    return value in CREDENTIAL_SCHEMAS or _stored_schema(value) is not None


def credential_type_choices():
    """
    Built-in types plus every stored one, for forms and serializers.

    Degrades to the built-ins alone if the stored types cannot be read — which
    happens legitimately while migrations are being applied, before the table
    exists. Failing there would make the plugin unimportable during its own
    install.
    """
    from netbox_openbao.models import CredentialTypeSchema

    choices = list(CredentialTypeChoices)
    try:
        choices += [(schema.slug, schema.name) for schema in CredentialTypeSchema.objects.all()]
    except Exception:
        logger.debug('Stored credential types are not readable yet; offering built-ins only')
    return choices


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

    # A stored type carries a real JSON Schema; enforce it in full rather than
    # settling for the required/unknown checks above.
    if (json_schema := schema.get('json_schema')) is not None:
        try:
            import jsonschema

            jsonschema.validate(instance=cleaned, schema=json_schema)
        except ImportError:
            pass
        except Exception as exc:
            # jsonschema's message quotes the failing *instance*, which for a
            # secret payload is the material itself. Report the path only.
            path = '.'.join(str(p) for p in getattr(exc, 'absolute_path', []) or []) or _('payload')
            raise ValidationError({
                'secret_data': _('Does not match the schema for this credential type (at: {path}).').format(
                    path=path,
                ),
            }) from None

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

    run = EXTRACTORS.get(extractor)
    if run is None:
        return {}
    extracted = run(payload)

    # The allowlist is the load-bearing part for stored types: whatever an
    # extractor returns, only these keys can reach a NetBox column, so a
    # schema cannot cause secret material to be mirrored out of OpenBao.
    return {key: value for key, value in extracted.items() if key in EXTRACTABLE_FIELDS}
