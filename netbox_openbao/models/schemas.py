"""
Operator-defined credential types.

The built-in types are Python: `CredentialTypeChoices` plus
`CREDENTIAL_SCHEMAS`. Adding one — a vendor API key with three named fields, a
RADIUS shared secret, a database DSN — meant a plugin release, so an operator
could not model their own estate without forking.

This was deferred at bootstrap on purpose. Shipping a stored schema format
before the built-in types had settled would have frozen the format
prematurely; they have now settled.

**The security constraint that shapes the whole model:** `extractor` names a
function from a vetted registry. It is never an import path, never a dotted
callable, never anything resolvable to arbitrary code. A JSONField that can
name any importable object is remote code execution wearing a schema.
"""

from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel

__all__ = ('CredentialTypeSchema',)


class CredentialTypeSchema(NetBoxModel):
    """A credential type defined as data rather than as a plugin release."""

    name = models.CharField(
        verbose_name=_('name'),
        max_length=100,
        unique=True,
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        max_length=50,
        unique=True,
        help_text=_('Used as the credential type value. May not shadow a built-in type.'),
    )
    description = models.CharField(
        verbose_name=_('description'),
        max_length=200,
        blank=True,
    )
    schema = models.JSONField(
        verbose_name=_('JSON Schema'),
        help_text=_('A JSON Schema object describing the secret payload. Must define "properties".'),
    )
    secret_fields = ArrayField(
        base_field=models.CharField(max_length=100),
        verbose_name=_('secret fields'),
        default=list,
        blank=True,
        help_text=_(
            'Which properties hold secret material. Anything not listed here may be mirrored into a '
            'NetBox column, so getting this wrong is what turns a schema into a leak.'
        ),
    )
    extractor = models.CharField(
        verbose_name=_('extractor'),
        max_length=50,
        blank=True,
        help_text=_(
            'Name of a built-in extractor to derive non-secret metadata, e.g. "ssh" or "x509". '
            'Chosen from a fixed list; it is not a path to code.'
        ),
    )

    clone_fields = ('schema', 'secret_fields', 'extractor')

    class Meta:
        ordering = ('name',)
        verbose_name = _('credential type schema')
        verbose_name_plural = _('credential type schemas')

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        from netbox_openbao.choices import CredentialTypeChoices
        from netbox_openbao.secrets.registry import EXTRACTORS

        # A stored type may not shadow a built-in. The built-ins are what the
        # plugin's own code paths assume, and a stored type quietly overriding
        # `ssh-keypair` would change how existing credentials validate.
        if self.slug in CredentialTypeChoices.values():
            raise ValidationError({
                'slug': _('"{slug}" is a built-in credential type and cannot be redefined.').format(
                    slug=self.slug,
                ),
            })

        if not isinstance(self.schema, dict):
            raise ValidationError({'schema': _('Schema must be a JSON object.')})

        properties = self.schema.get('properties')
        if not isinstance(properties, dict) or not properties:
            raise ValidationError({
                'schema': _('Schema must define a non-empty "properties" object.'),
            })

        # Validate the schema itself, so a malformed one is rejected here
        # rather than at the first write against it.
        try:
            import jsonschema

            jsonschema.Draft202012Validator.check_schema(self.schema)
        except ImportError:
            pass
        except Exception as exc:
            raise ValidationError({'schema': _('Invalid JSON Schema: {error}').format(error=exc)}) from None

        # Every declared secret field must exist. A typo here would silently
        # mark nothing as secret, and the value would then be eligible to be
        # mirrored into a NetBox column.
        unknown = sorted(set(self.secret_fields) - set(properties))
        if unknown:
            raise ValidationError({
                'secret_fields': _('Not defined in the schema: {fields}.').format(
                    fields=', '.join(unknown),
                ),
            })

        if self.extractor and self.extractor not in EXTRACTORS:
            raise ValidationError({
                'extractor': _('Unknown extractor "{name}". Available: {available}.').format(
                    name=self.extractor,
                    available=', '.join(sorted(EXTRACTORS)) or _('none'),
                ),
            })

    @property
    def public_fields(self):
        """Properties that are not secret, and so may be stored in NetBox."""
        return [name for name in self.schema.get('properties', {}) if name not in self.secret_fields]
