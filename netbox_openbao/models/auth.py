"""Encrypted OpenBao service identities.

``SECRET_KEY`` is the root of trust for these rows. It cannot itself be stored
in the database: doing so would place the wrapping key beside the ciphertext it
protects. Operators must re-encrypt the rows when rotating ``SECRET_KEY``.
"""

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, router, transaction
from django.db.models import Q
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from utilities.querysets import RestrictedQuerySet

__all__ = (
    'AUTH_MATERIAL_FIELDS',
    'AuthMaterialDecryptionError',
    'EngineAuthMaterial',
)

AUTH_MATERIAL_FIELDS = (
    'role_id',
    'secret_id',
    'token',
    'k8s_role',
    'k8s_jwt_path',
    'client_cert',
    'client_key',
)
_CIPHERTEXT_PREFIX = 'v1:'
_HKDF_SALT = b'netbox-openbao-engine-auth-material-v1'
_HKDF_INFO = b'netbox-openbao/engine-auth-material'


class AuthMaterialDecryptionError(RuntimeError):
    """Raised without ciphertext or plaintext when stored material cannot be opened."""


def _fernet(secret_key=None):
    source = settings.SECRET_KEY if secret_key is None else secret_key
    if not isinstance(source, str) or not source:
        raise AuthMaterialDecryptionError('OpenBao auth material cannot be decrypted.')
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(source.encode())
    return Fernet(base64.urlsafe_b64encode(derived))


def _encrypt(value, *, secret_key=None):
    if value in (None, ''):
        return ''
    token = _fernet(secret_key).encrypt(str(value).encode()).decode()
    return f'{_CIPHERTEXT_PREFIX}{token}'


def _decrypt(value, *, secret_key=None):
    if not value:
        return ''
    if not value.startswith(_CIPHERTEXT_PREFIX):
        raise AuthMaterialDecryptionError('OpenBao auth material uses an unsupported encryption format.')
    try:
        return _fernet(secret_key).decrypt(value[len(_CIPHERTEXT_PREFIX):].encode()).decode()
    except (InvalidToken, UnicodeError, ValueError):
        raise AuthMaterialDecryptionError('OpenBao auth material cannot be decrypted.') from None


class EngineAuthMaterial(models.Model):
    """One encrypted service identity for an engine, policy tier, or cluster."""

    engine = models.OneToOneField(
        to='netbox_openbao.SecretEngine',
        on_delete=models.CASCADE,
        related_name='auth_material',
        null=True,
        blank=True,
        verbose_name=_('secret engine'),
    )
    policy = models.OneToOneField(
        to='netbox_openbao.CredentialPolicy',
        on_delete=models.CASCADE,
        related_name='auth_material',
        null=True,
        blank=True,
        verbose_name=_('credential policy'),
        help_text=_('Optional tier-specific identity. Blank tiers use their engine identity.'),
    )
    cluster = models.OneToOneField(
        to='netbox_openbao.OpenBaoCluster',
        on_delete=models.CASCADE,
        related_name='auth_material',
        null=True,
        blank=True,
        verbose_name=_('OpenBao cluster'),
        help_text=_('Service identity used only by the cluster administration plane.'),
    )

    # These fields contain only versioned ciphertext. Their names are explicit
    # so a schema inspection cannot mistake them for plaintext columns.
    role_id_ciphertext = models.TextField(blank=True, editable=False)
    secret_id_ciphertext = models.TextField(blank=True, editable=False)
    token_ciphertext = models.TextField(blank=True, editable=False)
    k8s_role_ciphertext = models.TextField(blank=True, editable=False)
    k8s_jwt_path_ciphertext = models.TextField(blank=True, editable=False)
    client_cert_ciphertext = models.TextField(blank=True, editable=False)
    client_key_ciphertext = models.TextField(blank=True, editable=False)

    revision = models.PositiveBigIntegerField(default=1, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ('engine_id', 'policy_id', 'cluster_id')
        verbose_name = _('engine authentication material')
        verbose_name_plural = _('engine authentication material')
        constraints = (
            models.CheckConstraint(
                condition=(
                    (Q(engine__isnull=False) & Q(policy__isnull=True) & Q(cluster__isnull=True))
                    | (Q(engine__isnull=True) & Q(policy__isnull=False) & Q(cluster__isnull=True))
                    | (Q(engine__isnull=True) & Q(policy__isnull=True) & Q(cluster__isnull=False))
                ),
                name='netbox_openbao_auth_material_one_owner',
            ),
        )

    def __str__(self):
        if self.policy_id:
            return f'Authentication for policy {self.policy}'
        if self.engine_id:
            return f'Authentication for engine {self.engine}'
        return f'Authentication for cluster {self.cluster}'

    @classmethod
    def from_db(cls, db, field_names, values, **kwargs):
        instance = super().from_db(db, field_names, values, **kwargs)
        instance._capture_loaded_values()
        return instance

    def refresh_from_db(self, *args, **kwargs):
        super().refresh_from_db(*args, **kwargs)
        self._capture_loaded_values()

    def _capture_loaded_values(self):
        self._loaded_auth_values = {
            field.attname: getattr(self, field.attname)
            for field in self._meta.concrete_fields
            if field.attname in self.__dict__
        }

    def _submitted_fields(self, update_fields):
        fields = {
            field.name: field
            for field in self._meta.concrete_fields
            if not field.primary_key and field.name not in {'revision', 'created', 'last_updated'}
        }
        if update_fields is not None:
            names = set(update_fields)
            return [
                field for field in fields.values()
                if field.name in names or field.attname in names
            ]
        loaded = getattr(self, '_loaded_auth_values', {})
        return [
            field for field in fields.values()
            if field.attname not in loaded
            or getattr(self, field.attname) != loaded[field.attname]
        ]

    def get_absolute_url(self):
        return reverse('plugins:netbox_openbao:openbaosettings_list')

    @property
    def owner(self):
        return self.policy or self.engine or self.cluster

    def clean(self):
        super().clean()
        if sum(value is not None for value in (self.engine_id, self.policy_id, self.cluster_id)) != 1:
            raise ValidationError(_('Choose exactly one engine, policy, or cluster.'))

    def get_secret(self, name, *, secret_key=None):
        if name not in AUTH_MATERIAL_FIELDS:
            raise ValueError('Unknown OpenBao auth material field.')
        return _decrypt(getattr(self, f'{name}_ciphertext'), secret_key=secret_key)

    def set_secret(self, name, value, *, secret_key=None):
        if name not in AUTH_MATERIAL_FIELDS:
            raise ValueError('Unknown OpenBao auth material field.')
        setattr(self, f'{name}_ciphertext', _encrypt(value, secret_key=secret_key))

    def clear_secret(self, name):
        self.set_secret(name, '')

    def is_configured(self, name):
        if name not in AUTH_MATERIAL_FIELDS:
            raise ValueError('Unknown OpenBao auth material field.')
        return bool(getattr(self, f'{name}_ciphertext'))

    @property
    def ciphertext_version(self):
        configured = (
            getattr(self, f'{name}_ciphertext')
            for name in AUTH_MATERIAL_FIELDS
            if self.is_configured(name)
        )
        versions = {value.partition(':')[0] for value in configured}
        return versions.pop() if len(versions) == 1 else ('mixed' if versions else '')

    @property
    def cache_identity(self):
        return f'{self.pk}:{self.revision}'

    def token_cache_key(self, engine_slug=None):
        del engine_slug
        return f'netbox_openbao:token:{self.cache_identity}'

    def save(self, *args, **kwargs):
        using = kwargs.get('using') or router.db_for_write(type(self), instance=self)
        kwargs['using'] = using
        if self._state.adding:
            super().save(*args, **kwargs)
            self._capture_loaded_values()
            return

        submitted = self._submitted_fields(kwargs.get('update_fields'))
        with transaction.atomic(using=using):
            locked = type(self).objects.using(using).select_for_update().get(pk=self.pk)
            previous_revision = locked.revision
            for field in submitted:
                setattr(locked, field.attname, getattr(self, field.attname))
            locked.revision = previous_revision + 1
            locked._openbao_previous_revision = previous_revision
            save_kwargs = dict(kwargs)
            save_kwargs.pop('force_insert', None)
            save_kwargs['force_update'] = True
            save_kwargs['update_fields'] = {
                *(field.name for field in submitted),
                'revision',
                'last_updated',
            }
            models.Model.save(locked, *args, **save_kwargs)
            locked.refresh_from_db()
            for field in self._meta.concrete_fields:
                setattr(self, field.attname, getattr(locked, field.attname))
            self._state.db = locked._state.db
            self._state.adding = False
        self._capture_loaded_values()

    def delete(self, *args, **kwargs):
        return super().delete(*args, **kwargs)

    def reencrypt(self, old_secret_key):
        values = {
            name: self.get_secret(name, secret_key=old_secret_key)
            for name in AUTH_MATERIAL_FIELDS
            if self.is_configured(name)
        }
        for name, value in values.items():
            self.set_secret(name, value)
        self.save()

    def serialize_object(self, exclude=None):
        """Return only status metadata for event and changelog serializers."""
        excluded = set(exclude or ())
        data = {
            'id': self.pk,
            'engine': self.engine_id,
            'policy': self.policy_id,
            'cluster': self.cluster_id,
            'revision': self.revision,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
        }
        for name in AUTH_MATERIAL_FIELDS:
            data[f'{name}_configured'] = self.is_configured(name)
        return {key: value for key, value in data.items() if key not in excluded}
