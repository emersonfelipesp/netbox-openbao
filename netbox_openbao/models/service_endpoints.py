from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel

from netbox_openbao.choices import ServiceTypeChoices
from netbox_openbao.config import assignable_model_labels
from netbox_openbao.secrets.extractors import ssh_fingerprint

__all__ = ('SSHPublicKey', 'ServiceEndpoint')

SECRET_OPTION_PARTS = ('password', 'passphrase', 'private_key', 'private-key', 'community', 'secret', 'token')


def _secret_option_paths(value, prefix=''):
    paths = []
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f'{prefix}.{key}' if prefix else str(key)
            normalized = str(key).lower().replace(' ', '_')
            if any(part in normalized for part in SECRET_OPTION_PARTS):
                paths.append(path)
            paths.extend(_secret_option_paths(nested, path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            paths.extend(_secret_option_paths(nested, f'{prefix}[{index}]'))
    return paths


class ServiceEndpoint(NetBoxModel):
    assigned_object_type = models.ForeignKey(
        to='contenttypes.ContentType', on_delete=models.PROTECT, related_name='+',
    )
    assigned_object_id = models.PositiveBigIntegerField()
    assigned_object = GenericForeignKey(
        ct_field='assigned_object_type', fk_field='assigned_object_id',
    )
    service_type = models.CharField(max_length=20, choices=ServiceTypeChoices)
    host = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    ssh_known_hosts_entry = models.TextField(blank=True)
    ssh_strict_host_key_checking = models.BooleanField(default=True)
    options = models.JSONField(default=dict, blank=True)
    credential = models.ForeignKey(
        to='netbox_openbao.Credential', on_delete=models.PROTECT,
        related_name='service_endpoints', null=True, blank=True,
    )
    import_source = models.CharField(max_length=200, blank=True, db_index=True, editable=False)

    clone_fields = ('assigned_object_type', 'service_type', 'port')

    class Meta:
        ordering = ('assigned_object_type', 'assigned_object_id', 'service_type', 'port')
        constraints = (
            models.UniqueConstraint(
                fields=('assigned_object_type', 'assigned_object_id', 'service_type', 'port'),
                name='%(app_label)s_%(class)s_unique_object_service_port',
            ),
        )
        indexes = (
            models.Index(
                fields=('assigned_object_type', 'assigned_object_id'),
                name='openbao_service_object_idx',
            ),
        )

    def __str__(self):
        return f'{self.get_service_type_display()} {self.host or self.assigned_object}:{self.port}'

    def clean(self):
        super().clean()
        if not isinstance(self.options, dict):
            raise ValidationError({'options': _('Options must be a JSON object.')})
        if secret_paths := _secret_option_paths(self.options):
            raise ValidationError({
                'options': _('Options may not contain secret-shaped keys: {paths}.').format(
                    paths=', '.join(secret_paths),
                ),
            })
        if not self.assigned_object_type_id:
            return
        label = f'{self.assigned_object_type.app_label}.{self.assigned_object_type.model}'
        permitted = assignable_model_labels()
        if label not in permitted:
            raise ValidationError({
                'assigned_object_type': _(
                    'Service endpoints may not be assigned to {label}. Permitted types: {permitted}.'
                ).format(label=label, permitted=', '.join(permitted) or _('none configured')),
            })


class SSHPublicKey(NetBoxModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='openbao_ssh_public_keys',
    )
    service_endpoint = models.ForeignKey(
        ServiceEndpoint, on_delete=models.CASCADE, related_name='ssh_public_keys',
    )
    public_key = models.TextField()
    fingerprint = models.CharField(max_length=128, blank=True, editable=False, db_index=True)
    key_type = models.CharField(max_length=50, blank=True, editable=False)
    installed_at = models.DateTimeField(null=True, blank=True)
    import_source = models.CharField(max_length=200, blank=True, db_index=True, editable=False)

    clone_fields = ('user', 'service_endpoint')

    class Meta:
        ordering = ('user', 'service_endpoint', 'pk')
        constraints = (
            models.UniqueConstraint(
                fields=('user', 'service_endpoint'),
                name='%(app_label)s_%(class)s_unique_user_endpoint',
            ),
        )

    def __str__(self):
        return f'{self.user} @ {self.service_endpoint}'

    def clean(self):
        super().clean()
        if self.service_endpoint_id and self.service_endpoint.service_type != ServiceTypeChoices.TYPE_SSH:
            raise ValidationError({'service_endpoint': _('SSH public keys require an SSH service endpoint.')})

    def save(self, *args, **kwargs):
        parts = self.public_key.split()
        self.fingerprint = ssh_fingerprint(self.public_key)
        algorithm = parts[0] if parts else ''
        if algorithm == 'ssh-ed25519':
            self.key_type = 'ed25519'
        elif algorithm.startswith('ssh-rsa'):
            self.key_type = 'rsa'
        elif algorithm.startswith('ecdsa-'):
            self.key_type = 'ecdsa'
        else:
            self.key_type = algorithm
        if kwargs.get('update_fields') is not None:
            kwargs['update_fields'] = set(kwargs['update_fields']) | {'fingerprint', 'key_type'}
        super().save(*args, **kwargs)


def credential_visible(user, credential_id):
    """True when ``user`` may view the Credential with ``credential_id``."""
    if credential_id is None or user is None:
        return False
    from netbox_openbao.models.credentials import Credential

    return Credential.objects.restrict(user, 'view').filter(pk=credential_id).exists()
