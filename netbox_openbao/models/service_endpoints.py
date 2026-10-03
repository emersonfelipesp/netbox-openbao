from django.conf import settings
from django.db import models
from netbox.models import NetBoxModel

from netbox_openbao.secrets.extractors import ssh_fingerprint

__all__ = ('SSHPublicKey',)

class SSHPublicKey(NetBoxModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='openbao_ssh_public_keys',
    )
    application_service = models.ForeignKey(
        to='ipam.Service', on_delete=models.CASCADE, related_name='openbao_ssh_public_keys',
    )
    public_key = models.TextField()
    fingerprint = models.CharField(max_length=128, blank=True, editable=False, db_index=True)
    key_type = models.CharField(max_length=50, blank=True, editable=False)
    installed_at = models.DateTimeField(null=True, blank=True)
    import_source = models.CharField(max_length=200, blank=True, db_index=True, editable=False)

    clone_fields = ('user', 'application_service')

    class Meta:
        ordering = ('user', 'application_service', 'pk')
        constraints = (
            models.UniqueConstraint(
                fields=('user', 'application_service'),
                name='%(app_label)s_%(class)s_unique_user_service',
            ),
        )

    def __str__(self):
        return f'{self.user} @ {self.application_service}'

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
