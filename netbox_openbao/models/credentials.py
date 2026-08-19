from uuid import uuid4

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import PrimaryModel

from netbox_openbao.choices import CredentialStatusChoices, CredentialTypeChoices
from netbox_openbao.config import get_config

__all__ = ('Credential',)


class Credential(PrimaryModel):
    """
    A credential's inventory record. **Never its secret material.**

    Every field below is non-secret by construction: there is no model field
    that secret material could be written to, which is what makes the
    changelog, export templates, and the browsable API safe structurally
    rather than by convention. The material itself lives only at `path` on the
    engine's KV mount.

    The split is also what makes the expiry dashboard free: `valid_until` is
    stored here, so "every certificate expiring in 30 days" is one indexed
    query and zero OpenBao reads.
    """

    name = models.CharField(
        verbose_name=_('name'),
        max_length=200,
    )
    uuid = models.UUIDField(
        verbose_name=_('UUID'),
        default=uuid4,
        unique=True,
        editable=False,
        help_text=_('Immutable identity. The OpenBao path is derived from this and never changes.'),
    )
    credential_type = models.CharField(
        verbose_name=_('type'),
        max_length=50,
        choices=CredentialTypeChoices,
    )
    policy = models.ForeignKey(
        to='netbox_openbao.CredentialPolicy',
        on_delete=models.PROTECT,
        related_name='credentials',
        verbose_name=_('policy'),
    )
    engine = models.ForeignKey(
        to='netbox_openbao.SecretEngine',
        on_delete=models.PROTECT,
        related_name='credentials',
        verbose_name=_('secret engine'),
        help_text=_("Denormalized from the policy so path resolution and filtering avoid a join"),
    )
    path = models.CharField(
        verbose_name=_('path'),
        max_length=500,
        editable=False,
        db_index=True,
        help_text=_('Logical path beneath the KV mount. Derived from the UUID; never edited.'),
    )

    # Non-secret identity
    username = models.CharField(
        verbose_name=_('username'),
        max_length=200,
        blank=True,
    )

    # Non-secret public material, extracted once at write time
    public_key = models.TextField(
        verbose_name=_('public key'),
        blank=True,
    )
    fingerprint = models.CharField(
        verbose_name=_('fingerprint'),
        max_length=128,
        blank=True,
        db_index=True,
        help_text=_('SHA256 fingerprint of the public key or certificate'),
    )
    key_type = models.CharField(
        verbose_name=_('key type'),
        max_length=50,
        blank=True,
    )
    cert_serial = models.CharField(
        verbose_name=_('certificate serial'),
        max_length=128,
        blank=True,
    )
    cert_subject = models.CharField(
        verbose_name=_('certificate subject'),
        max_length=500,
        blank=True,
    )
    cert_issuer = models.CharField(
        verbose_name=_('certificate issuer'),
        max_length=500,
        blank=True,
    )
    valid_from = models.DateTimeField(
        verbose_name=_('valid from'),
        null=True,
        blank=True,
    )
    valid_until = models.DateTimeField(
        verbose_name=_('valid until'),
        null=True,
        blank=True,
        db_index=True,
    )

    # Lifecycle
    status = models.CharField(
        verbose_name=_('status'),
        max_length=50,
        choices=CredentialStatusChoices,
        default=CredentialStatusChoices.STATUS_ACTIVE,
    )
    rotation_interval = models.PositiveIntegerField(
        verbose_name=_('rotation interval'),
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        help_text=_('Days between rotations. Leave empty to disable rotation tracking.'),
    )
    last_rotated = models.DateTimeField(
        verbose_name=_('last rotated'),
        null=True,
        blank=True,
    )

    # Observed OpenBao state, refreshed by CredentialVerifyJob
    kv_version = models.PositiveIntegerField(
        verbose_name=_('KV version'),
        null=True,
        blank=True,
        editable=False,
        help_text=_('Mirror of the current KV v2 version at this path'),
    )
    last_verified = models.DateTimeField(
        verbose_name=_('last verified'),
        null=True,
        blank=True,
        editable=False,
    )

    clone_fields = ('credential_type', 'policy', 'engine', 'status', 'rotation_interval')

    class Meta:
        ordering = ('name', 'pk')
        verbose_name = _('credential')
        verbose_name_plural = _('credentials')
        indexes = (
            models.Index(fields=('credential_type', 'status')),
            models.Index(fields=('valid_until',)),
        )
        constraints = (
            models.UniqueConstraint(
                fields=('engine', 'path'),
                name='%(app_label)s_%(class)s_unique_engine_path',
                violation_error_message=_('A credential already occupies this path on this engine.'),
            ),
        )
        # Registers the `reveal` model action, yielding the assignable and
        # constrainable permission `netbox_openbao.reveal_credential`, entirely
        # separate from `view`. Someone may inventory every credential and
        # reveal none.
        permissions = (
            ('reveal', 'Reveal secret material'),
            ('rotate', 'Rotate secret material'),
        )

    def __str__(self):
        if self.username:
            return f'{self.name} ({self.username})'
        return self.name

    def get_status_color(self):
        return CredentialStatusChoices.colors.get(self.status)

    def get_credential_type_color(self):
        return CredentialTypeChoices.colors.get(self.credential_type)

    @property
    def derived_path(self):
        """
        Canonical logical path beneath the KV mount.

        UUID-based on purpose: a credential gets renamed, reassigned from one
        device to another, or shared across a fleet, and any path derived from
        the object graph breaks on the first such change. A broken path means
        an orphaned secret nobody can find.
        """
        prefix = (get_config('path_prefix') or 'netbox').strip('/')
        return f'{prefix}/credentials/{self.uuid}'

    @property
    def is_expired(self):
        if self.valid_until is None:
            return False
        from django.utils import timezone
        return self.valid_until <= timezone.now()

    def clean(self):
        super().clean()

        # The policy is the authorization tier and carries the AppRole. If the
        # credential's engine could differ from its policy's, the tier's
        # AppRole would be scoped to one instance while the material sat on
        # another — the exact mismatch the per-tier AppRole exists to prevent.
        if self.policy_id and self.engine_id and self.policy.engine_id != self.engine_id:
            raise ValidationError({
                'engine': _('Engine must match the policy\'s engine ({engine}).').format(
                    engine=self.policy.engine
                ),
            })

        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ValidationError({'valid_until': _('Validity window ends before it begins.')})

    def save(self, *args, **kwargs):
        # Default the engine from the policy so callers need only choose a tier.
        if self.policy_id and not self.engine_id:
            self.engine_id = self.policy.engine_id

        # `path` is derived, not user-supplied, and is stamped once. Recomputing
        # it on every save would silently orphan material if `path_prefix` were
        # ever changed in deployment configuration.
        if not self.path:
            self.path = self.derived_path

        super().save(*args, **kwargs)
