from uuid import uuid4

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models, router, transaction
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
        # Deliberately no `choices`. Django validates a choices field in
        # clean_fields(), which would reject any operator-defined
        # CredentialTypeSchema slug outright. Membership is checked in clean()
        # against the union of built-in and stored types instead, and
        # get_credential_type_display() below replaces what choices would have
        # provided.
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

    import_source = models.CharField(
        verbose_name=_('import source'),
        max_length=200,
        blank=True,
        db_index=True,
        editable=False,
        help_text=_(
            'Provenance for a credential copied in from another system, e.g. "netbox_secrets:142". '
            'What makes a migration resumable and a repeated run a no-op.'
        ),
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
        help_text=_('Highest version ever written at this path. This is what check-and-set compares against.'),
    )
    live_kv_version = models.PositiveIntegerField(
        verbose_name=_('live KV version'),
        null=True,
        blank=True,
        editable=False,
        help_text=_(
            'The version consumers are served. Empty means "whatever is latest", which is how every '
            'credential behaved before staged rotation existed.'
        ),
    )
    staged_kv_version = models.PositiveIntegerField(
        verbose_name=_('staged KV version'),
        null=True,
        blank=True,
        editable=False,
        help_text=_('A written but not yet promoted candidate awaiting a decision. Empty when none.'),
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
        # Stored types have no colour of their own; grey is honest about that
        # rather than borrowing a built-in's.
        return CredentialTypeChoices.colors.get(self.credential_type, 'gray')

    def get_credential_type_display(self):
        """
        Human label for the type.

        Supplied explicitly because the field has no `choices` — see the field
        definition. Tables and detail panels call this, so dropping it would
        break both.
        """
        labels = dict(CredentialTypeChoices)
        if self.credential_type in labels:
            return labels[self.credential_type]

        from netbox_openbao.models import CredentialTypeSchema

        stored = CredentialTypeSchema.objects.filter(slug=self.credential_type).first()
        return stored.name if stored is not None else self.credential_type

    @property
    def derived_path(self):
        """
        Canonical logical path beneath the KV mount.

        UUID-based on purpose: a credential gets renamed, reassigned from one
        device to another, or shared across a fleet, and any path derived from
        the object graph breaks on the first such change. A broken path means
        an orphaned secret nobody can find.
        """
        return self._path_for_prefix(get_config('path_prefix', 'netbox'))

    def _path_for_prefix(self, prefix):
        # The fallback can come from legacy PLUGINS_CONFIG rather than the
        # validated settings row. Validate every derivation so an unsafe legacy
        # value fails closed instead of reaching a backend path.
        from netbox_openbao.models.settings import validate_path_prefix

        validate_path_prefix(prefix)
        return f'{prefix}/credentials/{self.uuid}'

    @property
    def has_staged_version(self):
        """
        True while a candidate is written and awaiting promotion or discard.

        Tracked by its own field rather than inferred from
        `kv_version > live_kv_version`, because those two legitimately diverge
        after a discard: OpenBao's version counter never goes backwards, so
        `kv_version` stays high while nothing is staged.
        """
        return self.staged_kv_version is not None

    @property
    def is_expired(self):
        if self.valid_until is None:
            return False
        from django.utils import timezone
        return self.valid_until <= timezone.now()

    def _apply_defaults(self):
        """
        Default the engine from the policy so callers need only choose a tier.

        Applied in `clean()` as well as `save()` because NetBox's
        `ValidatedModelSerializer` runs `full_clean()` on an unsaved instance
        during REST validation — defaulting only in `save()` would make the
        API reject every create that omits `engine`, which is exactly the case
        the default exists to serve.
        """
        if self.policy_id and not self.engine_id:
            self.engine_id = self.policy.engine_id

    def full_clean(self, *args, **kwargs):
        # Defaults must be applied before validation, not during it: Django's
        # full_clean() runs clean_fields() first, which would already have
        # recorded "engine: This field cannot be null" by the time clean() got
        # a chance to fill it in.
        self._apply_defaults()
        super().full_clean(*args, **kwargs)

    def clean(self):
        self._apply_defaults()
        super().clean()

        # Replaces the field-level `choices` validation the field deliberately
        # does not have, so an operator-defined type is accepted and a typo
        # still is not.
        from netbox_openbao.secrets.registry import is_known_credential_type

        if self.credential_type and not is_known_credential_type(self.credential_type):
            raise ValidationError({
                'credential_type': _('Unknown credential type: {value}.').format(
                    value=self.credential_type,
                ),
            })

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
        # Repeated here for callers that bypass full_clean() (direct ORM use,
        # management commands, data migrations).
        self._apply_defaults()

        if not self._state.adding:
            return super().save(*args, **kwargs)

        using = kwargs.get('using') or router.db_for_write(type(self), instance=self)
        kwargs['using'] = using
        with transaction.atomic(using=using):
            # Prefix changes lock this same singleton row before their final
            # credential existence check. Whichever write obtains the lock
            # first commits a coherent outcome: the credential uses the new
            # prefix, or its existence prevents the prefix change.
            from netbox_openbao.models.settings import OpenBaoSettings

            settings_row = OpenBaoSettings._lock_for_prefix_write(using)

            # `path` is derived, not user-supplied, and is stamped once.
            # Recomputing it on every save would silently orphan material if
            # `path_prefix` were ever changed in deployment configuration.
            if not self.path:
                prefix = (
                    settings_row.path_prefix
                    if settings_row is not None
                    else get_config('path_prefix', 'netbox')
                )
                self.path = self._path_for_prefix(prefix)

            return super().save(*args, **kwargs)
