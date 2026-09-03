"""Database-backed settings for netbox-openbao.

This row contains configuration only. OpenBao authentication material remains
in the process environment or referenced files and must never be added here.
"""

from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import connections, models, router, transaction
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel
from rest_framework.throttling import SimpleRateThrottle
from utilities.exceptions import AbortRequest

from netbox_openbao.choices import SSHKeyTypeChoices

__all__ = ('OpenBaoSettings', 'validate_path_prefix', 'validate_reveal_rate')

_UNSET = object()

# Prefix updates, row creation/deletion, and credential creation select the
# singleton for update when it exists. This transaction-level PostgreSQL lock
# closes the same race on a fresh installation where there is no row to lock.
_PREFIX_WRITE_LOCK_ID = 430100


def _default_assignable_models():
    return [
        'dcim.device',
        'virtualization.virtualmachine',
        'ipam.service',
    ]


def _default_expiry_warning_days():
    return [30, 14, 7, 1]


def validate_reveal_rate(value):
    """Reject values DRF's throttle parser cannot consume at request time."""
    try:
        requests, duration = SimpleRateThrottle.parse_rate(None, value)
    except (IndexError, KeyError, TypeError, ValueError):
        requests = duration = None
    if requests is None or requests < 1 or duration is None:
        raise ValidationError(
            _('Enter a valid DRF throttle rate such as "30/hour".'),
            code='invalid',
        )


def validate_path_prefix(prefix):
    """Reject an effective path prefix that could escape or alter its KV path."""
    if not isinstance(prefix, str):
        malformed = True
    else:
        segments = prefix.split('/')
        malformed = (
            not prefix
            or prefix.startswith('/')
            or prefix.endswith('/')
            or any(character.isspace() for character in prefix)
            or any(segment in ('', '.', '..') for segment in segments)
        )
    if malformed:
        raise ValidationError({
            'path_prefix': _(
                'The effective netbox_openbao path_prefix configuration must be a non-empty '
                'relative path without leading or trailing slashes, empty or traversal '
                'segments, or whitespace.'
            ),
        })


class OpenBaoSettings(NetBoxModel):
    """The singleton row controlling netbox-openbao runtime behaviour."""

    singleton_key = models.CharField(
        max_length=32,
        unique=True,
        default='default',
        editable=False,
    )
    path_prefix = models.CharField(
        verbose_name=_('path prefix'),
        max_length=200,
        default='netbox',
        help_text=_('Path beneath the KV mount used for newly created credentials.'),
    )
    assignable_models = ArrayField(
        base_field=models.CharField(max_length=100),
        verbose_name=_('assignable models'),
        default=_default_assignable_models,
        blank=True,
        help_text=_('Object types to which credentials may be assigned.'),
    )
    assignable_models_deny = ArrayField(
        base_field=models.CharField(max_length=100),
        verbose_name=_('denied assignable models'),
        default=list,
        blank=True,
        help_text=_('Object types refused even when an installed plugin registers them.'),
    )
    store_public_material = models.BooleanField(
        verbose_name=_('store public material'),
        default=True,
        help_text=_('Persist extracted public keys and certificate metadata in NetBox.'),
    )
    reveal_rate_limit = models.CharField(
        verbose_name=_('reveal rate limit'),
        max_length=64,
        default='30/hour',
        validators=(validate_reveal_rate,),
        help_text=_('Per-user DRF throttle rate for credential reveals, for example "30/hour".'),
    )
    reveal_ttl = models.PositiveIntegerField(
        verbose_name=_('reveal TTL'),
        default=300,
        help_text=_('Maximum lifetime in seconds advertised for revealed material.'),
    )
    token_cache_ttl = models.PositiveIntegerField(
        verbose_name=_('token cache TTL'),
        default=3600,
        help_text=_('Fallback token cache lifetime in seconds when login returns no lease.'),
    )
    audit_retention_days = models.PositiveIntegerField(
        verbose_name=_('audit retention days'),
        default=365,
        help_text=_('Credential access-log retention in days.'),
    )
    allow_generation = models.BooleanField(
        verbose_name=_('allow generation'),
        default=True,
        help_text=_('Allow server-side generation of credential material.'),
    )
    default_ssh_key_type = models.CharField(
        verbose_name=_('default SSH key type'),
        max_length=32,
        choices=SSHKeyTypeChoices,
        default=SSHKeyTypeChoices.TYPE_ED25519,
    )
    expiry_warning_days = ArrayField(
        base_field=models.PositiveIntegerField(),
        verbose_name=_('expiry warning days'),
        default=_default_expiry_warning_days,
        blank=True,
        help_text=_('Days before expiry at which the expiry scan reports a credential.'),
    )

    # These fields are stored now so the interval reconciliation work can use
    # them without another schema change. jobs.py deliberately continues to
    # read the five decorator arguments from PLUGINS_CONFIG until that work is
    # complete; presenting a value as live when it reverts on worker restart
    # would be worse than leaving its current restart-required semantics.
    engine_health_interval = models.PositiveIntegerField(
        verbose_name=_('engine health interval'),
        default=5,
        help_text=_('Engine health job interval in minutes.'),
    )
    expiry_scan_interval = models.PositiveIntegerField(
        verbose_name=_('expiry scan interval'),
        default=1440,
        help_text=_('Credential expiry scan interval in minutes.'),
    )
    credential_verify_interval = models.PositiveIntegerField(
        verbose_name=_('credential verification interval'),
        default=1440,
        help_text=_('Credential verification job interval in minutes.'),
    )
    rotation_due_interval = models.PositiveIntegerField(
        verbose_name=_('rotation due interval'),
        default=1440,
        help_text=_('Rotation-due scan interval in minutes.'),
    )
    access_log_prune_interval = models.PositiveIntegerField(
        verbose_name=_('access-log prune interval'),
        default=10080,
        help_text=_('Access-log pruning interval in minutes.'),
    )

    class Meta:
        verbose_name = _('OpenBao settings')
        verbose_name_plural = _('OpenBao settings')

    def __str__(self):
        return 'OpenBao settings'

    def clean(self):
        super().clean()
        prefix = self.path_prefix or ''
        validate_path_prefix(prefix)
        self._validate_prefix_change(prefix)

    def _validate_prefix_change(self, prefix, *, previous=_UNSET, using=None):
        """
        Refuse to move the prefix once credentials exist.

        Changing it cannot orphan existing material — `path` is stamped once at
        creation — so the danger is the opposite of the obvious one. The
        AppRole's OpenBao policy is scoped to the prefix, so **new** writes start
        being refused while every existing credential keeps working, and the
        resulting permission error reads as a vault outage rather than as a
        configuration change somebody made.
        """
        if previous is _UNSET:
            previous = self._stored_prefix()

        from netbox_openbao.models.credentials import Credential

        credentials = Credential.objects.using(using) if using else Credential.objects
        if previous is None:
            mismatched = any(
                credential.path != credential._path_for_prefix(prefix)
                for credential in credentials.only('path', 'uuid').iterator()
            )
            if mismatched:
                raise ValidationError({
                    'path_prefix': _(
                        "Path prefix cannot be set to '{prefix}' because existing Credential "
                        'rows are stamped under a different path prefix. Create the settings '
                        'row with the prefix already encoded in their stored paths.'
                    ).format(prefix=prefix),
                })
            return

        if prefix == previous:
            return

        if not credentials.exists():
            return

        raise ValidationError({
            'path_prefix': _(
                "Path prefix cannot be changed while credentials exist. The AppRole's OpenBao "
                'policy is scoped to secret/data/{prefix}/credentials/*; changing the prefix '
                'would make OpenBao refuse new credential writes with a permission error that '
                'looks like a vault outage, while every existing credential keeps working.'
            ).format(prefix=previous),
        })

    def _stored_prefix(self):
        """
        The prefix currently in force, read back rather than taken from `self`.

        NetBox's serializer and `ModelForm` both mutate the instance before
        `clean()` runs, so `self.path_prefix` is already the *incoming* value by
        this point. On creation, read the singleton by its fixed key so a second
        create compares against the authoritative row. Return `None` for the
        first row; existing credential paths then decide whether the proposed
        prefix is coherent.
        """
        if self.pk:
            return type(self).objects.filter(pk=self.pk).values_list('path_prefix', flat=True).first()
        return (
            type(self).objects.filter(singleton_key='default')
            .values_list('path_prefix', flat=True)
            .first()
        )

    def save(self, *args, **kwargs):
        """Force the singleton key and re-check prefix safety under a row lock."""
        self.singleton_key = 'default'
        using = kwargs.get('using') or router.db_for_write(type(self), instance=self)
        kwargs['using'] = using
        with transaction.atomic(using=using):
            locked = type(self)._lock_for_prefix_write(using)
            if self._state.adding:
                if locked is None:
                    self._validate_prefix_change(
                        self.path_prefix,
                        previous=None,
                        using=using,
                    )
                # An existing singleton is left to the unique constraint so the
                # API can translate the losing create into its structured 400.
                return super().save(*args, **kwargs)

            if locked is None or locked.pk != self.pk:
                raise ValidationError(
                    _('OpenBao settings cannot be saved because this row no longer exists.'),
                    code='stale',
                )

            updates_prefix = kwargs.get('update_fields') is None or 'path_prefix' in kwargs['update_fields']
            if updates_prefix:
                # Form and serializer validation necessarily happened before
                # this transaction. Re-check after taking the same lock that a
                # credential create takes, closing the validate/create/save
                # race without moving ordinary validation into save().
                self._validate_prefix_change(
                    self.path_prefix,
                    previous=locked.path_prefix,
                    using=using,
                )
            return super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        """Keep the authoritative prefix in place while credentials exist."""
        using = using or router.db_for_write(type(self), instance=self)
        with transaction.atomic(using=using):
            locked = type(self)._lock_for_prefix_write(using)
            if locked is not None:
                locked._ensure_deletable(using)
            # QuerySet.delete() does not call this method, so a pre_delete
            # receiver invokes the same model guard for that path. Mark the
            # instance to avoid running its existence query twice here.
            self._settings_delete_guard_checked = True
            try:
                return super().delete(using=using, keep_parents=keep_parents)
            finally:
                del self._settings_delete_guard_checked

    def _ensure_deletable(self, using):
        """Raise an HTTP/UI-safe refusal while any credential remains."""
        from netbox_openbao.models.credentials import Credential

        if Credential.objects.using(using).exists():
            raise AbortRequest(
                _(
                    "OpenBao settings cannot be deleted while credentials exist. The AppRole's "
                    'OpenBao policy is scoped to secret/data/{prefix}/credentials/*; deleting the '
                    'row could change the effective path prefix and make OpenBao refuse new '
                    'credential writes with a permission error that looks like a vault outage, '
                    'while every existing credential keeps working.'
                ).format(prefix=self.path_prefix)
            )

    @classmethod
    def _lock_for_prefix_write(cls, using):
        """Serialize prefix-dependent writes, including while the row is absent."""
        locked = cls._lock_for_write(using)
        if locked is not None:
            return locked

        # Every supported creator takes this lock before inserting the first
        # row. Re-check afterwards because a transaction that won the lock may
        # have created the singleton while this one waited.
        with connections[using].cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [_PREFIX_WRITE_LOCK_ID])
        return cls._lock_for_write(using)

    @classmethod
    def _lock_for_write(cls, using):
        """Lock the singleton row shared by prefix changes and credential creates."""
        return (
            cls.objects.using(using)
            .select_for_update()
            .filter(singleton_key='default')
            .only('path_prefix')
            .first()
        )

    @classmethod
    def get_solo(cls):
        """Return the singleton, creating it only on this explicit write path."""
        obj, _created = cls.objects.get_or_create(singleton_key='default')
        return obj
