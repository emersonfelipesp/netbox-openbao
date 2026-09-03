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
from utilities.querysets import RestrictedQuerySet

from netbox_openbao.choices import SSHKeyTypeChoices

__all__ = (
    'STATIC_INTERVAL_SETTINGS',
    'OpenBaoSettings',
    'validate_path_prefix',
    'validate_reveal_rate',
)

#: Stored on the model, still read from PLUGINS_CONFIG at import by the
#: @system_job decorators. Declared once so the form, the panel, and the startup
#: warning cannot disagree about which settings are not yet live.
STATIC_INTERVAL_SETTINGS = (
    'engine_health_interval',
    'expiry_scan_interval',
    'credential_verify_interval',
    'rotation_due_interval',
    'access_log_prune_interval',
)

#: Excluded from the change audit: the intervals, which are stored but not yet
#: acted on, and the housekeeping columns NetBox contributes. Module scope
#: rather than a class attribute, because `check_no_secret_fields.py` parses
#: class-body assignments looking for fields and a constant there is noise in
#: exactly the signal that script exists to keep clean.
NOT_AUDITED = frozenset(STATIC_INTERVAL_SETTINGS) | {
    'id', 'singleton_key', 'created', 'last_updated', 'custom_field_data', 'tags',
}

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


class OpenBaoSettingsQuerySet(RestrictedQuerySet):
    """
    Audit a refused bulk deletion once its own transaction has unwound.

    `QuerySet.delete()` never calls `Model.delete()`, so the guard reaches it
    through a `pre_delete` receiver — which fires inside the atomic block
    `QuerySet.delete()` opens, where an audit row cannot survive the refusal
    that follows it. Catching here is the first point outside that block.

    One limit is worth stating rather than discovering: a caller that wraps the
    deletion in a transaction of its own — DRF's bulk destroy does — rolls this
    record back too. The guard, not the record, is the enforcement, and the
    refusal is logged either way.
    """

    def delete(self, *args, **kwargs):
        instances = list(self)
        try:
            return super().delete(*args, **kwargs)
        except AbortRequest:
            for instance in instances:
                instance._audit_refusal('delete', 'credentials exist')
            raise


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

    objects = OpenBaoSettingsQuerySet.as_manager()

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

    @staticmethod
    def _audit_refusal(field, detail):
        """
        Record a refused configuration change.

        A refusal is worth more to an operator reconstructing an incident than a
        successful change: it is evidence that somebody tried to widen a control
        and was stopped. This lives on the model rather than in a view or a
        serializer so every surface — UI, REST API, management command — is
        covered by one implementation instead of three that can disagree.

        Best-effort, and bounded in one way worth knowing. Django offers no
        rollback hook, so this must be called from outside any transaction the
        refusal will roll back — `delete()` and the queryset's `delete()` both
        catch `AbortRequest` and record it afterwards, and validation refusals
        run before the write transaction opens at all. What remains outside
        reach is a caller that wraps the whole operation in a transaction of its
        own, such as DRF's bulk destroy. The guard itself — not this record — is
        the enforcement.
        """
        try:
            from netbox.context import current_request

            from netbox_openbao.services import log_settings_change

            request = current_request.get()
            log_settings_change(
                getattr(request, 'user', None),
                request=request,
                success=False,
                message=f'Refused change to {field}: {detail}',
            )
        except Exception:
            import logging

            logging.getLogger('netbox.plugins.netbox_openbao').exception(
                'Could not audit a refused settings change to %s', field,
            )

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
                self._audit_refusal('path_prefix', 'existing credentials are stamped under a different prefix')
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

        self._audit_refusal('path_prefix', 'credentials exist')
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

    def _changed_field_names(self, committed=None, update_fields=None):
        """
        Field names differing from the committed row, for the audit record.

        Names only — the access log's contract is that it carries no values, and
        a rate limit is not secret but a log that sometimes carries values is one
        somebody will later extend to carry the wrong one.
        """
        if self.pk is None:
            return []
        if committed is None:
            committed = type(self).objects.filter(pk=self.pk).first()
        if committed is None:
            return []
        candidates = self.audited_fields()
        if update_fields is not None:
            # `save(update_fields=...)` persists only these, so reporting a diff
            # on anything else would name a change that was never written.
            persisted = set(update_fields)
            candidates = tuple(name for name in candidates if name in persisted)

        return [
            name for name in candidates
            if getattr(self, name, None) != getattr(committed, name, None)
        ]

    @classmethod
    def audited_fields(cls):
        """
        Concrete fields whose change is worth an audit record.

        Derived from the model rather than imported from
        `config.MODEL_BACKED_SETTINGS`: that module imports this one lazily to
        break a cycle, and importing it back at class-definition time would
        reinstate it.
        """
        return tuple(
            field.name for field in cls._meta.concrete_fields
            if field.name not in NOT_AUDITED
        )

    def save(self, *args, **kwargs):
        """
        Force the singleton key and re-check prefix safety under a row lock.

        A refusal raised below is audited from out here, after the transaction
        has unwound. Recording it inside would put the row into exactly the
        transaction the refusal discards.
        """
        self.singleton_key = 'default'
        using = kwargs.get('using') or router.db_for_write(type(self), instance=self)
        kwargs['using'] = using
        try:
            return self._save_locked(*args, **kwargs)
        except AbortRequest:
            self._audit_refusal('singleton_key', 'settings already exist')
            raise

    def _save_locked(self, *args, **kwargs):
        """The write itself, under the singleton row lock."""
        using = kwargs['using']
        with transaction.atomic(using=using):
            locked = type(self)._lock_for_prefix_write(using)
            # Diffed against the LOCKED row, not against whatever was committed
            # when this instance was loaded. Two administrators editing the same
            # settings concurrently would otherwise each report a diff against
            # their own stale snapshot, and the audit would describe a change
            # that never happened.
            self._openbao_changed_fields = self._changed_field_names(
                locked, update_fields=kwargs.get('update_fields'),
            )
            if self._state.adding:
                if locked is None:
                    self._validate_prefix_change(
                        self.path_prefix,
                        previous=None,
                        using=using,
                    )
                elif locked is not None:
                    # Two concurrent creates both pass form and serializer
                    # validation, because `exists()` there runs before either
                    # inserts. The loser would otherwise reach PostgreSQL's
                    # unique constraint as an `IntegrityError`, which
                    # `ObjectEditView` does not catch — a 500 on a page whose
                    # only fault was losing a race. The advisory lock taken
                    # above serialises the two, so re-checking here is decisive
                    # rather than another hopeful `exists()`. The refusal is
                    # audited by the caller below, once this transaction has
                    # unwound and a row can actually commit.
                    raise AbortRequest(
                        _(
                            'OpenBao settings already exist. Edit the existing configuration '
                            'instead of creating a second one.'
                        )
                    )
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
        """
        Keep the authoritative prefix in place while credentials exist.

        The refusal is audited **after** the transaction below has unwound, not
        from inside the guard. A row written inside a transaction that then
        raises is rolled back with it, so the audit recorded the refusal into
        exactly the transaction that discarded it — the one record an operator
        reconstructing an incident most wants, reliably absent.
        """
        using = using or router.db_for_write(type(self), instance=self)
        try:
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
        except AbortRequest:
            self._audit_refusal('delete', 'credentials exist')
            raise

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
        """
        Lock the singleton row shared by prefix changes and credential creates.

        Loads the whole row rather than deferring to `path_prefix`. The audit
        diff reads every audited field off this instance, and a deferred field
        costs a refresh query *each* — turning one row read into roughly one
        query per setting on every save. Selecting the columns once is cheaper
        than being clever about which of them will be touched.
        """
        return (
            cls.objects.using(using)
            .select_for_update()
            .filter(singleton_key='default')
            .first()
        )

    @property
    def superseded_plugins_config_keys(self):
        """
        Keys still set in `PLUGINS_CONFIG` that this row now overrides.

        Once a row exists it is authoritative, so a key left in the settings
        file is silently ignored. That is the single most likely support
        question this change creates — an operator edits a value they can see
        and nothing happens — so it is surfaced on the object page and warned
        about at startup rather than left to be discovered.

        Interval keys are excluded: they are genuinely still read from the file,
        so listing them here would be wrong.
        """
        from django.conf import settings as django_settings

        from netbox_openbao.config import MODEL_BACKED_SETTINGS

        configured = (django_settings.PLUGINS_CONFIG or {}).get('netbox_openbao') or {}
        live = set(MODEL_BACKED_SETTINGS) - set(STATIC_INTERVAL_SETTINGS)
        superseded = sorted(key for key in live if key in configured)
        return ', '.join(superseded) or _('None')

    @property
    def static_interval_summary(self):
        """Name the settings this row stores but does not yet govern."""
        return _('%(keys)s (read from PLUGINS_CONFIG at worker start)') % {
            'keys': ', '.join(STATIC_INTERVAL_SETTINGS),
        }

    @classmethod
    def get_solo(cls):
        """Return the singleton, creating it only on this explicit write path."""
        obj, _created = cls.objects.get_or_create(singleton_key='default')
        return obj
