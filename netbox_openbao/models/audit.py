from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from utilities.querysets import RestrictedQuerySet

from netbox_openbao.choices import AccessActionChoices

__all__ = ('CredentialAccessLog',)


class CredentialAccessLog(models.Model):
    """
    Correlates a NetBox user with an OpenBao access.

    OpenBao's own audit device is authoritative for what happened at the vault,
    but it only ever sees an AppRole — it cannot say *which NetBox user* asked.
    This table is the other half of that record.

    Deliberately a plain Django model, not a NetBoxModel: it is append-only
    evidence, so change logging, journaling, and tags would be noise at best
    and a second mutable copy of audit data at worst. It never stores a value.
    """

    credential = models.ForeignKey(
        to='netbox_openbao.Credential',
        on_delete=models.SET_NULL,
        related_name='access_logs',
        null=True,
        blank=True,
    )
    credential_name_snapshot = models.CharField(
        verbose_name=_('credential name'),
        max_length=200,
        help_text=_('Captured at access time so the record survives deletion of the credential'),
    )
    credential_uuid_snapshot = models.UUIDField(
        verbose_name=_('credential UUID'),
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='+',
        null=True,
        blank=True,
    )
    username_snapshot = models.CharField(
        verbose_name=_('username'),
        max_length=150,
        blank=True,
    )
    action = models.CharField(
        verbose_name=_('action'),
        max_length=50,
        choices=AccessActionChoices,
    )
    source_ip = models.GenericIPAddressField(
        verbose_name=_('source IP'),
        null=True,
        blank=True,
    )
    reason = models.TextField(
        verbose_name=_('reason'),
        blank=True,
    )
    request_id = models.CharField(
        verbose_name=_('request ID'),
        max_length=64,
        blank=True,
        help_text=_("NetBox's per-request ID, for correlation with OpenBao audit entries"),
    )
    success = models.BooleanField(
        verbose_name=_('success'),
        default=True,
    )
    message = models.CharField(
        verbose_name=_('message'),
        max_length=500,
        blank=True,
        help_text=_('Scrubbed failure summary. Never contains secret material.'),
    )
    timestamp = models.DateTimeField(
        verbose_name=_('timestamp'),
        auto_now_add=True,
        db_index=True,
    )
    executor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='+', null=True, blank=True,
    )
    executor_snapshot = models.CharField(max_length=150, blank=True, db_default='')
    execution_id = models.PositiveBigIntegerField(null=True, blank=True, db_index=True)
    intent_run_id = models.PositiveBigIntegerField(null=True, blank=True)
    step_id = models.CharField(max_length=100, blank=True, db_default='')
    reference_name = models.CharField(max_length=100, blank=True, db_default='')
    assignment_id = models.PositiveBigIntegerField(null=True, blank=True)
    resolved_version = models.PositiveIntegerField(null=True, blank=True)
    purpose = models.CharField(max_length=50, blank=True, db_default='')
    dispatch_nonce_digest = models.CharField(max_length=64, blank=True, db_default='')

    # NetBox's generic views call queryset.restrict(); a plain models.Manager
    # has no such method, so the object-permission-aware manager is opted into
    # explicitly here rather than inherited from NetBoxModel.
    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ('-timestamp', '-pk')
        verbose_name = _('credential access log')
        verbose_name_plural = _('credential access logs')
        indexes = (
            models.Index(fields=('credential', '-timestamp')),
            models.Index(fields=('user', '-timestamp')),
        )

    def __str__(self):
        return f'{self.timestamp:%Y-%m-%d %H:%M:%S} {self.action} {self.credential_name_snapshot}'

    def get_absolute_url(self):
        return reverse('plugins:netbox_openbao:credentialaccesslog', args=[self.pk])

    def get_action_color(self):
        return AccessActionChoices.colors.get(self.action)
