from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import OrganizationalModel

__all__ = ('CredentialPolicy',)


class CredentialPolicy(OrganizationalModel):
    """
    An authorization tier, mapped onto a real OpenBao policy.

    The plugin holds a **separate AppRole per tier**, which bounds blast radius:
    a leaked SecretID reads only what that tier's OpenBao policy grants, and a
    tier whose SecretID was never delivered to an instance is unreadable from
    it at all.

    It is **not** a re-authorization of the NetBox user, and the documentation
    is careful about the difference. `get_backend()` selects the AppRole from
    the credential's own policy, so a NetBox permission bug that hands someone
    a `prod-core` credential makes the read with the `prod-core` AppRole —
    which is the identity authorized for that path. OpenBao allows it. Path
    separation only becomes real if tiers are given separate mounts, because
    credential paths are UUID-derived and every tier's policy covers all of
    them. See `docs/security.md`.
    """

    engine = models.ForeignKey(
        to='netbox_openbao.SecretEngine',
        on_delete=models.PROTECT,
        related_name='policies',
        verbose_name=_('secret engine'),
    )
    openbao_policy = models.CharField(
        verbose_name=_('OpenBao policy'),
        max_length=200,
        help_text=_('Name of the policy in OpenBao that this tier maps to, e.g. netbox-prod-core'),
    )
    approle_env_prefix = models.CharField(
        verbose_name=_('AppRole environment prefix'),
        max_length=100,
        blank=True,
        help_text=_(
            "Environment variable prefix for this tier's AppRole. Defaults to the engine's prefix when blank."
        ),
    )
    groups = models.ManyToManyField(
        to='users.Group',
        related_name='openbao_credential_policies',
        blank=True,
        verbose_name=_('groups'),
        help_text=_('Coarse gate applied in addition to object permissions, not instead of them'),
    )
    max_reveal_ttl = models.PositiveIntegerField(
        verbose_name=_('maximum reveal TTL'),
        default=300,
        validators=[MinValueValidator(1)],
        help_text=_('Seconds a revealed secret from this tier may be considered valid by a consumer'),
    )
    require_reason = models.BooleanField(
        verbose_name=_('require reason'),
        default=False,
        help_text=_('Force callers to supply a justification, recorded in the access log, on every reveal'),
    )

    clone_fields = ('engine', 'openbao_policy', 'approle_env_prefix', 'max_reveal_ttl', 'require_reason')

    class Meta:
        ordering = ('name',)
        verbose_name = _('credential policy')
        verbose_name_plural = _('credential policies')

    def __str__(self):
        return self.name

    @property
    def env_prefix(self):
        """The tier's AppRole prefix, falling back to the engine's."""
        return self.approle_env_prefix or self.engine.env_prefix
