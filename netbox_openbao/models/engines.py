from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import PrimaryModel

from netbox_openbao.choices import AuthMethodChoices, EngineStatusChoices

__all__ = ('SecretEngine',)


class SecretEngine(PrimaryModel):
    """
    One OpenBao instance plus a single KV mount on it.

    Deliberately holds **no authentication material**. RoleIDs, SecretIDs, and
    tokens are resolved at runtime from the process environment, keyed by
    `env_prefix`. Storing the vault's own credentials in the database this
    plugin exists to keep secrets out of would defeat the entire design.
    """

    name = models.CharField(
        verbose_name=_('name'),
        max_length=100,
        unique=True,
    )
    slug = models.SlugField(
        verbose_name=_('slug'),
        max_length=100,
        unique=True,
        help_text=_("Also derives the environment variable prefix for this engine's credentials"),
    )
    api_url = models.URLField(
        verbose_name=_('API URL'),
        max_length=200,
        help_text=_('Base URL of the OpenBao API, e.g. https://bao.example.net:8200'),
    )
    namespace = models.CharField(
        verbose_name=_('namespace'),
        max_length=200,
        blank=True,
        help_text=_('OpenBao namespace, if the deployment uses them'),
    )
    kv_mount = models.CharField(
        verbose_name=_('KV mount'),
        max_length=100,
        default='secret',
        help_text=_('Mount point of the key/value secrets engine'),
    )
    kv_version = models.PositiveSmallIntegerField(
        verbose_name=_('KV version'),
        default=2,
        validators=[MinValueValidator(1)],
        help_text=_('KV secrets engine version. Version 2 is required for versioning and custom metadata.'),
    )
    auth_method = models.CharField(
        verbose_name=_('auth method'),
        max_length=50,
        choices=AuthMethodChoices,
        default=AuthMethodChoices.METHOD_APPROLE,
    )
    tls_verify = models.BooleanField(
        verbose_name=_('verify TLS'),
        default=True,
        help_text=_('Disabling this exposes every secret read to interception. Development only.'),
    )
    ca_cert_path = models.CharField(
        verbose_name=_('CA certificate path'),
        max_length=500,
        blank=True,
        help_text=_('Filesystem path to a CA bundle used to verify the OpenBao certificate'),
    )
    is_default = models.BooleanField(
        verbose_name=_('is default'),
        default=False,
        help_text=_('Used by credentials that do not name an engine. At most one engine may be the default.'),
    )

    # Observed state. Written by EngineHealthJob; not user-editable.
    status = models.CharField(
        verbose_name=_('status'),
        max_length=50,
        choices=EngineStatusChoices,
        default=EngineStatusChoices.STATUS_UNKNOWN,
        editable=False,
    )
    last_checked = models.DateTimeField(
        verbose_name=_('last checked'),
        null=True,
        blank=True,
        editable=False,
    )
    status_message = models.CharField(
        verbose_name=_('status message'),
        max_length=500,
        blank=True,
        editable=False,
        help_text=_('Scrubbed summary of the last health check result'),
    )

    clone_fields = (
        'api_url', 'namespace', 'kv_mount', 'kv_version', 'auth_method', 'tls_verify', 'ca_cert_path',
    )

    class Meta:
        ordering = ('name',)
        verbose_name = _('secret engine')
        verbose_name_plural = _('secret engines')
        constraints = (
            models.UniqueConstraint(
                fields=('is_default',),
                condition=models.Q(is_default=True),
                name='%(app_label)s_%(class)s_single_default',
                violation_error_message=_('Another engine is already marked as the default.'),
            ),
        )

    def __str__(self):
        return self.name

    @property
    def env_prefix(self):
        """
        Environment variable prefix for this engine's auth material, e.g. slug
        `prod-core` yields `NETBOX_BAO_PROD_CORE`, so the AppRole is read from
        `NETBOX_BAO_PROD_CORE_ROLE_ID` / `..._SECRET_ID`.
        """
        return f"NETBOX_BAO_{self.slug.upper().replace('-', '_')}"

    def get_status_color(self):
        return EngineStatusChoices.colors.get(self.status)
