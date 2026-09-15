"""OpenBao administration inventory and metadata-only audit records."""

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from netbox.models import PrimaryModel
from utilities.querysets import RestrictedQuerySet

from netbox_openbao.choices import AuthMethodChoices, BackendChoices, EngineStatusChoices

__all__ = ("OpenBaoAdministrationLog", "OpenBaoCluster")


class OpenBaoCluster(PrimaryModel):
    """One OpenBao API endpoint and namespace, independent of any mounted engine."""

    name = models.CharField(max_length=100, unique=True, verbose_name=_("name"))
    slug = models.SlugField(max_length=100, unique=True, verbose_name=_("slug"))
    backend = models.CharField(
        max_length=50,
        choices=BackendChoices,
        default=BackendChoices.BACKEND_OPENBAO,
        verbose_name=_("backend"),
    )
    api_url = models.URLField(
        max_length=200,
        verbose_name=_("API URL"),
        help_text=_("Base URL of the OpenBao API, for example https://bao.example.net:8200"),
    )
    namespace = models.CharField(max_length=200, blank=True, verbose_name=_("namespace"))
    auth_method = models.CharField(
        max_length=50,
        choices=AuthMethodChoices,
        default=AuthMethodChoices.METHOD_APPROLE,
        verbose_name=_("authentication method"),
    )
    tls_verify = models.BooleanField(default=True, verbose_name=_("verify TLS"))
    ca_cert_path = models.CharField(
        max_length=500,
        blank=True,
        verbose_name=_("CA certificate path"),
        help_text=_("Filesystem path to the CA bundle used to verify the OpenBao certificate"),
    )
    host_device = models.ForeignKey(
        to="dcim.Device",
        on_delete=models.PROTECT,
        related_name="openbao_clusters",
        null=True,
        blank=True,
        verbose_name=_("OpenBao host"),
    )

    # Observed metadata only. No response body or authentication material is persisted.
    status = models.CharField(
        max_length=50,
        choices=EngineStatusChoices,
        default=EngineStatusChoices.STATUS_UNKNOWN,
        editable=False,
        verbose_name=_("status"),
    )
    status_message = models.CharField(
        max_length=500,
        blank=True,
        editable=False,
        verbose_name=_("status message"),
    )
    last_checked = models.DateTimeField(null=True, blank=True, editable=False, verbose_name=_("last checked"))
    openbao_version = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        verbose_name=_("OpenBao version"),
    )
    capability_digest = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        verbose_name=_("capability digest"),
        help_text=_("SHA-256 of the last successfully normalized OpenAPI capability document"),
    )
    capabilities_checked = models.DateTimeField(
        null=True,
        blank=True,
        editable=False,
        verbose_name=_("capabilities checked"),
    )

    clone_fields = (
        "backend",
        "api_url",
        "namespace",
        "auth_method",
        "tls_verify",
        "ca_cert_path",
        "host_device",
    )

    class Meta:
        ordering = ("name",)
        verbose_name = _("OpenBao cluster")
        verbose_name_plural = _("OpenBao clusters")
        permissions = (
            ("discover", "Discover OpenBao administrative capabilities"),
            ("operate", "Run non-sensitive OpenBao administrative operations"),
            ("operate_sensitive", "Run material-bearing OpenBao administrative operations"),
            ("operate_destructive", "Run destructive OpenBao administrative operations"),
            ("initialize", "Initialize an OpenBao cluster"),
            ("unseal", "Submit OpenBao unseal material or reset unseal progress"),
            ("seal", "Seal an OpenBao cluster"),
            ("manage_raft", "Manage OpenBao Raft configuration"),
            ("remove_raft_peer", "Remove an OpenBao Raft peer"),
            ("download_raft_snapshot", "Download an OpenBao Raft snapshot"),
            ("restore_raft_snapshot", "Restore an OpenBao Raft snapshot"),
            ("force_restore_raft_snapshot", "Force restore an OpenBao Raft snapshot"),
            ("view_authentication", "View OpenBao authentication and MFA configuration"),
            ("manage_auth_methods", "Enable, configure, tune, and remount OpenBao auth methods"),
            ("disable_auth_methods", "Disable OpenBao auth methods"),
            ("manage_auth_resources", "Manage OpenBao auth method resources"),
            ("delete_auth_resources", "Delete OpenBao auth method resources"),
            ("issue_auth_material", "Issue one-shot OpenBao authentication material"),
            ("authenticate", "Use OpenBao authentication and MFA flows"),
            ("manage_tokens", "Look up and renew OpenBao tokens"),
            ("revoke_tokens", "Revoke OpenBao tokens"),
            ("manage_mfa", "Manage OpenBao MFA methods and login enforcements"),
            ("delete_mfa", "Delete OpenBao MFA methods, secrets, and login enforcements"),
            ("view_secret_engines", "View OpenBao secrets-engine configuration"),
            ("manage_secret_engines", "Enable, tune, and remount OpenBao secrets engines"),
            ("disable_secret_engines", "Disable OpenBao secrets engines"),
            ("explore_secret_operations", "View classified OpenBao mounted operations"),
            ("execute_secret_operations", "Execute write operations on OpenBao secrets engines"),
            ("delete_secret_operations", "Delete or destroy mounted OpenBao secret resources"),
            ("reveal_secret_operations", "Read material-bearing OpenBao secrets-engine responses"),
            ("reveal_kv_secrets", "Read KV secret values, metadata, versions, and diffs"),
            ("manage_kv_secrets", "Create, update, patch, undelete, and configure KV secrets"),
            ("destroy_kv_versions", "Delete or irreversibly destroy KV secrets and versions"),
            ("use_transit", "Use OpenBao transit cryptographic operations"),
            ("manage_transit_keys", "Create, configure, and rotate OpenBao transit keys"),
            ("delete_transit_keys", "Delete OpenBao transit keys"),
            ("generate_database_credentials", "Generate OpenBao database credentials"),
            ("manage_database_roles", "Manage OpenBao database connections and roles"),
            ("delete_database_resources", "Delete OpenBao database connections and roles"),
            ("rotate_database_credentials", "Rotate OpenBao database credentials and connections"),
            ("issue_ssh_credentials", "Issue and verify OpenBao SSH credentials and certificates"),
            ("manage_ssh_roles", "Manage OpenBao SSH roles"),
            ("delete_ssh_roles", "Delete OpenBao SSH roles"),
            ("generate_totp_codes", "Generate and validate OpenBao TOTP codes"),
            ("manage_totp_keys", "Create and view OpenBao TOTP keys"),
            ("delete_totp_keys", "Delete OpenBao TOTP keys"),
        )

    def __str__(self):
        return self.name

    @property
    def env_prefix(self):
        """Environment prefix used for this cluster's service identity."""
        return f"NETBOX_BAO_{self.slug.upper().replace('-', '_')}"

    def get_status_color(self):
        return EngineStatusChoices.colors.get(self.status)


class OpenBaoAdministrationLog(models.Model):
    """Append-only NetBox actor correlation for OpenBao administration calls."""

    cluster = models.ForeignKey(
        to="netbox_openbao.OpenBaoCluster",
        on_delete=models.SET_NULL,
        related_name="administration_logs",
        null=True,
        blank=True,
    )
    cluster_name_snapshot = models.CharField(max_length=100, verbose_name=_("cluster name"))
    cluster_slug_snapshot = models.CharField(max_length=100, verbose_name=_("cluster slug"))
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="+",
        null=True,
        blank=True,
    )
    username_snapshot = models.CharField(max_length=150, blank=True, verbose_name=_("username"))
    action = models.CharField(max_length=100, verbose_name=_("action"))
    operation_id = models.CharField(max_length=200, blank=True, verbose_name=_("operation ID"))
    risk_level = models.CharField(max_length=32, verbose_name=_("risk level"))
    method = models.CharField(max_length=16, blank=True, verbose_name=_("method"))
    path_template = models.CharField(max_length=500, blank=True, verbose_name=_("path template"))
    source_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name=_("source IP"))
    reason = models.TextField(blank=True, verbose_name=_("reason"))
    request_id = models.CharField(max_length=64, blank=True, verbose_name=_("request ID"))
    capability_digest = models.CharField(max_length=64, blank=True, verbose_name=_("capability digest"))
    outcome = models.CharField(
        max_length=32,
        choices=(
            ("authorized", _("Authorized")),
            ("succeeded", _("Succeeded")),
            ("failed", _("Failed")),
            ("unknown", _("Unknown")),
        ),
        default="succeeded",
        verbose_name=_("outcome"),
    )
    success = models.BooleanField(default=True, verbose_name=_("success"))
    status_code = models.PositiveSmallIntegerField(null=True, blank=True, verbose_name=_("status code"))
    message = models.CharField(
        max_length=500,
        blank=True,
        verbose_name=_("message"),
        help_text=_("Fixed safe summary. Request bodies, response bodies, and backend diagnostics are forbidden."),
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name=_("timestamp"))

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ("-timestamp", "-pk")
        verbose_name = _("OpenBao administration log")
        verbose_name_plural = _("OpenBao administration logs")
        default_permissions = ("view",)
        indexes = (
            models.Index(fields=("cluster", "-timestamp")),
            models.Index(fields=("user", "-timestamp")),
            models.Index(fields=("operation_id", "-timestamp")),
        )

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.action} {self.cluster_name_snapshot}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_openbao:openbaoadministrationlog", args=[self.pk])
