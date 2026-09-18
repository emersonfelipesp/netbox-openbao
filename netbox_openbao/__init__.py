"""
netbox-openbao — OpenBao-backed credential storage for NetBox.

OpenBao is the system of record for secret *material*. NetBox is the system of
record for credential *inventory and relationships*. Nothing secret is ever
stored in a NetBox model field, which is what makes the changelog, export
templates, and the browsable API structurally safe rather than safe by
convention.
"""

from netbox.plugins import PluginConfig

__version__ = '0.1.0.post1'


class NetBoxOpenBaoConfig(PluginConfig):
    name = 'netbox_openbao'
    verbose_name = 'NetBox OpenBao'
    description = 'Store device, VM, and service secret material in OpenBao with NetBox-native relationships'
    version = __version__
    base_url = 'openbao'
    author = 'Emerson Felipe'
    author_email = 'emerson@netdevopsbr.com'

    # 4.6 and 4.7. The earlier 4.7-only pin was based on ipam.Service having
    # changed in two ways; only one of them turned out to be true. The parent
    # GenericForeignKey is already present in 4.6 — it is just the ports that
    # differ, `protocol` + `ports` there against `port_mappings` in 4.7 — and
    # `quickadd` now handles both, detecting which from the model's own field
    # set. Every other NetBox API this plugin imports exists in both releases.
    #
    # The floor matters operationally: the estate runs 4.6.5, and netbox-nms
    # supports 4.5.8-4.6.99, so a 4.7 floor left no version where the two could
    # be installed together and made netbox-nms#213 permanently dormant.
    #
    # The gate compares RELEASE.version, which is "4.7.0" on 4.7.0-beta2 (the
    # beta designation is a separate field), so this still loads on the beta.
    min_version = '4.6.0'
    max_version = '4.7.99'

    required_plugins = ['netbox_rpc']

    # Discards the thread-local settings memo after every response. NetBox
    # appends this to MIDDLEWARE at startup, so it needs nothing from the
    # operator. Without it a worker thread keeps whatever configuration it read
    # on its first request for the life of the process, and a settings change
    # appears to take on one thread and silently not on the others — see
    # `middleware.SettingsCacheMiddleware`.
    middleware = ['netbox_openbao.middleware.SettingsCacheMiddleware']

    required_settings = []
    default_settings = {
        # Path prefix beneath the KV mount. Full logical path for a credential
        # is "<path_prefix>/credentials/<uuid>".
        'path_prefix': 'netbox',

        # Object types a Credential may be assigned to. Anything not listed
        # here — and not registered by an installed plugin, see below — is
        # rejected at both form and API level.
        'assignable_models': [
            'dcim.device',
            'virtualization.virtualmachine',
            'ipam.service',
        ],

        # Object types to refuse even when an installed plugin registered them
        # through `registry.register_assignable_models()`. Registration comes
        # from code rather than from the operator, so this is what keeps the
        # allowlist theirs: deny wins over both the list above and the registry.
        'assignable_models_deny': [],

        # Persist non-secret public material (public keys, certificates) in
        # NetBox. Disabling this gives up the zero-read expiry dashboard.
        'store_public_material': True,

        # DRF throttle rate for the reveal endpoint, per user.
        'reveal_rate_limit': '30/hour',

        # Seconds a revealed secret is considered valid by consumers. Also the
        # ceiling applied to CredentialPolicy.max_reveal_ttl.
        'reveal_ttl': 300,

        # Fallback TTL (seconds) for a cached OpenBao token when the login
        # response carries no lease duration.
        'token_cache_ttl': 3600,

        # Days of CredentialAccessLog history retained by AccessLogPruneJob.
        'audit_retention_days': 365,

        # Allow the plugin to generate key material server-side.
        'allow_generation': True,
        'default_ssh_key_type': 'ed25519',

        # Optional second, human-readable path written alongside the canonical
        # UUID path. Off by default: it is a consistency liability.
        'path_alias_template': None,

        # Days before expiry at which ExpiryScanJob raises an event.
        'expiry_warning_days': [30, 14, 7, 1],

        # Background job intervals, in minutes. Read at import time by the
        # @system_job decorators in jobs.py.
        'engine_health_interval': 5,
        'expiry_scan_interval': 1440,
        'credential_verify_interval': 1440,
        'rotation_due_interval': 1440,
        'access_log_prune_interval': 10080,
    }

    def ready(self):
        # super().ready() resolves the conventional resource paths for us:
        # navigation.menu, template_content.template_extensions, and
        # search.indexes. The imports below cover what registers by decorator
        # rather than by exported name.
        super().ready()

        # jobs:    self-registers via @system_job at import time
        # search:   self-registers via @register_search
        # signals:  destroys material on delete, refreshes KV metadata
        # views:    ESSENTIAL — @register_model_view decorators live there, and
        #           urls.py resolves them through get_model_urls() at URLconf
        #           load. Drop this import and every plugin URL 404s.
        from . import checks, jobs, search, signals, views  # noqa: F401


config = NetBoxOpenBaoConfig
