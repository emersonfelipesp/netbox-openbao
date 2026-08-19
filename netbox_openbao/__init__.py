"""
netbox-openbao — OpenBao-backed credential storage for NetBox.

OpenBao is the system of record for secret *material*. NetBox is the system of
record for credential *inventory and relationships*. Nothing secret is ever
stored in a NetBox model field, which is what makes the changelog, export
templates, and the browsable API structurally safe rather than safe by
convention.
"""

from netbox.plugins import PluginConfig

__version__ = '0.1.0'


class NetBoxOpenBaoConfig(PluginConfig):
    name = 'netbox_openbao'
    verbose_name = 'NetBox OpenBao'
    description = 'Store device, VM, and service secret material in OpenBao with NetBox-native relationships'
    version = __version__
    base_url = 'openbao'
    author = 'Emerson Felipe'
    author_email = 'emerson.felipe@nmultifibra.com.br'

    # NetBox 4.7 only. 4.7 replaced ipam.Service's protocol/ports with
    # port_mappings and moved its parent to a GenericForeignKey; supporting 4.6
    # would mean branching on both. The version gate compares RELEASE.version,
    # which is "4.7.0" on 4.7.0-beta1 (the beta designation is a separate
    # field), so this correctly loads on the current beta.
    min_version = '4.7.0'
    max_version = '4.7.99'

    required_settings = []
    default_settings = {
        # Slug of the SecretEngine used when a Credential does not name one.
        'default_engine': None,

        # Path prefix beneath the KV mount. Full logical path for a credential
        # is "<path_prefix>/credentials/<uuid>".
        'path_prefix': 'netbox',

        # Object types a Credential may be assigned to. Anything not listed
        # here is rejected at both form and API level.
        'assignable_models': [
            'dcim.device',
            'virtualization.virtualmachine',
            'ipam.service',
        ],

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

        # Background job intervals, in minutes.
        'engine_health_interval': 5,
        'expiry_scan_interval': 1440,
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
        from . import jobs, search, signals, views  # noqa: F401


config = NetBoxOpenBaoConfig
