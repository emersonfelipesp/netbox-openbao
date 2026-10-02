"""
netbox-openbao — OpenBao-backed credential storage for NetBox.

OpenBao is the system of record for credential *material*. NetBox is the system
of record for credential *inventory and relationships*. Credential payloads
never enter a NetBox model field. OpenBao service identities are the narrow
exception: ``EngineAuthMaterial`` stores only versioned ciphertext, and every
serializer, changelog, export, search, and event surface exposes status rather
than that ciphertext.
"""

from netbox.plugins import PluginConfig

__version__ = '0.2.0rc1'


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
    # 4.7 is the floor because SSH credentials are tied to an Application
    # Service (`ipam.Service`) whose ports are stored as `port_mappings`, the
    # representation NetBox 4.7 introduced. Earlier releases are not supported.
    #
    # The gate compares RELEASE.version, which is "4.7.0" on 4.7.0-beta2 (the
    # beta designation is a separate field), so this still loads on the beta.
    min_version = '4.7.0'
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
    default_settings = {}

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
