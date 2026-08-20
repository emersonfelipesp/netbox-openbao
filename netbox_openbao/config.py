"""Typed access to PLUGINS_CONFIG['netbox_openbao']."""

from netbox.plugins import get_plugin_config

PLUGIN_NAME = 'netbox_openbao'


def get_config(key, default=None):
    """
    Return a plugin configuration value.

    Falls back to `default` only when the key is absent from both the
    deployment's PLUGINS_CONFIG and the plugin's default_settings.
    """
    try:
        return get_plugin_config(PLUGIN_NAME, key)
    except KeyError:
        return default


def assignable_model_labels():
    """Lowercased "app_label.model" strings a Credential may be assigned to."""
    return [label.lower() for label in get_config('assignable_models', [])]
