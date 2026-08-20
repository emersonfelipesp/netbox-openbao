"""Typed access to PLUGINS_CONFIG['netbox_openbao']."""

from netbox.plugins import get_plugin_config

PLUGIN_NAME = 'netbox_openbao'


def get_config(key, default=None):
    """
    Return a plugin configuration value, falling back to `default`.

    The fallback covers a missing key *and* a null value. NetBox merges
    `default_settings` into `PLUGINS_CONFIG` at startup, and
    `get_plugin_config()` returns None rather than raising for a key that is
    not in the merged result — so any deployment that replaces the dict after
    startup, or any test using `override_settings`, silently gets None.

    That mattered: `store_public_material` resolving to None instead of True
    turned metadata extraction off without any error, which looks exactly like
    the extractors failing.
    """
    try:
        value = get_plugin_config(PLUGIN_NAME, key)
    except KeyError:
        return default
    return default if value is None else value


def assignable_model_labels():
    """
    Lowercased "app_label.model" strings a Credential may be assigned to.

    Tolerates the key being absent or null. NetBox merges `default_settings`
    into `PLUGINS_CONFIG` at startup, so a deployment that replaces the dict
    afterwards — or a test using `override_settings` — can leave keys missing,
    and an allowlist that raises is worse than one that is empty.
    """
    return [label.lower() for label in (get_config('assignable_models') or [])]
