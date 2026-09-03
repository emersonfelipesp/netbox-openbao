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

    Resolved from three sources, in this precedence:

    1. `assignable_models` — what the operator configured.
    2. The registry populated by `registry.register_assignable_models()`, which
       is how an integrating plugin declares its own credential-holding models
       from `AppConfig.ready()` instead of making every deployment restate them
       in a settings file.
    3. `assignable_models_deny` — subtracted from the union of the first two.

    **Deny wins.** Registration comes from installed code rather than from the
    operator, so without a subtraction an operator could not refuse an
    integration's choice without patching a plugin they did not write. With it,
    the allowlist is still theirs.

    Tolerates every key being absent or null. NetBox merges `default_settings`
    into `PLUGINS_CONFIG` at startup, so a deployment that replaces the dict
    afterwards — or a test using `override_settings` — can leave keys missing,
    and an allowlist that raises is worse than one that is empty.

    Sorted, because the returned list is rendered into
    `CredentialAssignment.clean()`'s error message; an operator comparing two
    instances should not have to notice that the same set printed in a
    different order.
    """
    def _normalize(values):
        return {
            label.strip().lower()
            for label in (values or [])
            if isinstance(label, str) and label.strip()
        }

    from netbox_openbao.registry import registered_assignable_models

    permitted = _normalize(get_config('assignable_models'))
    permitted |= registered_assignable_models()
    permitted -= _normalize(get_config('assignable_models_deny'))

    return sorted(permitted)
