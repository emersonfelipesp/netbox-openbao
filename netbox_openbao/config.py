"""
Settings-row access, memoised per request, with a `PLUGINS_CONFIG` fallback.

Resolution order:

    per-request memo  →  settings row  →  PLUGINS_CONFIG  →  caller default

**There is deliberately no shared cache layer.** An earlier revision mirrored
NetBox's own two-layer configuration cache — a thread-local in front of the
Django cache — and it was the wrong shape for this. Two independent defects
came directly from that second layer:

* A concurrent fill race. A reader loads the row, another process commits a
  change and deletes the shared key, and then the first reader completes its
  `cache.set()` with the snapshot it had already fetched. On a shared backend
  with no expiry, that stale entry stays authoritative indefinitely — including
  for `reveal_rate_limit` and `allow_generation`, which are security controls
  rather than preferences.
* A hard dependency on cache availability. Every read went through
  `cache.get()`, so a Redis outage made configuration unreadable, and an
  invalidation failure *after* a committed write surfaced as a 500 on a request
  whose database change had already succeeded.

Both were fixable, and fixing them meant versioned keys or a distributed lock
plus best-effort wrappers on every cache call. What that machinery buys is
measurable and small: the per-request memo alone already collapses a page's
several `get_config()` calls into **one** query — `assertNumQueries` in
`tests/test_settings.py` pins it. The shared layer only turned that one into
zero, on a page where NetBox itself issues dozens.

So the memo stays and the shared cache is gone. One indexed lookup on a
single-row table, per request, is the entire cost.

The memo's lifetime is bounded by whoever created it: `SettingsCacheMiddleware`
discards it after each response, and the job runners discard it around each run.
Without one of those a long-lived process would hold its first snapshot forever.
"""

import logging
import threading

from django.core.exceptions import ImproperlyConfigured
from django.db import connections
from django.db.utils import DatabaseError
from netbox.plugins import get_plugin_config

PLUGIN_NAME = 'netbox_openbao'

# Fetched in one query and memoised as one object. This read path sits on every
# object detail render through the globally registered credential panel, as well
# as on assignment validation and each reveal, so a query per key would be a
# per-page regression across the whole estate.
MODEL_BACKED_SETTINGS = (
    'path_prefix',
    'assignable_models',
    'assignable_models_deny',
    'store_public_material',
    'reveal_rate_limit',
    'reveal_ttl',
    'token_cache_ttl',
    'audit_retention_days',
    'allow_generation',
    'default_ssh_key_type',
    'expiry_warning_days',
    'engine_health_interval',
    'expiry_scan_interval',
    'credential_verify_interval',
    'rotation_due_interval',
    'access_log_prune_interval',
)

logger = logging.getLogger('netbox.plugins.netbox_openbao')
_thread_locals = threading.local()

# The sentinel means "the query ran and there is no settings row." It is a real
# per-request answer, not an uninitialised memo, so a no-row deployment still
# issues one query per request rather than one query per key.
_MISSING = object()


class Config:
    """One snapshot of the settings row, or `_MISSING` when none exists."""

    def __init__(self):
        self.values = self._populate_from_db()

    @staticmethod
    def _populate_from_db():
        # Imported lazily: `Credential` calls `get_config` while the model
        # package is still being populated, so importing the settings model at
        # module scope would make that package depend on its own incomplete
        # `__init__`.
        from netbox_openbao.models.settings import OpenBaoSettings

        try:
            # Never `get_or_create` here. A read must leave a missing row
            # missing, or the database becomes authoritative the first time
            # anything asks for a setting and `PLUGINS_CONFIG` stops being
            # reachable — which would also make every `override_settings` test
            # in this suite pass while asserting against defaults.
            values = OpenBaoSettings.objects.values(*MODEL_BACKED_SETTINGS).first()
            return _MISSING if values is None else values
        except DatabaseError:
            # A management command can import the plugin before `migrate` has
            # created the table, and the database can simply be down. Neither
            # may take the process with it; fall back for this snapshot.
            logger.warning('Skipping OpenBao settings initialization (database unavailable)')
            return _MISSING


def _settings_write_is_uncommitted():
    """
    True while this thread sits inside the transaction that wrote settings.

    A `post_save` receiver fires *before* its surrounding transaction commits.
    The writing thread should see its own change, but that row may still be
    rolled back — and Django has no rollback hook with which to discard a memo
    built from it. So while the marker matches, reads go straight to the
    database and are not memoised; once the transaction ends the marker stops
    matching and normal memoisation resumes.
    """
    pending = getattr(_thread_locals, 'settings_write_transaction', None)
    if pending is None:
        return False

    alias, marker = pending
    try:
        connection = connections[alias]
        still_open = bool(marker) and connection.in_atomic_block
    except Exception:
        still_open = False

    if not still_open:
        del _thread_locals.settings_write_transaction
    return still_open


def _current_config():
    if _settings_write_is_uncommitted():
        return Config()

    if not hasattr(_thread_locals, 'config'):
        _thread_locals.config = Config()
    return _thread_locals.config


def clear_config(*, pending_write=False, using='default'):
    """
    Discard this thread's settings snapshot.

    `pending_write` is set by the save/delete receiver. It records that a write
    is in flight in the current transaction, so reads until that transaction
    ends bypass the memo rather than caching a value that may not survive.
    """
    if hasattr(_thread_locals, 'config'):
        del _thread_locals.config
    if hasattr(_thread_locals, 'settings_write_transaction'):
        del _thread_locals.settings_write_transaction

    if not pending_write:
        return

    try:
        connection = connections[using]
        in_transaction = connection.in_atomic_block
    except Exception:
        in_transaction = False

    if in_transaction:
        _thread_locals.settings_write_transaction = (using, True)


def get_config(key, default=None):
    """
    Return one configuration value, without changing the caller-facing API.

    Keeping this signature and its fallback semantics identical is what makes
    the move to database-backed settings a substitution at every call site
    rather than a rewrite of their logic.

    A null resolves to `default`, which is load-bearing rather than incidental:
    `get_plugin_config()` returns `None` for a key absent from the merged
    result, and treating that as a real value once turned `store_public_material`
    off silently and looked exactly like the extractors failing.
    """
    values = _current_config().values
    value = _MISSING if values is _MISSING else values.get(key, _MISSING)
    if value is _MISSING:
        try:
            value = get_plugin_config(PLUGIN_NAME, key)
        except (ImproperlyConfigured, KeyError):
            value = None
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
