"""
The integration point for plugins that want their own objects to hold credentials.

`CredentialAssignment` accepts only the object types a deployment has opted
into, and until now the only way to opt one in was to hand-edit
`PLUGINS_CONFIG['netbox_openbao']['assignable_models']`. That is the right
control for an *operator* and the wrong mechanism for an *integrating plugin*:
a plugin that stores its secrets here already knows which of its models are
credential holders, and making the operator restate that in a settings file
means the integration is silently inert until someone reads the right paragraph
of the right README. The failure it produces — a validation error on a form
about a configuration file the operator was never pointed at — is a poor way to
learn that.

So a plugin registers its own models from `AppConfig.ready()`::

    from netbox_openbao.registry import register_assignable_models

    class MyPluginConfig(PluginConfig):
        def ready(self):
            super().ready()
            register_assignable_models(
                'my_plugin.endpoint',
                'my_plugin.appliance',
            )

**Registration adds; it never removes.** The resolved allowlist is the union of
the configured list and the registry, minus anything in `assignable_models_deny`.
An operator therefore keeps the final word without having to patch a plugin they
did not write: deny wins over both configuration and registration.

Timing matters and is not negotiable. The registry is read by
`CredentialAssignment.clean()`, so registration has to have happened before the
first form or serializer validation. `ready()` is the only hook that reliably
runs before any request; registering from a view, a signal, or module scope of
something imported lazily will appear to work in development and fail on a
worker that never imported that module.

Nothing here holds secret material, and the registry is never serialized — it is
a set of model labels, rebuilt from installed code on every process start.
"""

import logging
import re
import threading

__all__ = (
    'register_assignable_models',
    'registered_assignable_models',
    'rejected_assignable_models',
)

logger = logging.getLogger('netbox.plugins.netbox_openbao')

#: `app_label.model`, the shape a Django content-type label takes. Checked
#: before the app-registry lookup below, so a malformed string is reported as
#: malformed rather than as an unknown model.
#:
#: A leading underscore is permitted in both halves: Django only requires an app
#: label to be a valid Python identifier, so `_internal.thing` is legal and
#: rejecting it would refuse a plugin that had done nothing wrong.
_LABEL_RE = re.compile(r'^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$')

# Module-level and process-local, rebuilt on every start from whatever
# `ready()` hooks run. A lock because NetBox's app registry is not guaranteed
# to populate from a single thread under every deployment, and a set mutated
# during iteration is a far worse bug to chase than the cost of a lock taken a
# handful of times at boot.
_registered = set()
_rejected = set()
_lock = threading.Lock()


def _model_exists(label):
    """
    True if `label` names a model in the Django app registry.

    Catches the class of typo the shape check cannot: `my_plguin.endpoint` is a
    well-formed `app_label.model` string and still names nothing.

    Any exception is treated as "no". `apps.get_model()` raises `LookupError`
    for an unknown app or model, and this is called from `ready()` where an
    escaping exception would take the whole instance down — the one outcome this
    function exists to avoid.
    """
    from django.apps import apps

    app_label, _, model = label.partition('.')
    try:
        apps.get_model(app_label, model)
    except Exception:
        return False
    return True


def register_assignable_models(*labels):
    """
    Declare that `CredentialAssignment` may target these models.

    Args:
        *labels (str): ``app_label.model`` strings, matched case-insensitively
            against the assigned object's content type.

    Idempotent: registering the same label twice is not an error, which matters
    because `ready()` can run more than once under some test runners.

    **Bad entries are rejected loudly but never raise.** A label is checked two
    ways, because shape alone is not enough: `my_plguin.endpoint` is a perfectly
    well-formed string and a typo, and a registry that accepted it would leave a
    broken integration indistinguishable from one nobody configured — discovered
    much later through an assignment that will not save, with nothing pointing at
    the cause. So the label must also **name a model Django actually has**.

    That check is safe here. `apps.populate()` imports every application's models
    (its second phase) before it invokes any `AppConfig.ready()` (its third), so
    by the time a plugin registers, `apps.get_model()` can answer for any
    installed app — including one that appears later in `INSTALLED_APPS`.

    Each rejection is logged at ERROR naming the plugin-supplied value, and kept
    in `rejected_assignable_models()` so a diagnostic can surface it.

    Raising instead would be worse. This runs inside `AppConfig.ready()`, where
    an exception does not fail one integration — it takes the entire NetBox
    instance down at startup, including every unrelated plugin and the UI an
    operator would use to diagnose it. A credential-management path is not
    worth that trade.
    """
    accepted = set()
    rejected = set()

    for label in labels:
        if not isinstance(label, str) or not label.strip():
            rejected.add(repr(label))
            continue
        candidate = label.strip().lower()
        if not _LABEL_RE.match(candidate) or not _model_exists(candidate):
            rejected.add(label)
            continue
        accepted.add(candidate)

    if rejected:
        logger.error(
            'netbox-openbao ignored %d invalid assignable-model registration(s): %s. '
            'Each must be an "app_label.model" string naming a model this NetBox has '
            'installed. The models they were meant to name cannot hold credentials '
            'until the registering plugin is corrected.',
            len(rejected), ', '.join(sorted(rejected)),
        )

    if not accepted and not rejected:
        return

    with _lock:
        _registered.update(accepted)
        _rejected.update(rejected)


def registered_assignable_models():
    """Return a copy of the registered labels. Never the live set."""
    with _lock:
        return set(_registered)


def rejected_assignable_models():
    """
    Return a copy of the registrations that were refused as malformed.

    Exposed so a diagnostic — a system check, a status page, a support bundle —
    can report a broken integration rather than leaving it to be inferred from
    a startup log line nobody read.
    """
    with _lock:
        return set(_rejected)
