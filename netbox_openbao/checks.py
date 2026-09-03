"""
Startup diagnostics, run as Django system checks.

Deliberately **not** run from `AppConfig.ready()`. These need the database, and
querying it during app initialisation earns Django's
`Accessing the database during app initialization is discouraged` warning — for
a good reason: the connection may not be usable, and on a fresh install the
table does not exist yet. System checks run after initialisation, on
`manage.py check`, `runserver`, and `migrate`, which is exactly when an operator
is in a position to act on what they say.
"""

from django.core.checks import Warning, register
from django.db.utils import DatabaseError

__all__ = ('check_superseded_plugins_config',)

SUPERSEDED_CONFIG = 'netbox_openbao.W001'
CHECK_FAILED = 'netbox_openbao.W002'


@register()
def check_superseded_plugins_config(app_configs, **kwargs):
    """
    Report `PLUGINS_CONFIG` keys that a saved settings row now overrides.

    Once a row exists it is authoritative, so a key left in `configuration.py`
    is silently ignored. Silence is the wrong behaviour: the operator can see
    the value, may well have just edited it, and nothing tells them it no longer
    decides anything. That is the most likely support question database-backed
    settings create.

    Interval keys are excluded because they genuinely are still read from the
    file — naming them would be the opposite error.
    """
    from django.conf import settings as django_settings

    try:
        from netbox_openbao.config import MODEL_BACKED_SETTINGS
        from netbox_openbao.models.settings import STATIC_INTERVAL_SETTINGS, OpenBaoSettings

        if not OpenBaoSettings.objects.exists():
            return []

        configured = (django_settings.PLUGINS_CONFIG or {}).get('netbox_openbao') or {}
        live = set(MODEL_BACKED_SETTINGS) - set(STATIC_INTERVAL_SETTINGS)
        superseded = sorted(key for key in live if key in configured)
    except DatabaseError:
        # Before `migrate`, or with the database down. Expected during bootstrap
        # and not worth reporting from a diagnostic.
        return []
    except Exception as exc:
        # Anything else is a real problem, and swallowing it would remove the
        # only signal telling an operator their PLUGINS_CONFIG values are being
        # ignored — making the precedence problem undiagnosable.
        return [
            Warning(
                f'netbox-openbao could not compare PLUGINS_CONFIG against the settings row: {exc!r}',
                hint=(
                    'Settings precedence cannot be verified, so a value in configuration.py may '
                    'be silently ignored. Report this with the traceback.'
                ),
                id=CHECK_FAILED,
            )
        ]

    if not superseded:
        return []

    return [
        Warning(
            'netbox-openbao reads these settings from the database, so their '
            f'PLUGINS_CONFIG values are ignored: {", ".join(superseded)}.',
            hint=(
                'Remove them from configuration.py to avoid confusion, or delete the '
                'OpenBao settings row to return to file-based configuration.'
            ),
            id=SUPERSEDED_CONFIG,
        )
    ]
