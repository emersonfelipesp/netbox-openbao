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

from django.core.checks import Error, Warning, register

__all__ = ('check_superseded_plugins_config',)

SUPERSEDED_CONFIG = 'netbox_openbao.W001'
CHECK_FAILED = 'netbox_openbao.E001'


def _ignored_plugin_keys():
    from django.conf import settings as django_settings

    configured = (django_settings.PLUGINS_CONFIG or {}).get('netbox_openbao') or {}
    return sorted(configured)


@register()
def check_superseded_plugins_config(app_configs, **kwargs):
    """Report every ignored netbox-openbao ``PLUGINS_CONFIG`` key."""
    try:
        superseded = _ignored_plugin_keys()
    except Exception:
        return [
            Error(
                'netbox-openbao could not inspect ignored PLUGINS_CONFIG values.',
                hint='Correct PLUGINS_CONFIG so the ignored legacy keys can be reported safely.',
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
                'Remove them from configuration.py and configure the plugin through '
                'OpenBao > Configuration > Settings, the REST API, or openbao_configure.'
            ),
            id=SUPERSEDED_CONFIG,
        )
    ]
