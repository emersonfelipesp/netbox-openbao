"""
Background jobs.

Registered as NetBox system jobs, so they are scheduled by NetBox's own RQ
worker and surface in the core Jobs UI without the plugin running a scheduler
of its own.

`ExpiryScanJob` performs **zero OpenBao reads** — it answers entirely from
`valid_until` in PostgreSQL. That is the direct payoff of splitting metadata
from material: expiry reporting costs one indexed query rather than one
network round-trip per certificate.
"""

import logging
from datetime import timedelta
from functools import wraps

from django.utils import timezone
from netbox.jobs import JobRunner, system_job
from netbox.plugins import get_plugin_config

from .backends import get_backend
from .backends.exceptions import OpenBaoError
from .choices import CredentialStatusChoices, EngineStatusChoices
from .config import clear_config, get_config
from .models import Credential, CredentialAccessLog, SecretEngine

logger = logging.getLogger('netbox.plugins.netbox_openbao')

__all__ = (
    'AccessLogPruneJob',
    'CredentialVerifyJob',
    'EngineHealthJob',
    'ExpiryScanJob',
    'RotationDueJob',
)


def _static_job_interval(key, default):
    """Read an import-time interval directly from PLUGINS_CONFIG.

    The settings row contains these fields as schema foundation, but switching
    the decorators alone would make a UI/API edit appear live and then revert
    at worker restart. Interval rescheduling is deliberately a separate change.
    """
    value = get_plugin_config('netbox_openbao', key)
    return int(value or default)


def _fresh_settings_per_run(run):
    """Give each RQ job a fresh thread-local settings snapshot."""
    @wraps(run)
    def wrapped(self, *args, **kwargs):
        # RQ reuses a long-lived worker outside the HTTP middleware lifecycle.
        # Clear on both edges so one job cannot inherit another's snapshot and
        # a failing job cannot leave its own snapshot behind.
        clear_config()
        try:
            return run(self, *args, **kwargs)
        finally:
            clear_config()

    return wrapped


# `system_job` requires a plain int and reads it at import time. This module is
# imported from PluginConfig.ready(), by which point PLUGINS_CONFIG is loaded,
# so the configured interval is honoured rather than documented-and-ignored.
@system_job(interval=_static_job_interval('engine_health_interval', 5))
class EngineHealthJob(JobRunner):
    """Probe every engine's `sys/health` and record the observed status."""

    class Meta:
        name = 'OpenBao engine health'

    @_fresh_settings_per_run
    def run(self, *args, **kwargs):
        checked = 0
        for engine in SecretEngine.objects.all():
            result = get_backend(engine).health()
            SecretEngine.objects.filter(pk=engine.pk).update(
                status=result['status'],
                status_message=result['message'][:500],
                last_checked=timezone.now(),
            )
            if result['status'] != EngineStatusChoices.STATUS_HEALTHY:
                self.logger.warning(f"Engine {engine.slug}: {result['status']} — {result['message']}")
            checked += 1
        self.logger.info(f'Checked {checked} engine(s).')
        return f'Checked {checked} engine(s).'


@system_job(interval=_static_job_interval('expiry_scan_interval', 1440))
class ExpiryScanJob(JobRunner):
    """
    Flag credentials at or past their validity window.

    Reads only PostgreSQL. No engine is contacted, so this remains correct and
    fast even while an engine is sealed or unreachable.
    """

    class Meta:
        name = 'OpenBao credential expiry scan'

    @_fresh_settings_per_run
    def run(self, *args, **kwargs):
        now = timezone.now()

        expired = Credential.objects.filter(
            valid_until__isnull=False,
            valid_until__lte=now,
        ).exclude(status__in=[
            CredentialStatusChoices.STATUS_EXPIRED,
            CredentialStatusChoices.STATUS_RETIRED,
        ])
        expired_count = expired.count()
        if expired_count:
            expired.update(status=CredentialStatusChoices.STATUS_EXPIRED)
            self.logger.warning(f'Marked {expired_count} credential(s) expired.')

        warnings = []
        for days in sorted(get_config('expiry_warning_days') or [], reverse=True):
            horizon = now + timedelta(days=int(days))
            upcoming = Credential.objects.filter(
                valid_until__isnull=False,
                valid_until__gt=now,
                valid_until__lte=horizon,
            ).exclude(status=CredentialStatusChoices.STATUS_RETIRED)
            count = upcoming.count()
            if count:
                warnings.append(f'{count} expiring within {days} day(s)')
                for credential in upcoming[:50]:
                    self.logger.warning(
                        f'{credential.name} expires {credential.valid_until:%Y-%m-%d} '
                        f'(within {days} day(s))'
                    )

        summary = f'{expired_count} expired'
        if warnings:
            summary = f"{summary}; {', '.join(warnings)}"
        return summary


@system_job(interval=_static_job_interval('credential_verify_interval', 1440))
class CredentialVerifyJob(JobRunner):
    """
    Confirm every credential's path still resolves, and refresh `kv_version`.

    This is the backstop the write-path compensator depends on: if a
    compensating delete ever fails, the residue shows up here as an orphan
    rather than lingering unnoticed.
    """

    class Meta:
        name = 'OpenBao credential verification'

    @_fresh_settings_per_run
    def run(self, *args, **kwargs):
        verified = missing = errored = 0

        for credential in Credential.objects.select_related('engine', 'policy').iterator():
            backend = get_backend(credential.engine, credential.policy)
            try:
                metadata = backend.read_metadata(credential.path)
            except OpenBaoError as exc:
                # A missing path is a data-integrity finding, not a transport
                # error, so the two are counted separately.
                from .backends.exceptions import OpenBaoNotFound

                if isinstance(exc, OpenBaoNotFound):
                    missing += 1
                    self.logger.error(
                        f'Credential {credential.name} (#{credential.pk}) has no material at '
                        f'{credential.path} on engine {credential.engine.slug}.'
                    )
                else:
                    errored += 1
                    self.logger.warning(f'Could not verify {credential.name} (#{credential.pk}): {exc}')
                continue

            Credential.objects.filter(pk=credential.pk).update(
                kv_version=metadata.get('current_version') or credential.kv_version,
                last_verified=timezone.now(),
            )
            verified += 1

        return f'{verified} verified, {missing} missing, {errored} unreachable.'


@system_job(interval=_static_job_interval('rotation_due_interval', 1440))
class RotationDueJob(JobRunner):
    """Report credentials past their configured rotation interval."""

    class Meta:
        name = 'OpenBao rotation due scan'

    @_fresh_settings_per_run
    def run(self, *args, **kwargs):
        now = timezone.now()
        due = []
        candidates = Credential.objects.filter(rotation_interval__isnull=False).exclude(
            status__in=[CredentialStatusChoices.STATUS_RETIRED, CredentialStatusChoices.STATUS_EXPIRED]
        )
        for credential in candidates.iterator():
            reference = credential.last_rotated or credential.created
            if reference is None:
                continue
            if reference + timedelta(days=credential.rotation_interval) <= now:
                due.append(credential)
                self.logger.warning(
                    f'{credential.name} is due for rotation (last rotated '
                    f'{reference:%Y-%m-%d}, interval {credential.rotation_interval} day(s)).'
                )
        return f'{len(due)} credential(s) due for rotation.'


@system_job(interval=_static_job_interval('access_log_prune_interval', 10080))
class AccessLogPruneJob(JobRunner):
    """Enforce the configured audit retention window."""

    class Meta:
        name = 'OpenBao access log pruning'

    @_fresh_settings_per_run
    def run(self, *args, **kwargs):
        days = int(get_config('audit_retention_days') or 365)
        cutoff = timezone.now() - timedelta(days=days)
        deleted, _detail = CredentialAccessLog.objects.filter(timestamp__lt=cutoff).delete()
        self.logger.info(f'Pruned {deleted} access log entr(ies) older than {days} day(s).')
        return f'Pruned {deleted} entr(ies).'
