"""
HashiCorp Vault backend.

OpenBao is a fork of Vault, and their KV v2 and AppRole surfaces remain
compatible — which is why `hvac` drives both unmodified, and why this class is
almost empty. That is the honest outcome, not an unfinished one: inventing
overrides to look substantial would mean maintaining divergence that does not
exist.

**Differences confirmed against a live Vault dev server**, not assumed:

* `sys/health` returns a strict superset of OpenBao's payload — Vault adds
  `performance_standby`, `enterprise`, `clock_skew_ms`, `echo_duration_ms`, and
  `replication_primary_canary_age_ms`. Every field the base implementation reads
  (`initialized`, `sealed`, `standby`, `version`) is present on both, so health
  parsing needs no override.
* `performance_standby` has no OpenBao counterpart. A Vault performance standby
  serves reads while reporting `standby: true`, so treating it as a standby is
  correct, but it is worth distinguishing in the status message rather than
  leaving an operator to guess why a node is "standby" and still answering.
* Version strings are not comparable between the two projects and must never be
  used to infer capability.

KV v2 semantics — check-and-set on create and on stale versions, per-version
reads, version listing, `custom_metadata` round-trips, and version-scoped
deletes — are verified identical by running the same integration suite against
both servers. See `tests/test_backends.py`.
"""

from netbox_openbao.choices import EngineStatusChoices

from .openbao import OpenBaoBackend

__all__ = ('VaultBackend',)


class VaultBackend(OpenBaoBackend):
    """Read/write access to one KV mount on one HashiCorp Vault instance."""

    def health(self):
        """
        Report health, distinguishing a Vault performance standby.

        Everything else is inherited: the payload Vault returns is a superset
        of OpenBao's, so the base parsing already reads the right fields.
        """
        result = super().health()

        payload = result.get('raw') or {}
        if result['status'] == EngineStatusChoices.STATUS_STANDBY and payload.get('performance_standby'):
            result['message'] = 'Performance standby node; serving reads.'
        if payload.get('enterprise'):
            result['message'] = f"{result['message']} Enterprise build."

        return result
