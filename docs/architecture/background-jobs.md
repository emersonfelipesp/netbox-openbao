# Background jobs

Five jobs, registered with NetBox's `@system_job` decorator so they are
scheduled by NetBox's own RQ worker and appear in the core **Jobs** UI. The
plugin runs no scheduler of its own.

Intervals still come from `PLUGINS_CONFIG` and are read **at import time** by
the decorators. The fields also exist on `OpenBaoSettings` as schema
foundation, but are not consumed or rescheduled yet; editing those row fields
does not affect a running or restarted worker. Keep the five interval keys in
`PLUGINS_CONFIG` until reconciliation support lands. See
[Configuration](../configuration.md#plugins_config-seed-and-fallback).

Every run clears the thread-local settings memo before it starts and again in a
`finally` block. RQ workers are long-lived and do not pass through the HTTP
middleware, so this boundary is what makes changes such as
`audit_retention_days` and `expiry_warning_days` visible between jobs, including
after a job raises.

| Job | Default interval | Contacts OpenBao? |
|---|---|---|
| [`EngineHealthJob`](#enginehealthjob) | 5 min | yes |
| [`ExpiryScanJob`](#expiryscanjob) | 24 h | **no** |
| [`CredentialVerifyJob`](#credentialverifyjob) | 24 h | yes |
| [`RotationDueJob`](#rotationduejob) | 24 h | no |
| [`AccessLogPruneJob`](#accesslogprunejob) | 7 days | no |

The worker needs the same AppRole environment as the web service. A worker
without it reports every engine as `unauthorized`, which looks like an OpenBao
problem and is not — see [Troubleshoot](../how-to/troubleshooting.md).

## `EngineHealthJob`

Probes each engine's `sys/health` and records `status`, `status_message`, and
`last_checked`. Those fields are not user-editable; this job is the only writer.

The statuses are distinguished because they demand different responses:

| Status | Means | Do |
|---|---|---|
| `healthy` | Initialized, unsealed, active | nothing |
| `standby` | Unsealed standby node | nothing; on Vault a performance standby serves reads |
| `sealed` | Reachable but sealed | unseal it |
| `unreachable` | Network or TLS failure | check the URL, the CA path, and firewalls |
| `unauthorized` | Authentication rejected | check the environment on **both** units |

`health()` is required not to raise for a reachable-but-unhealthy instance,
which is what makes `sealed` and `unreachable` distinguishable at all.

## `ExpiryScanJob`

Marks credentials past `valid_until` as `expired`, and warns at each horizon in
`expiry_warning_days` (default `[30, 14, 7, 1]`).

**This job performs zero OpenBao reads.** It answers entirely from an indexed
PostgreSQL column.

That is the direct payoff of splitting metadata from material: expiry reporting
costs one indexed query rather than one network round-trip per certificate, and
it stays correct and fast **while an engine is sealed or unreachable**. A
plugin that stored certificates opaquely would have to read every one of them
to answer the same question, and would go blind exactly when the vault is down.

→ [Report on expiry](../how-to/expiry-reporting.md)

Credentials already `expired` or `retired` are excluded from the sweep, so the
job does not rewrite the same rows every day.

## `CredentialVerifyJob`

Reads each credential's KV metadata — **metadata, never values** — to confirm
the path still resolves, and refreshes `kv_version` from the server's
`current_version`.

This is the backstop the [write-path compensator](write-path.md) depends on. If
a compensating delete ever fails, the residue shows up here rather than
lingering unnoticed:

- **missing** — the path is gone. A data-integrity finding: NetBox has a row
  whose material does not exist, so every consumer of it fails.
- **unreachable** — a transport error. Says nothing about the data.

The two are counted and logged separately for exactly that reason.

!!! warning "It cannot find the opposite case"

    This job iterates **existing credential rows**. Material under the plugin's
    prefix that NetBox no longer has a row for — the residue of a failed
    compensating delete, or of a deletion whose backend call failed — has no
    row to iterate from, so nothing here will ever surface it.

    Finding that means listing the mount for `managed_by: netbox-openbao`
    material with no matching credential. The `custom_metadata` needed to do it
    is written on every credential, and the OpenBao policy already grants
    `list` on `metadata/`, but the plugin has no job that does the walk. Until
    it does, alert on the `ORPHANED SECRET` log line — that is the only signal
    such material exists.

## `RotationDueJob`

Reports credentials past their `rotation_interval`, measured from `last_rotated`
or, failing that, `created`.

It **reports**; it does not rotate. Automatic rotation would mean the plugin
generating and deploying material without anyone deciding to, and deployment is
the half it does not own.

Retired and expired credentials are excluded.

## `AccessLogPruneJob`

Deletes `CredentialAccessLog` rows older than `audit_retention_days` (default
365).

Set this to whatever your retention policy actually is. Both directions are a
real cost: too short and the log cannot answer the question you eventually ask
of it; too long and it is an ever-growing table of who read what.
