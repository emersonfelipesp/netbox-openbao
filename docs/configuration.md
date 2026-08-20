# Configuration

## `PLUGINS_CONFIG`

```python
PLUGINS_CONFIG = {
    'netbox_openbao': {
        # Path prefix beneath the KV mount. The full logical path for a
        # credential is "<path_prefix>/credentials/<uuid>".
        #
        # Changing this after credentials exist does NOT move them: `path` is
        # stamped once at creation, on purpose, so a config change cannot
        # orphan material. Existing credentials keep their old prefix.
        'path_prefix': 'netbox',

        # Object types a credential may be assigned to. Enforced on the model,
        # so the REST API and direct ORM callers are held to the same list.
        'assignable_models': [
            'dcim.device',
            'virtualization.virtualmachine',
            'ipam.service',
        ],

        # Persist non-secret public material (public keys, certificates).
        # Disabling this gives up the zero-read expiry dashboard, which is the
        # main reason to run this plugin rather than another one.
        'store_public_material': True,

        # DRF throttle rate for the reveal endpoint, per user. Bounds the blast
        # radius of a leaked API token.
        'reveal_rate_limit': '30/hour',

        # Seconds a revealed secret should be considered valid by a consumer.
        # A policy tier's max_reveal_ttl lowers this further; it never raises it.
        'reveal_ttl': 300,

        # Fallback TTL for a cached OpenBao token when the login response
        # carries no lease duration. A real lease always wins, and the cache
        # expires at 80% of it.
        'token_cache_ttl': 3600,

        # Retention for CredentialAccessLog, enforced by AccessLogPruneJob.
        'audit_retention_days': 365,

        # Allow the plugin to generate key material server-side.
        'allow_generation': True,
        'default_ssh_key_type': 'ed25519',

        # Optional second, human-readable path written alongside the canonical
        # UUID path. Off by default: it is a consistency liability, because the
        # alias encodes facts that change.
        'path_alias_template': None,

        # Days before expiry at which ExpiryScanJob warns.
        'expiry_warning_days': [30, 14, 7, 1],

        # Background job intervals, in minutes. Read at import time by the
        # @system_job decorators, so a change needs a NetBox restart.
        'engine_health_interval': 5,
        'expiry_scan_interval': 1440,
        'credential_verify_interval': 1440,
        'rotation_due_interval': 1440,
        'access_log_prune_interval': 10080,
    },
}
```

## The default engine

There is no `default_engine` setting. The default is the `SecretEngine` whose
`is_default` flag is set, which is enforced by a database constraint (at most
one), visible and changeable in the UI, and does not need a restart. A
duplicate setting in `PLUGINS_CONFIG` would have been a second place for the
same decision to live, and therefore a place for the two to disagree.

The default engine pre-selects itself when you create a new `CredentialPolicy`.

## Environment

Auth material is **never** read from `configuration.py` or the database. Each
engine derives a prefix from its slug (`prod-core` → `NETBOX_BAO_PROD_CORE`),
and a `CredentialPolicy` may override it with `approle_env_prefix` so a tier
authenticates with its own AppRole.

| Auth method | Variables |
|---|---|
| `approle` | `<PREFIX>_ROLE_ID`, `<PREFIX>_SECRET_ID` |
| `token` | `<PREFIX>_TOKEN` (development only) |
| `kubernetes` | `<PREFIX>_K8S_ROLE`, optionally `<PREFIX>_K8S_JWT_PATH` |
| `cert` | none — the client certificate is presented by the TLS session |

Every variable also accepts a `_FILE` suffix naming a file to read instead,
which is how you mount a Docker or Kubernetes secret without exposing the value
in `/proc/<pid>/environ`.

## Policy tiers and defence in depth

A `CredentialPolicy` is not just a label. It maps onto a real OpenBao policy and
carries its own AppRole, so three independent layers must all pass before
material is returned:

1. **NetBox object permissions** — `netbox_openbao.reveal_credential`, with
   optional constraints (`{"policy__slug": "lab"}`).
2. **The policy's group gate** — `CredentialPolicy.groups`, a coarse filter
   applied in addition to, never instead of, object permissions.
3. **The OpenBao policy itself** — reached through that tier's AppRole.

The third layer is what makes the first two survivable. A NetBox-side
permission bug on `prod-core` credentials still cannot read them, because the
request is routed through the `prod-core` AppRole and OpenBao's own policy
stops it.

Give each tier a genuinely separate AppRole and deliver its SecretID
separately. Reusing one AppRole across tiers collapses layer 3 and leaves you
with a label.

## Reveal controls

- `max_reveal_ttl` (per policy) caps the plugin-wide `reveal_ttl`.
- `require_reason` (per policy) forces a justification on every reveal, recorded
  in the access log. A refused reveal is still audited — that is the entry you
  most want to see.
