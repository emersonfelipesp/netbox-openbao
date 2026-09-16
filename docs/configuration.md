# Configuration

## Database-backed settings

Runtime configuration is stored in the singleton `OpenBaoSettings` row and is
available through `/api/plugins/openbao/settings/`. A saved row is
authoritative, and non-interval changes are visible to the next request without
restarting NetBox.

Create the row on an installation that does not have one yet:

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/settings/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"path_prefix": "netbox", "reveal_rate_limit": "30/hour"}'
```

Read the collection to discover its ID, then update it with `PATCH`:

```bash
curl https://netbox.example.net/api/plugins/openbao/settings/ \
  -H "Authorization: Bearer $TOKEN"

curl -X PATCH https://netbox.example.net/api/plugins/openbao/settings/1/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"expiry_warning_days": [60, 30, 14, 7, 1]}'
```

The model has a fixed, unique `singleton_key`, so the database enforces at
most one settings row. It contains configuration only: OpenBao RoleIDs,
SecretIDs, and tokens remain outside the database.

The settings row can be deleted only while no credentials exist. Once a
credential exists, deleting the row could restore a different fallback
`path_prefix`, producing the same partial outage as changing the prefix: the
AppRole policy still covers the old path while new writes target another one.
Credential creation and settings writes select the singleton for update before
re-checking the committed credential state. A transaction-level advisory lock
covers the fresh-installation case where no settings row exists to lock yet.
If credentials were already created from a `PLUGINS_CONFIG` fallback, the first
settings row must use the prefix stamped into those credential paths. Changing
the fallback first does not make the stored paths move with it.

The read order is:

```
per-request memo → settings row → PLUGINS_CONFIG → caller default
```

The missing-row result is memoised, but a read never creates a row. This keeps
`PLUGINS_CONFIG` usable as the fallback for a fresh installation and for
deployment-specific overrides. The whole row, including the no-row sentinel,
is held only for the current request or job run. Five `get_config()` calls cost
one indexed single-row query, not five.

There is deliberately no shared Django cache layer. A shared fill could race a
committed invalidation and restore stale security controls indefinitely, and a
cache outage would otherwise make every settings read fail. Avoiding those two
failure modes costs one database query per request on a page that already
issues dozens. It also means the plugin has no settings-cache backend or TTL to
configure.

Saving or deleting the row clears the writing thread's memo immediately. Reads
after a write remain unmemoised until the surrounding transaction ends because
Django provides no rollback hook that could discard an uncommitted snapshot. A
rollback therefore cannot leave its discarded value authoritative for the rest
of the request or job.

Use API or form saves for automatic settings validation. As with every Django
model, a direct instance `save()` does not call `full_clean()`; an ORM caller
must call it explicitly, although the instance save still clears the current
thread's memo. `QuerySet.update()`, `bulk_update()`, and raw SQL bypass both
`full_clean()` and save signals. An in-flight request may therefore keep its
earlier snapshot, but every later request performs its own database lookup.
Nothing can repair an invalid value that bypassed validation.

The per-request memo is load-bearing rather than an optimisation. The
credentials panel is registered globally, so this read path runs on **every
object detail page in NetBox**, as well as on every assignment save and every
reveal. A lookup per key would put several extra queries on every page in the
estate.

The thread-local memo is discarded after each response by a middleware the
plugin declares itself, so it needs nothing from you. Each background job also
clears the memo at the start and in a `finally` block, because an RQ worker is
long-lived and does not pass through HTTP middleware. Without these lifecycle
boundaries, a worker thread would retain the first settings snapshot it read.

### From the CLI

The settings are an ordinary plugin API endpoint, so `nbx` reaches them with no
support of its own:

```bash
nbx call GET /api/plugins/openbao/settings/ --json
nbx call PATCH /api/plugins/openbao/settings/1/ \
  --body-json '{"reveal_ttl": 600}' --confirm --json
```

## `PLUGINS_CONFIG` seed and fallback

`PLUGINS_CONFIG` remains supported. During upgrade, the data migration copies
effective non-default values into the settings row. If no row exists, reads
continue to resolve from `PLUGINS_CONFIG` and then their hard defaults.
Set-like model labels are stripped, lowercased, deduplicated, and sorted during
the migration, matching runtime semantics. An unsafe legacy `path_prefix` is
not copied into a row the runtime model rejects, and credential path derivation
fails closed until that fallback is corrected.

The five job intervals are transitional exceptions. Their fields exist on the
settings model, but the `@system_job` decorators still read `PLUGINS_CONFIG` at
module import. Editing the row's interval fields does not reschedule jobs yet;
keep configuring those five keys below until interval reconciliation lands.

```python
PLUGINS_CONFIG = {
    'netbox_openbao': {
        # Path prefix beneath the KV mount. The full logical path for a
        # credential is "<path_prefix>/credentials/<uuid>".
        #
        # This must be a non-empty relative path without leading or trailing
        # slashes, empty or traversal segments, or whitespace. It can be
        # changed, or the settings row deleted, only while no credentials
        # exist. The AppRole's OpenBao policy is scoped to
        # secret/data/<path_prefix>/credentials/*; changing the prefix later
        # would make new writes fail with a permission error while every
        # existing credential continued to work at its stamped path.
        'path_prefix': 'netbox',

        # Object types a credential may be assigned to. Enforced on the model,
        # so the REST API and direct ORM callers are held to the same list.
        #
        # An installed plugin can add its own models to this without you
        # editing anything — see "Assignable object types" below. The resolved
        # allowlist is this list plus whatever plugins registered, minus
        # `assignable_models_deny`.
        'assignable_models': [
            'dcim.device',
            'virtualization.virtualmachine',
            'ipam.service',
        ],

        # Object types to refuse even when an installed plugin registered them.
        # Registration comes from code rather than from you, so this is what
        # keeps the allowlist yours: deny wins over both the list above and the
        # registry.
        'assignable_models_deny': [],

        # Persist non-secret public material (public keys, certificates).
        # Disabling this gives up the zero-read expiry dashboard, which is the
        # main reason to run this plugin rather than another one.
        'store_public_material': True,
        # Verified live/staged SSH public fingerprints and KV version bindings
        # remain mandatory for automation identity, even when this is False.
        # Full public keys and optional certificate display metadata remain opt-in.

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
        #
        # This setting is not model-backed. It is currently unused by the
        # package and remains here pending a separate removal-or-implementation
        # decision.
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
engine and administrative cluster derives a prefix from its slug
(`prod-core` → `NETBOX_BAO_PROD_CORE`),
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

## Administrative clusters

Create a cluster under **Plugins → OpenBao → Administration → Clusters** or at
`POST /api/plugins/openbao/clusters/`. The record contains the API URL,
namespace, backend, authentication method, TLS policy, and optional NetBox
device hosting OpenBao. It never contains credentials.

Existing installations receive one cluster per `SecretEngine` during migration
`0011`. The engine's connection fields remain authoritative for credential
traffic during the compatibility period, while administration uses the linked
cluster. Do not deliberately diverge the two connections; later engine
lifecycle work will complete the consolidation.

Keep `tls_verify` enabled. For an internal CA, set `ca_cert_path` to its bundle
instead of disabling verification. Broker clusters may report health but reject
capability discovery until the broker implements the bounded administration
contract; the plugin does not bypass the broker by connecting directly.

The **Administration** tab provides guarded cluster state, initialization,
unseal, seal, Raft peer, and snapshot controls for OpenBao 2.6.2 through the
reviewed 2.6.x line. Assign each dedicated object permission separately; broad
cluster view or discovery access does not grant a mutation. Keep the configured
API URL on the management network and point it at the active node or a trusted
OpenBao-aware load balancer. Redirects to a reported leader are intentionally
not followed. Complete operational procedures are in the
[cluster administration runbook](how-to/administer-openbao-cluster.md).

The **Policies and identity** tab exposes the reviewed policy, identity, OIDC,
and namespace registry. Runtime OpenAPI may prove that a static operation is
present, but it cannot add a path, request field, permission, or response
classification. Grant the dedicated cluster object permissions separately and
scope the OpenBao service identity to the same fixed paths. Namespace
administration is relative to `OpenBaoCluster.namespace`; an operation cannot
override that boundary. See the [access administration
runbook](how-to/administer-openbao-access.md).

## Policy tiers and defence in depth

A `CredentialPolicy` is not just a label. It maps onto a real OpenBao policy and
carries its own AppRole, so three independent layers must all pass before
material is returned:

1. **NetBox object permissions** — `netbox_openbao.reveal_credential`, with
   optional constraints (`{"policy__slug": "lab"}`).
2. **The policy's group gate** — `CredentialPolicy.groups`, a coarse filter
   applied in addition to, never instead of, object permissions. Enforced in
   `services.enforce_policy_access()`, so it covers every surface that reaches
   a credential rather than only the REST API, and a refusal is audited. An
   empty group list means the tier does not use the gate.
3. **The OpenBao policy itself** — reached through that tier's AppRole.

The third layer bounds **blast radius**, not authorization. OpenBao
authenticates the plugin, not the person, and the backend picks the AppRole
from the credential's own policy — so a NetBox bug that hands someone a
`prod-core` credential makes the read with the `prod-core` AppRole, which is
authorized for that path. Layer 3 does not re-check the user.

What it does buy: a leaked SecretID reads only its own tier, a tier whose
SecretID was never delivered to a NetBox is unreadable from it at all, and
OpenBao's audit attributes each read to a specific tier. Give tiers separate
mounts if you want path-level containment as well — see
[the security model](security.md#7-per-tier-approles).

Give each tier a genuinely separate AppRole and deliver its SecretID
separately. Reusing one AppRole across tiers collapses layer 3 and leaves you
with a label.

## Reveal controls

- `max_reveal_ttl` (per policy) caps the plugin-wide `reveal_ttl`.
- `require_reason` (per policy) forces a justification on every reveal, recorded
  in the access log. A refused reveal is still audited — that is the entry you
  most want to see.

## Assignable object types

A `CredentialAssignment` may only target a content type the deployment has
opted into. Anything else is refused in `CredentialAssignment.clean()`, so the
form, the REST API, and any direct ORM caller are held to the same list.

The resolved allowlist is:

```
(assignable_models  ∪  what installed plugins registered)  −  assignable_models_deny
```

### For operators

`assignable_models` is yours and needs no explanation.
`assignable_models_deny` subtracts from the result, so you can refuse a
specific model an installed plugin registered without patching a plugin you did
not write. **Deny wins over both.**

!!! warning "What this allowlist is, and is not"

    It is **not a security boundary against an installed plugin.** A NetBox
    plugin runs in the same process with full ORM access — it can already read
    every `Credential` row and call the service layer directly, allowlist or no
    allowlist. Registration widens a list that plugin code could bypass anyway,
    so it grants nothing it did not already have.

    What the allowlist actually bounds is *accident*: a mistyped content type in
    an API call, a bulk import pointed at the wrong model, an operator attaching
    a credential to something nobody intended to be a credential holder. That is
    a real and useful thing to bound, and it is the whole of it.

    The deny list is therefore an **operational** control, not a containment
    one: it is how you turn off an integration whose behaviour you do not want,
    or narrow one you only partly want. It is not a defence against a plugin you
    do not trust. Do not install one.

The validation error names the resolved list, which is the fastest way to see
what a running instance actually permits:

> Credentials may not be assigned to `dcim.site`. Permitted types:
> `dcim.device`, `ipam.service`, `virtualization.virtualmachine`.

### For plugin authors

If your plugin stores its secrets here, register its credential-holding models
from `AppConfig.ready()`:

```python
from netbox.plugins import PluginConfig
from netbox_openbao.registry import register_assignable_models


class MyPluginConfig(PluginConfig):
    name = 'my_plugin'
    # ...

    def ready(self):
        super().ready()
        register_assignable_models(
            'my_plugin.endpoint',
            'my_plugin.appliance',
        )
```

Labels are `app_label.model`, matched case-insensitively, and registration is
idempotent.

Three things are worth stating plainly:

- **`ready()` is the only place this works.** The registry is read by
  `CredentialAssignment.clean()`, so registration has to have happened before
  the first form or serializer validation. Registering from a view, a signal,
  or the module scope of something imported lazily will appear to work in
  development and fail on a worker that never imported that module.
- **Registration adds; it never removes.** You cannot un-register, and you
  cannot override an operator's `assignable_models_deny`.
- **Import `netbox_openbao.registry` defensively if your plugin treats this
  integration as optional.** Wrap the import in `try: ... except ImportError:`
  so your plugin still loads where `netbox-openbao` is not installed.

A bad label is **rejected and logged at ERROR**, naming the value, and is
retrievable from `registry.rejected_assignable_models()`. "Bad" is checked two
ways, because shape alone is not enough — `dcim.rakc` is a perfectly well-formed
`app_label.model` string and names nothing:

1. it must match `app_label.model`;
2. it must name a model this NetBox actually has.

It does not raise. This code runs inside `AppConfig.ready()`, where an exception
does not fail one integration but takes the whole NetBox instance down at
startup, including the UI an operator would use to diagnose it. Check the log
after adding a registration — a rejected label means the model silently cannot
hold credentials.

!!! note "Panel registration does not depend on `PLUGINS` order"

    The credentials panel on object detail pages is registered globally and
    filters on the allowlist at render time. That is deliberate: NetBox reads a
    template extension's `models` attribute exactly once, during the owning
    plugin's `ready()`, so a panel scoped from a snapshot of the allowlist would
    miss any model registered by a plugin that initialized later — giving the
    same configuration a different UI depending on the order of `PLUGINS`, with
    no error anywhere. Your models get their panel regardless of where you sit
    in that list.

Prefer a core NetBox content type where one already models the thing. If your
plugin's object has a foreign key to `dcim.Device` or
`virtualization.VirtualMachine`, assign the credential to *that* — both are in
the default allowlist, so the integration needs no configuration at all, and
the Ansible collection can resolve it by device or VM name on day one.
