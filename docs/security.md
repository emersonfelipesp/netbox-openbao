# Security model

Execution-bound automation has an additional boundary described in
[Automation resolution](automation-resolution.md): the actor and named
reference come from RPC's authoritative execution, not from the authenticated
executor's request. The provider rechecks credential/assignment/target access,
pins one live version, reserves a durable one-use receipt, and requires its
correlated audit before delivering any material. Unsigned dispatch, staged
versions, repeated receipt use, and ambient outer transactions are refused.

This plugin's job is to hold the most sensitive data in a NetBox estate. The
properties below are what make that defensible, and each is enforced
structurally — by a type, a constraint, or an absent column — rather than by a
convention the next contributor has to remember.

The secrets-engine administration workspace applies the same absence-of-custody
rule to first-class KV, transit, database, SSH, TOTP, PKI, and Kubernetes journeys. Runtime
OpenAPI can prove that an exact reviewed operation exists, but it cannot invent
an executable journey, permission, risk classification, destructive
confirmation, or response class. Results are inserted as text, returned with
`Cache-Control: no-store`, cleared before selection changes, catalog reloads,
new or failed requests, unrelated operations, five-minute expiry, or `pagehide`, and never
written to a model, cache, session, task, URL, exception, or audit record. The
audit contains only actor, cluster, operation metadata, capability digest,
reason, outcome, and status. Separate permissions isolate material reads,
ordinary management, credential generation, cryptographic use, and destructive
key/version lifecycle.
Journey request fields that can contain material are cleared after successful
or failed execution, explicit clearing, five-minute expiry, and `pagehide`;
autocomplete and spellcheck are disabled for those controls.
PKI and Kubernetes material downloads are created only from the currently
rendered response after an explicit click. The browser revokes the temporary
object URL immediately; the response and file are not persisted by NetBox.

Each is covered by a test in `netbox_openbao/tests/test_security.py`. If you
change one, that test should fail; if it doesn't, the test is wrong.

## `change_openbaosettings` is admin-tier

Treat it alongside `reveal_credential` and `rotate_credential`, not as an
ordinary settings permission. Whoever holds it can:

- **widen `reveal_rate_limit`**, which is the control bounding how fast a leaked
  API token can drain the credential store — the single control most worth
  weakening if you are the attacker;
- **turn off `store_public_material`**, giving up the zero-read expiry dashboard;
- **repoint `path_prefix`**, though the model refuses that while credentials
  exist, for the reasons in the configuration guide.

Disabling optional public-material display does not disable SSH automation
identity verification. Separate live/staged public-key fingerprints and their
exact KV versions are maintained from actual material writes. Legacy display
fingerprints are never trusted for admission, and the selected bundle's actual
public fingerprint must match its frozen authorization before delivery.

Settings changes are recorded in `CredentialAccessLog` with the `configure`
action as well as in NetBox's changelog. The changelog answers *what* changed;
the access log puts it in the same timeline as the reveals it governs, which is
where an operator reconstructing an incident is already looking. The record names
the fields that changed and never their values — the access log's standing
contract is that it carries no values, and a log that sometimes carries them is
one somebody will later extend to carry the wrong one.

The audit is written from a model signal rather than the edit view, so it covers
the REST API and management commands as well as the UI. A permission this
consequential should not be auditable on only one of its surfaces.


## 1. No model field can hold secret material

`Credential` has no column that material could be written to. That is the claim
everything else rests on, because it makes whole categories of leak impossible
rather than merely unlikely:

- A changelog entry cannot contain a private key. (This matters more than it
  sounds: `ObjectChange` records are permanent, and a leaked key in one is
  effectively unrecallable.)
- An export template cannot be written to emit one.
- The REST representation has nothing secret to omit.
- A `SELECT *` by a DBA, a replica, or a backup restore surfaces nothing.

The test walks `Credential._meta.get_fields()` and fails on any name containing
`password`, `private`, `secret`, `passphrase`, or `token`.

## 2. `secret_data` is write-only

The API accepts material through a `write_only` serializer field. DRF itself
refuses to serialize it, so it cannot appear in a `GET`, a `brief=true`
response, the browsable API, an export, or an OpenAPI example — regardless of
what any view does. It is consumed by the viewset, handed to the backend, and
dropped.

## 3. `reveal` is a permission in its own right

`Credential.Meta.permissions` declares `reveal` and `rotate`, which NetBox 4.7
auto-registers as model actions. They appear as checkboxes in the standard
ObjectPermission form and accept constraints like any other action.

The consequence worth stating plainly: **a role can inventory every credential
in the estate and read none of them.** Auditors, capacity planners, and most
automation want exactly that.

Constraints work too. A permission with `{"policy__slug": "lab"}` yields a
`404` on a production credential — not a `403`, which would confirm it exists.

## 4. Reveal responses are unstorable

- `renderer_classes` is overridden to `[JSONRenderer]` on the action.
  `BrowsableAPIRenderer` would template the secret into an HTML page, and HTML
  is what caches, history, and "save page as" retain.
- `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`.
- Rate limited per user (`reveal_rate_limit`, default `30/hour`), bounding how
  fast a leaked token can drain the store.

The **UI** reveal is POST-only, so a secret is never fetched by a bookmark, a
browser prefetch, a link scanner, or a history replay.

## 5. No GraphQL surface at all

The plugin registers no `graphql_schema`, so its models are not exposed through
NetBox's GraphQL API in any form — not even metadata.

This is deliberate rather than unfinished. GraphQL queries are logged verbatim
by most gateways, and a graph API's response shape is harder to audit than a
single named REST action. If metadata-only GraphQL types are added later, a
reveal field must never be among them.

## 6. No auth material in the database

`SecretEngine` and `OpenBaoSettings` have no `role_id`, `secret_id`, or `token`
column. Material is read from the process environment at login, or from a file
the environment points at. Storing the vault's own credentials in the database
this plugin exists to keep secrets out of would defeat the entire design.

The standalone field checker and the live model test maintain a reviewed
allowlist for both `Credential` and `OpenBaoSettings`, so a newly added settings
field receives the same scrutiny as a credential column.

## 7. Per-tier AppRoles

Each `CredentialPolicy` maps to a real OpenBao policy and can carry its own
AppRole. Three independent layers must pass:

1. NetBox object permissions, with constraints.
2. The policy's group gate.
3. The OpenBao policy reached through that tier's AppRole.

**What layer 3 does and does not do.** OpenBao authenticates the *plugin*, not
the person. The backend selects the AppRole from the credential's own policy,
so if a NetBox authorization bug hands someone a `prod-core` credential, the
read is made with the `prod-core` AppRole — the identity that is *supposed* to
read that path — and OpenBao allows it.

Per-tier AppRoles are therefore **not** a re-authorization of NetBox users, and
they do not contain a NetBox permission or group-gate failure on a tier whose
AppRole this instance holds. An earlier version of this page said they did.
What they buy is blast radius, and that is worth having:

- A leaked SecretID reads only what its tier's policy grants, not the estate.
- A tier whose SecretID was never delivered to a given NetBox is unreadable
  *from* that NetBox, whatever NetBox itself decides. That is a real
  containment boundary, and it is the argument for keeping the most sensitive
  tier off a shared instance.
- OpenBao's audit device attributes each read to a specific tier rather than to
  one estate-wide identity.
- If tiers are given **separate mounts or path prefixes**, a bug that reaches
  across them fails at OpenBao. With the single shared prefix documented here,
  it does not — the paths are UUID-derived and every tier's policy covers all
  of them.

Layer 2 is enforced in `services.enforce_policy_access()`, which is the
chokepoint **every** surface goes through — the REST actions, the full-page UI
reveal, the HTMX reveal, the UI promote and discard, the edit form's material
write, and `PATCH`/`PUT` of `secret_data`. A refusal is recorded in the access
log.

It also covers **every** update of an existing credential, not only those
carrying material. `policy` is a writable field, so a user in one tier's groups
could otherwise move a credential out of a tier they are not in and into one
they are — an update with no `secret_data` — and then reveal it. Credential
paths are UUID-derived under one shared prefix, so the receiving tier's AppRole
reads the same secret; layers 2 and 3 both fall to one request that never
touches material. The gate is on the update itself rather than on the `policy`
field, because anything narrower is a denylist.

That is worth stating precisely, because none of it was always true: the check
lived in the REST viewset's authorization helper and nowhere else, so a user
belonging to none of a tier's groups was refused over the API and served the
same material by the credential page. `PATCH` of `secret_data` bypassed it in
the other direction — routed by DRF's own `update()`, it never reached the
helper at all, so the dedicated `rotate` action refused what the ordinary
update route allowed. `tests/test_policy_gate.py` asserts the gate on each
surface separately.

A `Credential`'s engine is validated to match its policy's engine. Without
that, a tier's AppRole could be scoped to one instance while the material sat
on another — the exact mismatch per-tier AppRoles exist to prevent.

## 8. Backend exceptions carry no server text

An OpenBao `403` body can enumerate policy rules. `hvac` embeds the response
body in its exception text, so letting one propagate would put the shape of
your authorization model into Sentry, into `logging`, and into DRF error
responses.

Every backend exception is caught and re-raised as a
`netbox_openbao.backends.exceptions` type built from a fixed string, with
`from None` so the original is not chained onto the traceback either. The
incoming message is inspected internally — that is how a check-and-set conflict
is told from any other `400` — and then discarded.

## 9. Every access is audited

`CredentialAccessLog` records who, when, from where, which action, and whether
it succeeded. **Never the value.**

- It is append-only and exposed read-only through the API. The same token that
  reveals a secret cannot erase the record of having done so.
- Its viewset extends `NetBoxReadOnlyModelViewSet`, **not** DRF's
  `ReadOnlyModelViewSet`. That distinction is load-bearing: NetBox applies
  object permissions in `BaseViewSet.initial()`, which is the thing that calls
  `queryset.restrict()`. A viewset outside that hierarchy is still gated on the
  model-level permission, but silently ignores every *constraint* on the
  granting ObjectPermission — so a role scoped to one tier was held to its
  constraint by the UI list view and read the whole estate's log through the
  API, including credential names, usernames, reveal reasons, and source IPs.
- It survives deletion of the credential, via name and UUID snapshots.
- Failures are audited too — a refused reveal is the entry you most want.
- It is written **synchronously**. The original design deferred it to RQ for
  latency, but an indexed INSERT costs ~1ms against an OpenBao round-trip of
  tens of ms, and an audit record a queue failure can silently drop is not an
  audit record.

OpenBao's own audit device remains authoritative for what happened at the
vault. It only ever sees an AppRole, though, so it cannot say *which NetBox
user* asked. This table is the other half; `request_id` correlates the two.

Administrative calls use a separate `OpenBaoAdministrationLog` with the same
append-only and object-constraint properties. It stores the cluster and actor
snapshots, action, reviewed method and path template, risk, status, request ID,
and capability digest. It has no request-body, response-body, diagnostic, or
authentication-material field. A mutation is refused unless its durable
preflight audit commits. If the backend accepts the mutation but the completion
audit fails, the response explicitly reports `accepted-audit-incomplete` and
must not be retried. Capability and health responses are also marked `no-store`.

Cluster bootstrap, unseal, seal, Raft peer removal, and snapshot recovery add
dedicated object permissions and exact confirmations. Initialization and
unseal material is request-scoped and never enters the administrative audit.
Snapshot transfer is raw, authenticated, bounded streaming: the plugin neither
parses nor retains the bytes, and normal restore can never escalate to force
restore. A stale cluster ID, Raft index, standby endpoint, unsupported OpenBao
version, encoded body, multipart body, or transfer beyond 512 MiB fails closed.
Session-authenticated downloads require a reason, exact confirmation, and CSRF-
protected POST; API-token GET access remains available.

Runtime OpenAPI discovery is not authorization. Documents are size-, depth-,
path-, method-, string-, and operation-bounded before normalization; every
operation remains `executable=false`. An unclassified operation has no
permission and cannot be invoked. See
[OpenBao administration plane](architecture/administration-plane.md).

## 10. Write atomicity and orphaned secrets

OpenBao writes are not transactional with PostgreSQL, and **Django has no
rollback hook** — `transaction.on_commit` fires only on commit. The explicit
`material_transaction()` owner therefore remains active through the final
database commit, including caller object and assignment persistence. It
requires actual autocommit for every new owner, rejects manually managed and
unowned ambient transactions, and detects framework-caught inner
rollback through transaction-local audit witnesses.

Only a definitively rolled-back operation is compensated, and only its exact
written versions are removed, including on new paths. A lost commit
acknowledgement is unknown: material is preserved for reconciliation, not
deleted on a guess. Cleanup failures and unknown outcomes produce fixed,
non-secret audit evidence outside rollback and operation-correlated logs.
If the database is unavailable, the log explicitly reports that the audit
could not be persisted. See the [complete transaction contract](automation-resolution.md#material-transaction-contract).

`CredentialVerifyJob` checks existing inventory rows; it is not an orphan
reconciler. There is no distributed atomic commit across PostgreSQL and
OpenBao, and a process crash can still require manual reconciliation. Retain
operation evidence and inspect the exact credential UUID and version before
retrying an unknown outcome. The `managed_by: netbox-openbao` metadata helps
locate inventory-managed paths, but no automatic orphan cleanup is implied.

Deleting a `Credential` destroys its material from a `post_delete` signal
deferred to `transaction.on_commit`, so the irreversible half happens only once
the row deletion has actually committed. Doing it the other way round meant a
later failure in the same transaction restored the row and left it pointing at
material that no longer existed — routine under bulk deletion, where one late
failure wiped the material of every credential before it.

The residue that ordering can leave is the opposite one: the row is gone and the
backend call failed, so the material stays. That case is logged as
`ORPHANED SECRET` naming the engine and path, and it is **recoverable** — the
secret is still there to be found and removed — where the other is not. Do not
read this as "deletion never leaves readable material"; read it as "deletion
never destroys material for a deletion that did not happen".

## 11. A rotation cannot break a consumer, and cannot lose the old secret

`stage` writes replacement material without putting it into service, so a
rotation has a verification step and a way back. Two properties matter:

- While a version is staged, `reveal` continues to return the **live** version.
  Resolution consults `live_kv_version` before falling back to latest.
- `discard` first commits clearing the staged pointer, then deletes **only**
  that exact staged version. A rollback or unknown commit performs no discard
  deletion. Post-commit cleanup failure leaves the live material untouched and
  reports committed cleanup-incomplete reconciliation; it never restores a
  guessed staged pointer. Compensation elsewhere in the
  write path is scoped the same way, for the same reason: destroying a whole
  path to clean up a failed rotation would take the working secret with it.

A credential written before staged rotation existed has no live pointer, which
means "serve latest". Staging pins the pointer to what is live *now* before
writing the candidate — otherwise the first stage on such a credential would
put the unverified version straight into service, which is the exact outcome
staging exists to prevent.

## 12. Check-and-set on every write

Creates use `cas=0`, which requires the path not to exist — so a create cannot
silently overwrite material written outside NetBox. Rotations use the recorded
`kv_version`, so a rotation cannot clobber a concurrent write it never saw.
Both are verified against a live OpenBao in the integration tests, because a
mock proves nothing about whether `hvac` and OpenBao agree on what `cas` means.

## 13. The reveal countdown is a convenience, not a control

Revealed material clears itself from the page after the policy-capped TTL, and
there is a "clear now" button. Both are worth having: a screen left unattended
stops displaying a secret.

Neither is a security boundary, and the UI says so rather than implying
otherwise. The material has already left the server by the time it renders;
anyone who wants to keep it can. Clearing the page does not revoke anything,
and the access-log entry stands regardless.

The fragment ships inline script, which is only safe because values reach the
DOM through `textContent` and the node is dropped with `remove()`. Building
markup from a value would let material containing HTML execute in the
operator's session — `test_fragment_uses_no_innerhtml` enforces that by
substring so it cannot creep back.

## 14. Access administration is a closed registry

Policy, identity, OIDC, and namespace requests are admitted only when a static
OpenBao 2.6.2 operation matches the current runtime method and literal path
shape. OpenAPI cannot supply executable fields or permissions. Policy and OIDC
template text is bounded and transported as inert data. Canonical identifiers
reject traversal, encoded separators, and cross-namespace paths.

Generated passwords and OIDC client credentials are request-scoped material.
Metadata response normalization strips known material keys recursively unless
the operation's static response class and the user's dedicated permission both
allow material. Destructive operations require a fresh impact digest, exact
confirmation, reason, and durable preflight audit. Mutation uncertainty is
never retried automatically.

Namespace seal creation is excluded from this metadata contract because
OpenBao can return new unseal shares. `key_shares` is also stripped
defensively. Namespace metadata replacement must be explicit, entity-merge
impact binds all normalized merge choices, and audit evidence retains validated
non-secret target identifiers for reconciliation without retaining payloads.

## 15. An operator-defined type cannot execute code or leak material

`CredentialTypeSchema` lets operators define credential types as data. Two
limits keep that from being a privilege-escalation surface:

- **`extractor` names a function from a fixed registry.** It is never an import
  path, never a dotted callable, never anything resolvable to arbitrary code. A
  JSONField that could name any importable object would be remote code
  execution wearing a schema. Validated in the model's `clean()`, so the API
  enforces it as well as the form.
- **Extraction output is filtered against `EXTRACTABLE_FIELDS`** regardless of
  what the schema declares, and the payload itself never reaches a model field.
  So a type whose properties are named after model columns still cannot get
  them written.

A stored type also may not shadow a built-in slug, since the plugin's own code
paths assume the built-in definitions.

Schema validation errors report the failing **path**, never the value —
`jsonschema`'s own message embeds the failing instance, which for a secret
payload is the material.

## 16. Form inputs are not echoed

Secret form fields use widgets with `render_value=False`. On a validation error
the browser gets an empty box, not the key the user just pasted — which would
otherwise land in the back/forward cache and in any saved HTML or screenshot.

## Deployment notes

- **Leave `tls_verify` on.** With verification off, every secret an engine
  serves is exposed to anyone who can intercept the connection.
- **Scope the OpenBao policy to the path prefix**, not the whole mount. The
  plugin should not be able to read secrets it did not write.
- **Give each tier a genuinely separate AppRole** and deliver its SecretID
  separately. Reusing one AppRole across tiers collapses layer 3.
- **Add a Sentry `before_send` scrubber** for `netbox_openbao.*` if you run
  Sentry. The plugin does not put material in exceptions, but defence in depth
  is the point.


## Broker mode

An engine set to the `broker` backend reaches OpenBao through
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
which holds the AppRole so this NetBox does not.

**It does not make "NetBox compromise ≠ secret compromise" true.** An attacker
with code execution in NetBox can still ask the broker for material, and the
broker will answer for anything NetBox is authorized to request. Deploying it
is not a reason to relax anything documented above.

What it does change:

- Stealing NetBox's **database or configuration** no longer yields credentials
  that read the vault directly. The AppRole's SecretID never exists on the
  NetBox host.
- The broker's **audit log is outside NetBox's blast radius** — a compromise
  can read, but it cannot erase the record of having read.
- Authorization gains a second, independent layer: the broker re-checks every
  path against the prefixes it was configured to serve *this instance*, before
  it uses the AppRole. A NetBox-side permission bug is not sufficient on its
  own for a path outside them.

Authorization there is **per instance, not per user**. Enforcing per-user would
mean shipping this plugin's object permissions, constraints, and group
membership to the broker — a second implementation of the authorization model
this plugin exists to keep singular. NetBox remains the authority on who may
ask.

The same scrubbing rule applies in both directions: `BrokerBackend` discards the
broker's error text rather than relaying it. The broker is written not to leak
policy, but the plugin cannot verify that from here, and a backend that forwards
a remote string has given up the guarantee this page describes.

Administrative access uses a separate pinned contract. The plugin verifies the
contract version, registry digest, complete family set, and every operation's
name, family, and framing before sending an operation. The broker receives only
the reviewed operation identifier and bounded typed arguments. It never receives
a caller-selected OpenBao origin, namespace override, service credential, raw
method, or unreviewed path. Snapshot bytes and submitted authentication material
remain request-scoped, and mutation transport or parsing uncertainty is never
retried automatically. Broker authorization remains instance-level; NetBox
object permissions remain the sole per-user authorization model.
