# Execution-bound automation credential resolution

The automation provider delivers one named credential bundle to an authenticated
RPC executor. It does not accept an operator identity or arbitrary credential
reference from the HTTP caller. The persisted RPC execution supplies the
initiating actor, approved target, named reference, and reason; a signed dispatch
lease binds those decisions to the executor's current dispatch.

This provider does not itself implement Proxmox operations or backend secret
sinks. Enable a consuming workflow only after its RPC executor supports this
contract and the composed workflow has been verified. Ordinary inventory and
interactive reveal behavior are unchanged.

## Prerequisites

- Install compatible `netbox-rpc` support exposing
  `netbox_rpc.credential_contract.CredentialReferenceV1` and
  `netbox_rpc.credential_authority.validate_secret_resolution_dispatch`.
  The authority must also expose `check_authorization_lifetime`,
  `check_authorization_permissions`, its verified expiry and procedure/backend/
  approver identifiers; the version floor alone does not establish these capabilities.
  An older plugin fails closed; the provider never substitutes an unsigned
  execution ID or an ordinary reveal call.
- Configure RPC dispatch signing and verification keys, the expected backend
  audience, and the backend's explicit executor service identity. Deliver keys
  through the supported RPC configuration, not procedure parameters.
- Configure the existing OpenBao engine and policy using database-backed
  settings. Direct OpenBao and optional mTLS broker mode use the same provider
  checks. No AppRole per procedure is required.
- Grant the initiating actor constrained target-view, assignment-view and
  credential-reveal permissions, the required RPC execution permissions, and
  membership in the credential policy's permitted groups. Grant the executor
  only the metadata/API access needed for dispatch. Its permissions never
  replace those of the initiating actor.
- Serve NetBox over TLS. Configure a trusted reverse proxy correctly when TLS
  terminates there; do not trust arbitrary client-supplied forwarding headers.
  The provider refuses insecure requests.

## Frozen reference contract

References are declared and frozen in RPC before dispatch, not sent by a caller
to the OpenBao action. The shared, dependency-light versioned schema is owned
by `netbox-rpc`:

```json
{
  "schema_version": 1,
  "provider": "netbox-openbao",
  "assignment_id": 123,
  "target": {"object_type": "dcim.device", "object_id": 456},
  "purpose": "login",
  "fields": ["private_key", "passphrase"],
  "version": {"policy": "live"}
}
```

Specify exactly one integer `assignment_id` or canonical `credential_uuid`.
A UUID does not bypass assignment checks: it must identify exactly one enabled,
visible assignment for the exact target and purpose. Unknown properties,
arbitrary vault locators, caller identities, duplicate fields, and invalid IDs
are rejected by the shared contract. The provider checks every field against
the credential type's schema. An unconstrained `generic-kv` credential is not an
automation field allowlist; define an explicit custom schema when necessary.

The existing purposes are `login`, `enable`, `console`, `oob`, `api`, `agent`,
and `backup`. Typical assignments use `login` with `ssh-password` or
`ssh-keypair` for endpoint/node SSH; `api` with `api-token` for endpoint API,
PBS/PDM or Firecracker access; and `agent` with `api-token` for an agent.
The exact target distinguishes those assignments. Integrating plugins must
register their target models, and the operator's assignable-model deny list
continues to take precedence. Public keys, fingerprints and SSH usernames are
inventory metadata; they are not implicitly returned as secret fields.

Before approval, RPC calls the provider's metadata-only
`capture_reference_identity()` helper. It checks the initiating actor's access
without reading the vault and freezes the credential UUID, exact assignment,
target/purpose, username, fingerprint, credential type, policy and engine, plus
digests of the schema and non-secret backend selectors. The provider checks
that snapshot again under locks before reservation and before the read. An
unchanged assignment ID therefore cannot silently substitute a different
credential. The digests describe configuration, never secret values.

For SSH keys, `fingerprint` in that frozen identity is the verified **live**
key fingerprint, not the optional display fingerprint. The provider maintains
`live_key_fingerprint` and `live_key_version`, plus separate staged equivalents,
from the actual key supplied to a normal material write. These contain only
public-key fingerprints and version numbers, never private-key hashes. They
remain maintained when `store_public_material=False`; full public keys are
still omitted under that setting. Staging does not change the live identity,
discard clears only staged identity, and promotion moves the staged identity
and its version into the live binding.

Legacy keys with no verified live binding fail metadata-only admission
explicitly. Neither a nonempty old display fingerprint nor a matching-looking
version is a backfill source. An operator must establish the binding through
the normal authorized material-write workflow, supplying the actual key; this
feature does not silently read or rotate legacy secrets during admission or
migration. After its one explicit version read, the bundle service derives the
selected private key's public fingerprint and compares it with the frozen
identity before returning any requested field. Backend key substitution is
therefore refused even if inventory metadata is stale or has been altered.

## Resolution API

```text
POST /api/plugins/openbao/credentials/resolve-automation/
```

```json
{
  "schema_version": 1,
  "execution_id": 789,
  "step_id": "",
  "reference_name": "transport",
  "dispatch_lease": {}
}
```

The lease placeholder must contain the actual RPC-issued signed envelope.
An empty `step_id` denotes a standalone execution. A named step must be
recognized by the compatible RPC authority; the provider does not invent an
intent step when it is missing.

Successful responses contain `schema_version`, `credential_uuid`,
`assignment_id`, `resolved_version`, `ttl`, `secret: true`, `fields`, and
`access_log_id`. Only the requested fields are present. An absent optional
field, such as an unencrypted key's passphrase, is omitted. An absent required
field or a malformed value is refused. Each field is limited to 256 KiB.

The response is JSON-only and carries `Cache-Control: no-store`,
`Pragma: no-cache`, and `Expires: 0`. The executor must keep values out of
parameters, execution events, results, logs, URLs and shell fragments. SSH
passwords and keys belong in the transport credential channel; other material
requires an explicitly supported stdin, file or API-authentication sink.

## Version selection, rotation and retries

`live` selects an explicit `live_kv_version` and records it before reading the
backend. A missing live pointer is refused, not interpreted as latest. A
staged candidate is never served by automation, including when explicitly
requested. All requested fields come from one backend read at the same version.

`{"policy": "pinned", "number": 7}` is an approval precondition: version 7
must still be the current live version. It is not a permission to reveal
historical material. Rotation invalidates the pinned precondition and requires
a new authorization. With `live`, password or token material may rotate while
its approved identity remains unchanged. A changed username, key fingerprint,
assignment, schema, policy or backend selector requires a new authorization.
The executor uses the approved transport identity rather than silently
replacing it with current inventory metadata.

Before any read, the provider commits a non-secret receipt keyed by execution,
dispatch nonce digest, step and reference name. Every repeat is refused,
including after an outage, timeout, audit failure or lost HTTP response. Secret
values are never cached for retry. A newly authorized dispatch is required;
operators must reconcile any downstream operation with an unknown outcome
before issuing one. Provider receipts do not consume the backend's separate
one-time dispatch nonce.

The service requires an autocommit caller. Do not wrap the resolution API in
`ATOMIC_REQUESTS` or call it from an enclosing database transaction: that could
erase its durable receipt after material had already been read. Such calls
are rejected. Assignment, permission, policy, validity and version checks are
repeated immediately before the read. Disabling or removing an assignment,
retiring a credential, or revoking the actor prevents future reveals; it cannot
recall bytes already delivered to an executor.

Authorization is evaluated after all policy/engine/credential/assignment/schema lock
waits. Locks are acquired in that order, sorting IDs within each model when a
material update moves between policies. Supported material writes, staging,
promotion and discard follow the same policy/engine/credential ordering and
refresh observed version state after waiting. A PostgreSQL trigger takes the
parent policy lock for policy-group relationship insertions, updates and
deletions, including direct through-model writes and cascading removals. Thus
a committed group replacement or a policy slug change cannot be missed by a
delivery that waited behind it. Relationship changes and their locks roll back
with their database transaction; they do not create independent lock state.

Custom schema rows are locked after the assignment and before final permission,
validity or field checks. The RPC-verified dispatch expiry is checked again
after provider waits, immediately before the read and after the backend returns, using its immutable
authorization result without acquiring new RPC locks. RPC actor rows use
`FOR NO KEY UPDATE` so material audit foreign keys cannot create an inverted
lock cycle; catalog parent rows retain full insertion-blocking locks.
The approved schema digest includes the extractor selector.
RPC permissions are queried freshly after provider waits, immediately before
the read and after the backend returns. This final permission helper does not
reacquire authority locks or resolve a backend. It rechecks exact initiating
actor execution scope, exact approver scope and procedure/backend/target view
access without trusting previously cached user permissions. The provider also
repeats its own fresh restricted-access and frozen-identity checks after the
read while retaining its graph locks. Revocation during I/O denies disclosure;
it does not undo the vault access already performed, and its receipt stays spent.
An approved SSH fingerprint always requires verification of the returned
private key, even if an internal callback changes that selector. Material
persistence discards stale related-object caches before selecting the backend.

## Material transaction contract

`netbox_openbao.material_transactions.MATERIAL_TRANSACTION_CONTRACT_VERSION`
is `1`. Its `material_transaction()` context must begin before application or
framework atomic blocks. It owns the complete database commit for caller-owned
objects, material writes, assignment changes and final `save_m2m()`. Standalone
material services enter this owner automatically; nested services join only an
existing explicit owner. An arbitrary ambient application transaction is
refused before external writes. A new owner requires actual database autocommit,
including when a caller disabled autocommit without entering `atomic()`.
Nested participants may join an existing declared owner, but cannot create a
new owner inside a manually managed transaction. Credential UI and REST create/update entry
points preserve NetBox's framework methods and wrap them with this owner.

For a multi-credential operation, lock the caller's owner row first, resolve
all its current credential references, then call
`synchronization.lock_material_subjects(subjects, additional_policy_ids=...)`
with the complete source/destination set before the first write. The helper
locks sorted policy IDs, engine IDs and credential IDs, refuses relationship
drift, and returns current locked credentials. Recheck the owner's reference
and authentication selectors before proceeding. The graph freezes after its
initial acquisition: additional existing participants cannot be introduced
even before the first write. New credentials created
inside the owner are invisible to concurrent transactions until commit.
Material callbacks must declare their subject or destination policy before
they persist a row; an unscoped callback is refused before persistence.

The owner registers every backend attempt and exact returned version. Audit
witnesses detect an inner savepoint rollback even if the framework catches its
exception. A caught failed service poisons the complete owner. A definitive
database rollback, including a deferred foreign-key rejection at final commit,
compensates only the versions this operation successfully wrote. This rule
also applies to new paths: another writer may already have advanced them.
Pre-existing and concurrently written versions are never selected for cleanup.

A connection failure during commit is an unknown outcome, not proof of
rollback. No versions are deleted automatically in that case. Failed cleanup
and unknown outcomes create non-secret reconciliation audit records outside
the failed transaction, keyed by operation UUID, credential UUID and exact
version when known. Fixed operational logs carry the operation UUID, never
material or exception text. If the database cannot accept the reconciliation
record, the fixed log explicitly reports that evidence failure. There is no
automatic orphan reconciler or distributed atomic commit guarantee across a
process crash. Operators must reconcile before retrying an unknown outcome.

Discard clears the staged pointer and staged identity in the owned database
transaction. Only after a confirmed commit does it delete that exact previously
staged version. The cleanup method independently checks the commit witness;
normal context exit alone does not authorize deletion. Rollback or an unknown
commit never triggers discard deletion.
If post-commit cleanup fails, the live pointer and material stay intact, the
staged pointer stays cleared, and the operation returns an explicit committed
cleanup-incomplete error with reconciliation evidence. It does not restore a
guessed pointer or claim that a committed inventory change rolled back.
An owner's first commit callback witnesses confirmed commit, so an exception
from a later callback cannot be mistaken for a PostgreSQL rollback rejection.

Consumers must check this capability in the actual reviewed installed package;
an older `store_credential` function alone is not the transaction contract.
Clearing an owner reference must not delete shared credential material.

### Compatible-consumer release gate

This changes an existing material-write service boundary. Do not upgrade a
deployment that still calls the old service from an unowned outer transaction,
or adds existing participants after the first write. The provider fails closed;
there is no legacy bypass or fallback to local secret storage.

| Consumer | Required integration before release |
| --- | --- |
| Credential UI and REST create/update | The included wrappers own the unchanged framework methods; metadata batches predeclare all source and destination policies. Bulk material updates remain unsupported. |
| Built-in netbox-secrets importer | The included importer owns each secret and its assignment separately, preserving per-secret failure isolation and resumability. |
| Proxbox endpoint forms and serializers | A compatible adapter must own the endpoint, all material writes and assignments in one predeclared scope. Its legacy nested service calls are not compatible. |
| Optional private NMS credential bridge | A compatible adapter must include its DeviceCredential/DeviceService persistence and all OpenBao participants in the same predeclared scope before the first write. The legacy bridge has not been verified against this contract. |
| Other plugins and custom callers of material services | Inventory each caller and require the version-one owner and participant contract before enabling writes. Metadata-only paths that do not call a material service do not require it. |

The Proxbox and private NMS adapters and their composed version-matrix tests are
release-blocking prerequisites for deployments using those consumers. Existing
published dependency minimums are not evidence of compatibility. Keep writes
disabled until the actual reviewed consumer packages and their common NetBox
version have passed composed tests. This provider unit does not supply those
downstream storage adapters.

## Audit and maintenance

Access logs record initiating actor and executor separately, execution and
optional intent identifiers, step, reference name, purpose, assignment,
resolved version, correlation and nonce digest. They do not contain material,
request bodies, backend paths or backend exception text. Existing object-scoped
read-only access-log permissions still apply. A required audit write must
succeed before the provider reads or delivers material.

Internal receipts have no CRUD API and persist independently of ordinary audit
retention. Do not delete them while their execution can be dispatched or
replayed. Archiving a retired execution must retain the non-secret receipt
identity for at least the dispatch-validity and incident-retention period.
Provider resolution does not delete credentials or vault versions. Explicit
material mutation rollback uses the version-scoped compensation described above.

Migration 0009 is an additive schema expansion. New non-null columns on
existing assignment and audit tables have persistent database defaults, so an
older binary can still insert its original column set after a binary rollback.
Keep the expanded schema during that rollback: reversing the migration drops
provider receipts and correlation fields and therefore destroys replay and
audit evidence. Disable automation dispatch before changing either plugin's
version; re-enable it only after compatibility checks pass.

Migration 0010 adds the non-secret key bindings and policy-relationship trigger.
New fingerprint columns also have persistent empty database defaults for
old-binary inserts. Empty means unverified, not a trusted legacy identity. The
migration performs no vault reads or backfill. Its reverse operation removes
only its named trigger/function and added columns; disable automation before
any schema rollback, which discards verified identity state. A binary rollback
with the expanded schema retained is the supported recovery path.

Direct and broker integrations must be exercised against a real OpenBao KV v2
instance. Run the authorization suite on a real NetBox database, then verify
staged/live versions, CAS conflicts, deletion, broker policy denial, outage and
retry refusal with the repository's disposable development harness. Passing
fake-backend tests alone is not composed integration evidence.
