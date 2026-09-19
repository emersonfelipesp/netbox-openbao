# netbox-openbao — Agent Guide

A NetBox plugin that keeps **secret material in OpenBao** while **NetBox owns
credential inventory and relationships**.

Repository: <https://github.com/emersonfelipesp/netbox-openbao>.

## Release and deployment contract

Production is package-first. NMS target 9 publishes the exact wheel, sdist,
and schema-1 `netbox-openbao-release-manifest`; target 20 deploys reviewed
`develop` to staging; target 21 defaults to the exact package and retains an
explicit canonical-main override through a claimed, signed proof-v3 request.
RC publication is limited to direct `v*rc*` pushes and
TestPyPI. Final PyPI publication is limited to a published GitHub Release.
Never put secret material in package bytes, manifests, proofs, logs, receipts,
release notes, or rollback records. Follow `docs/release-deployment.md`.

## Hard constraints

**NetBox 4.6 and 4.7** (`min_version = "4.6.0"`,
`max_version = "4.7.99"`) and **OpenBao 2.6.x**.

This used to read "4.7 only — do not add 4.6 compatibility shims", on the
stated grounds that `ipam.Service` had changed in two ways. Only one of them
had. The parent GenericForeignKey was already present in 4.6; just the port
representation differs. Checked by importing every name the plugin uses under
both releases rather than by reading release notes: **61 of 64 NetBox imports
and 29 of 30 `netbox.ui` attributes are identical**, including the whole
declarative panel framework, `netbox.api.gfk_fields`, `netbox.jobs` and
`netbox.forms`, all of which the old note assumed were 4.7-only.

The floor matters operationally, which is why it was worth rechecking: the
estate still runs 4.6.5 while `netbox-nms` supports 4.5.8–4.7.99. Keeping the
4.6 floor preserves a common installable version today without preventing the
exact 4.7 beta source gate.

**Every runtime 4.6/4.7 difference lives in `netbox_openbao/compat.py`** — read
its docstring before adding a runtime version check anywhere else, and add it
there if you must add one. Migration-state differences are the exception: keep
them self-contained in the migration graph and derive inherited field state
from the running NetBox core, as migrations `0006` and `0014` do. Never import
runtime compatibility helpers from a migration. See
[Verified 4.7 facts](#verified-47-facts).

**Python 3.12+, PostgreSQL 15+ with `ltree`, Redis 6+.**

**OpenBao administration is cluster-scoped and fail-closed.**
`OpenBaoCluster` owns the administrative endpoint; `SecretEngine` owns a
credential-storage mount during the compatibility migration. Runtime OpenAPI
discovery is bounded by `administration/schema.py` and every discovered
operation remains non-executable until a reviewed registry entry supplies its
permission, response class, risk controls, and tests. Unknown operations never
become a generic proxy. Administrative responses are `no-store`, and a mutation
preflight audit failure blocks backend access. A completion-audit failure after
backend acceptance returns explicit `accepted-audit-incomplete` state. Keep the OpenBao 2.6.2 parity manifest and
`docs/architecture/administration-plane.md` synchronized with each capability
change.

**Cluster custody and Raft snapshots remain request-scoped.** Initialization,
unseal, seal, peer removal, snapshot download, restore, and force restore use
their dedicated `OpenBaoCluster` permissions and fixed API paths. Never add a
model, session, cache, task, audit, exception, screenshot, or multipart-upload
path for keys, root tokens, recovery material, unseal shares, or snapshot
bytes. Snapshot transfer stays raw authenticated streaming, bounded to 512 MiB,
with confirmed CSRF-protected POST for session downloads and normal and force
restore separated. Refuse stale Raft state, a standby
endpoint, unsupported OpenBao versions, redirects, retries after an unknown
outcome, and any mutation whose preflight audit did not commit. The bootstrap,
HA, recovery, and incident procedures are in
`docs/how-to/administer-openbao-cluster.md`.

**Raft join and final OpenBao UI parity remain request-scoped.** Raft join is
allowed only on an uninitialized node through the fixed
`/sys/storage/raft/join` contract and dedicated `join_raft_openbaocluster`
permission. Never persist or audit the leader CA, client certificate, or client
private key. Lease, wrapping, hashing, random-data, token-lookup, and UI-header
operations come only from `administration/finalization.py` and the pinned
`openbao-final-v2.6.2.json` fixture. Runtime OpenAPI may prove a reviewed route
exists but may not add one. Keep material no-store and browser-memory-only;
force revoke and UI configuration changes require dedicated permissions, a
fresh impact digest, a reason, and exact confirmation. Broker mode must verify
the pinned version and registry digest before forwarding the same reviewed
contract, and it must never fall back to direct OpenBao access. Procedures are in
`docs/how-to/administer-openbao-leases-tools.md`.

**Authentication and MFA administration never creates an OpenBao browser
session in NetBox.** The executable surface is the static OpenBao 2.6.2
registry in `administration/authentication.py`; runtime OpenAPI may prove that
a named reviewed operation exists but may never supply a path, field,
permission, or response parser. Keep passwords, JWTs, tokens, RoleIDs,
SecretIDs, provider credentials, MFA values, OIDC state/nonces, and TOTP setup
material out of models, Django sessions, caches, tasks, URLs, logs, exceptions,
and browser storage. Direct OIDC callbacks terminate at OpenBao, polling uses a
short-lived signed user/cluster/mount/state/nonce envelope, and material is
returned once with `no-store`. Submitted tokens are request-scoped and never
replace the cluster service identity. TOTP self-reset must derive the entity
from token lookup and must never accept a caller-selected entity. Mutation
transport or parsing uncertainty returns an explicit unknown outcome and must
never be retried automatically. Destructive auth/MFA/token operations
require their dedicated object permissions, reasons, and exact confirmations.
See `docs/how-to/administer-openbao-authentication.md`.

**Policy, identity, OIDC, and namespace administration is a closed static
registry.** Runtime OpenAPI may prove that a reviewed OpenBao 2.6.2 method and
literal path shape exists, but it may never supply an executable path, field,
permission, risk class, or response parser. Keep policy and template documents
as inert bounded data. Preserve canonical UUID, accessor, name, and namespace
identifiers; namespace operations accept one child segment relative to the
cluster's fixed namespace header and never accept a caller override. Generated
passwords and OIDC client credentials remain request-scoped material with
dedicated object permissions and `no-store`; metadata reads strip material
recursively. Delete, merge, key rotation, and namespace removal require fresh
impact previews, exact confirmations, reasons, and durable preflight audits.
Mutation uncertainty must never be retried automatically. See
`docs/how-to/administer-openbao-access.md`.

**Secrets-engine administration uses a classified, mount-scoped contract.**
First-class KV v1/v2, transit, database, SSH, TOTP, PKI, and Kubernetes journeys are defined in
`administration/engine_journeys.py`. A journey is executable only when its
static operation ID, method, path template, engine type, KV version, dedicated
permission, risk, and response class match the current mount-specific OpenAPI
document. Never derive a journey, permission, risk, confirmation, or response
class from runtime schema alone. KV diffs perform two request-scoped exact
version reads and never persist either value. Generated database and Kubernetes
credentials, PKI private keys and certificates, SSH certificates or OTPs,
transit outputs, TOTP codes, and KV values remain request-scoped and `no-store`.
Material downloads must be explicit, generated from the current response, and
backed by an immediately revoked object URL.
Fail closed when distinct mount names map to the same OpenAPI mount-parameter
identifier. First-class browse/list journeys must fix `list=true` server-side;
the caller may not override it.
Runtime OpenAPI discovery may admit only reviewed `(method, path template,
operation ID)` tuples whose path begins with the fixed `{secret_mount_path}`
placeholder and contains reviewed literal or bounded parameter segments. It
never supplies an origin, method, permission, response
class, identity, namespace, header, or redirect policy. Reads, writes,
mounted-resource deletion, and whole-engine disable use separate object
permissions. Bind every execution to the current capability digest and a live
non-system mount; bind destructive confirmation to the advertised method,
compiled path, and cluster slug. Material responses remain request-scoped and
`no-store`, and mutation uncertainty must never be retried automatically. See
`docs/how-to/administer-openbao-secret-engines.md`.

## The rule that matters most

> **Secret material must never become a model field, a form field bound to an
> instance, a log line, an exception message, or a changelog entry.**

`Credential` has no column capable of holding material, and that absence is the
foundation of every other guarantee. `netbox_openbao/tests/test_security.py`
enforces it by walking the model's fields and failing on any secret-shaped
name. **If you are about to add a field named `password`, `private_key`,
`token`, or similar to a model, stop — you are undoing the design.**

Every credential create, reveal, rotation, and deletion that touches stored
credential material goes through `services.py`; its views, serializers, forms,
and jobs never call a credential backend directly. Cluster lifecycle custody
uses the separate `administration/` transport boundary: administration views
may pass request-scoped initialization, unseal, or snapshot material directly
to that bounded backend, but may never persist or log it. Keep both boundaries
explicit so each remains auditable.

## Verified 4.7 facts

These were reconfirmed against the exact `v4.7.0-beta2` source. Several contradict
what 4.5/4.6-era plugin documentation says — do not "correct" them back:

1. **`ipam.Service`** replaced `protocol` + `ports` with a single
   `port_mappings` `ArrayField` of `"tcp/22"` strings. Its parent is a
   **GenericForeignKey** (`parent_object_type`/`parent_object_id`) rather than
   direct Device/VM FKs — but that half is **also true on 4.6**, contrary to
   what this list said before. Only the ports differ, and `quickadd` handles
   both by checking whether the model has `port_mappings`.
2. **Custom permission actions** register via `Meta.permissions` on the model,
   which NetBox auto-registers through `register_model_actions(model, actions)`
   — note the plural, model-first signature. There is no
   `register_model_action('reveal', models=[...])`.
3. `'reveal'` is a legal action name: `RESERVED_ACTIONS = ('view', 'add',
   'change', 'delete')`.
4. **Background jobs** use the `@system_job(interval_minutes)` decorator from
   `netbox.jobs`.
5. **Detail views are declarative.** `netbox.ui` — `layout.SimpleLayout`
   plus `panels` and `attrs` — replaces hand-written detail templates. Use
   `ui/panels.py`, not new templates. Present in 4.6 too; the only attribute
   this plugin uses that 4.6 lacks is `ArrayAttr`, shimmed in `compat.py`.
6. The **version gate compares `RELEASE.version`**, which is `"4.7.0"` on
   `4.7.0-beta2` (the `beta2` designation is a separate field), so the current
   beta remains within the declared `4.6.0`–`4.7.99` range.
7. `GenericObjectChoiceField` / `GenericObjectFormMixin` handle generic-FK
   form fields. **4.7 only** — `CredentialAssignmentForm` falls back to a
   separate type + ID pair on 4.6, which loses the HTMX re-render but produces
   the same assignment. `FieldSet(html_id=…)` is 4.7-only for the same reason
   and is passed conditionally.
8. GFK idiom: `to='contenttypes.ContentType'`, `on_delete=models.PROTECT`,
   `related_name='+'`.
9. NetBox 4.6 and 4.7 differ in inherited serializer fields, custom-action
   permission mapping, and bulk-list validation order. Compatibility tests must
   accept either no provisional secret write or an exactly compensated write,
   while requiring identical authorization and final database/backend state.
10. The exact-source harness rejects a dirty `NETBOX_SOURCE_DIR`, tests an
    archive of the verified commit, and owns its virtual environment beneath
    the unique validated work root. Do not restore `NETBOX_VENV_DIR` or a
    recursive delete of caller-selected paths.


## Quick-add SSH password auth

The **Add SSH access** action (`netbox_openbao/quickadd.py`; UI in `views.py` and
`forms.py`) accepts **username and password** (`auth_method=password`) as well as
SSH keypairs. Password auth writes an `ssh-password` credential through
`store_credential()` with payload key `password` (the SSH **login** password, not a
key passphrase). When `netbox-nms` is installed, `sync_ssh_password_to_nms` mirrors
the same login into a `DeviceCredential` and SSH `DeviceService`, using the
netbox-nms `openbao_write_policy` slug for OpenBao placement. See `docs/quick-add-ssh.md`.

## Traps already paid for

Each of these cost a debugging cycle. They are load-bearing, not stylistic.

- **`get_client_ip()` returns a `netaddr.IPAddress`, not a string.**
  `GenericIPAddressField` cannot adapt it. Because the audit write is
  best-effort (it must never mask the operation's outcome), the failure was
  swallowed and **every HTTP-originated access went unrecorded**. Always
  `str()` it.
- **Django has no rollback hook.** `transaction.on_commit` fires only on
  commit. Use the versioned `material_transaction()` owner before framework
  atomic blocks. It spans all caller/assignment changes and material writes
  through final commit; do not replace it with an inner savepoint or
  `on_commit` callback. Unowned ambient transactions are refused.
- **A rolled-back credential still holds a primary key in memory.** FK-ing an
  audit entry to it raises a deferred FK violation at commit. `log_access`
  takes `link=False` for that case. Material recovery always records UUID
  snapshots without an object FK; legacy deletion uses `_row_exists()`.
- **`full_clean()` runs `clean_fields()` before `clean()`.** Defaults that
  need to satisfy a `null=False` field must be applied in `full_clean()`, not
  `clean()`, or the API rejects the request before the default can apply.
- **`ValidatedModelSerializer` builds `Model(**attrs)`** to run `full_clean()`.
  Any non-model serializer field (`secret_data`) must be popped before
  `super().validate()`.
- **`bcrypt` is a real dependency.** `cryptography` delegates the OpenSSH
  bcrypt KDF to it and NetBox does not ship it, so passphrase-protected
  OpenSSH keys fail with `UnsupportedAlgorithm` without it.
- **Filterset fields that traverse a relation need an explicit `field_name`.**
  NetBox derives extra lookups from it and raises `ValueError: Invalid field
  name/lookup` when the bare filter name does not resolve on the model.
- **`views.py` must be imported in `ready()`.** `@register_model_view`
  decorators live there and `urls.py` resolves them via `get_model_urls()`. Drop
  that import and every plugin URL 404s.
- **NetBox 4.7 needs `API_TOKEN_PEPPERS`** for v2 tokens. Without it every API
  test errors in `setUp` with `ValueError`, which does not look like a config
  problem.
- **`makemigrations` requires `DEVELOPER = True`.**
- **Every `ObjectView` still needs an `<app_label>/<model_name>.html` stub**,
  even when the page is entirely panel-driven. NetBox 4.7's declarative layout
  does not remove the template lookup — without the stub the detail page raises
  `TemplateDoesNotExist`. All five stubs live in `templates/netbox_openbao/`.
- **`NetBoxTable` injects an actions column** linking to `<model>_changelog`.
  On a plain (non-NetBoxModel) model that view does not exist and the list page
  dies with `NoReverseMatch`. Set `actions = columns.ActionsColumn(actions=())`.
- **Do not reimplement `ObjectEditView.post()`.** An earlier revision did, and
  silently dropped `restrict_form_fields()` (which limits related-object
  selectors to what the user may view), changelog snapshots, and
  `alter_object()`. Preserve `super().post()` inside the outer material
  transaction owner; hook `form.save()` for material and acquire the complete
  source/destination graph before its first metadata save.
- **`super().clean()` can return `None`** in NetBox's form chain; fall back to
  `self.cleaned_data`.
- **`get_plugin_config()` returns `None`, not the default**, for a key absent
  from the merged config — which happens whenever `PLUGINS_CONFIG` is replaced
  after startup, including every `override_settings` in a test. `config.get_config`
  therefore treats `None` as "use the default". Before it did,
  `store_public_material` silently resolved to None and turned metadata
  extraction off, which looks exactly like the extractors failing.
- **An explicit `None` argument overrides a function default.** `generate_ssh_keypair(None)`
  raises rather than generating an Ed25519 key; callers must resolve the
  fallback themselves.
- **`TokenPermissions.perms_map` maps POST to `add_<model>`.** A custom POST
  `@action` therefore demands *create* rights unless you override it — which
  made `rotate` require `add_credential` and left `rotate_credential`
  decorative, and broke POST-`reveal` entirely. `api/permissions.py`
  remaps POST to `view_<model>` for both actions; the action's own permission
  is enforced through `restrict()`. The inherited write-token check still
  applies, so a read-only token cannot rotate.
- **All write compensation must be version-scoped, including creation.**
  Another writer can advance a new path after rollback. Delete only exact
  versions returned to the failed operation, never the whole path. Unknown
  commit outcomes must preserve material and emit non-secret reconciliation
  evidence outside rollback; they are never permission to delete.
- **Django's `ValidationError` is not translated by DRF** and escapes as a
  **500**. The service layer raises Django's (it also serves forms and
  management commands), so every API action calling it must convert —
  `api/views._as_drf_validation_error`. This bit the reveal endpoint's
  `require_reason` path before anyone noticed.
- **`kv_version` and `live_kv_version` legitimately diverge** after a discard,
  because OpenBao's version counter never goes backwards. Never infer "is
  something staged?" from comparing them; `staged_kv_version` is the answer.
- **Discard deletes an existing version only after its pointer change commits.**
  Rollback or unknown commit preserves the staged material. A post-commit
  cleanup failure is committed cleanup-incomplete, not rollback; keep the
  staged pointer cleared, preserve the live material and retain reconciliation
  evidence. Later commit-callback errors do not permit compensating a
  successfully committed write.
- **Sharing a `requests.Session` across backends is safe only because hvac
  builds `X-Vault-Token` per request** and never assigns to `session.headers`.
  If that changes, two policy tiers on the same engine URL could send each
  other's tokens. Do not move auth onto the session.

- **A plain DRF viewset never applies object-permission constraints.** NetBox
  calls `queryset.restrict()` in `netbox.api.viewsets.BaseViewSet.initial()`, so
  a viewset built on `rest_framework.viewsets.ReadOnlyModelViewSet` is still
  gated on the model-level permission by `TokenPermissions` — which is exactly
  why it looks fine — while every **constraint** on the granting
  ObjectPermission is silently dropped. `CredentialAccessLogViewSet` was that
  viewset. Use `NetBoxReadOnlyModelViewSet` for a read-only NetBox endpoint;
  it composes only the retrieve and list mixins, so append-only survives, and
  its `CustomFieldsMixin`/`ExportTemplatesMixin`/`ETagMixin` all probe with
  `hasattr`/`getattr` and tolerate a plain Django model.
- **DRF runs `initial()` before it resolves the handler**, so a permission
  failure returns 403 and *masks* the 405 that would prove a route does not
  exist. A test asserting "the audit log rejects POST" therefore passes for the
  wrong reason if the user lacks the permission. Assert the absent handler on
  the viewset structurally, or grant the permission first and then assert 405 —
  `test_policy_gate` does both.
- **`rotate` is a permission, and `PATCH` is a rotation.** `PUT`, `PATCH`, and
  the bulk list endpoint all reach `perform_update()` under
  `change_credential`; a `secret_data` key there writes a new version. Gating
  only the dedicated `rotate` action leaves the same write reachable by a
  different verb. `_require_rotate` resolves it through `restrict()` so
  constraints apply.
- **Destroying a secret is irreversible; a transaction is not.** So the destroy
  goes *after* the commit — `post_delete` plus `transaction.on_commit`, never
  `pre_delete`. `perform_bulk_destroy()` puts N deletions in one transaction,
  so a `pre_delete` destroy meant one late failure wiped the material of every
  credential before it while restoring all their rows. The residue that remains
  in the other direction (row gone, secret present) is recoverable; that one is
  not.
- **Assignment metadata is a committed projection, not part of the SQL write.**
  Service writes and assignment signals both call `defer_custom_metadata()`.
  It captures credential IDs and the database alias, then reloads final state
  in an empty context after commit. A shared transaction-scoped advisory lock
  serializes that reload and publication against credential deletion. Preserve
  old-owner capture on reassignment; never move backend metadata I/O back
  inside an assignment transaction.
- **`CredentialVerifyJob` cannot find an orphan.** It iterates existing
  credential rows, so it detects a row whose material is missing and is blind
  to material whose row is missing. Do not write that it reports orphans — the
  material owner's reconciliation audit/log and legacy deletion's
  `ORPHANED SECRET` log are the evidence until a mount-walking reconciler exists.
- **NetBox's `BaseViewSet` passes `fields`/`omit` to the serializer** for
  `?fields=`, `?omit=`, and `?brief=true`. A plain DRF `ModelSerializer` raises
  `TypeError: Field.__init__() got an unexpected keyword argument 'fields'` —
  a 500, not a 400. Use `netbox.api.serializers.BaseModelSerializer` even for a
  non-NetBoxModel.
- **Do not write that a per-tier AppRole stops a NetBox permission bug.** It
  does not. `get_backend()` picks the AppRole from the credential's own policy,
  so a bug that yields a `prod-core` credential reads it with the `prod-core`
  AppRole — the identity authorized for that path. Per-tier AppRoles bound
  blast radius: a leaked SecretID reaches only its tier, and a tier whose
  SecretID was never delivered to an instance is unreadable from it. Claim
  that, not more. This is the same mistake the broker-mode sentence was.
- **NetBox mutates the instance before your view code runs.**
  `ValidatedModelSerializer.validate()` `setattr()`s every validated attribute
  onto `self.instance` so it can `full_clean()` it, and Django's
  `ModelForm._post_clean()` calls `construct_instance()`. So by the time
  `perform_update()` or `form.save()` runs, `instance.<field>` is the
  **incoming** value, not the stored one. Any authorization decision that has
  to be made against the *current* state must re-read the committed row —
  `services.enforce_update_access` does. Getting this wrong is silent: the
  check runs, passes, and compares the caller against the value they chose.
- **An authorization check in a view is a check the other four surfaces do not
  have.** The `CredentialPolicy` group gate lived in
  `api/views.CredentialViewSet._authorize` and nowhere else, so the web UI
  served material the API refused. Anything of that shape belongs in
  `services.py`. Note also that `PATCH`/`PUT` are routed by DRF's own
  `update()` and never reach a custom action's authorization helper, so a gate
  applied only in that helper is bypassable by verb.
- **`netbox_openbao/secrets/` had no `__init__.py`** and worked only as an
  implicit namespace package. It now has one. A namespace portion inside a
  regular package merges with any same-named directory another distribution
  installs, and it is invisible to static tooling — which is how the
  documentation build found it.

## Testing

### Execution-bound automation provider

`automation.resolve_automation()` is the only supported automation-resolution
entry point. It loads the actor and frozen reference through
`netbox_rpc.credential_authority.validate_secret_resolution_dispatch`; no
caller-selected identity or reference is accepted. The shared strict reference
class is owned by `netbox_rpc.credential_contract`, not duplicated here.
RPC admission calls metadata-only `capture_reference_identity()` and freezes
its result before approval. The provider rechecks that identity under locks;
material rotation may advance the live version but cannot substitute an
assignment, username, key fingerprint, schema or backend identity.
Material reads remain in `services.read_automation_bundle()` after authorization.
SSH authority uses separate verified live fingerprint/version fields, never
the optional display fingerprint. Maintain those fields independently of
`store_public_material`; refuse legacy unverified admission and compare the
actual read key's fingerprint before delivery. Never backfill from display
metadata. Staged identity remains separate until promotion.

`synchronization.lock_credential_graph()` establishes policy IDs, engine IDs,
credential, then provider assignment and custom-schema lock order. Re-evaluate object restrictions
and policy groups after waits. Material writers use the same graph order;
the PostgreSQL policy-group through-table trigger synchronizes relationship
changes with policy locks, including direct writes and transaction rollback.
Recheck the RPC-verified lifetime after waits, immediately before the material
read and after the backend returns. Actor-only no-key locks avoid audit foreign
key inversions; do not weaken catalog insertion-protection locks.
Call RPC's fresh `check_authorization_permissions()` at those same boundaries
without reacquiring authority locks. Repeat provider restrictions after the
backend returns; a cached permission check from before I/O cannot authorize
delivery after revocation.

The caller must be in autocommit: a durable `AutomationResolutionReceipt`
commits before the read so an outer rollback cannot permit replay. Receipt
identity includes execution, nonce digest, step and reference. All repeats,
including unknown outcomes, are refused; values are never cached. A missing
live pointer and staged versions are refused; pinned means the specified version
must still be live. `CredentialAssignment.enabled` is rechecked immediately
before read. Audit failure blocks delivery. See `docs/automation-resolution.md`.

Provider and material transaction tests require real `TransactionTestCase`
semantics, not an artificial `TestCase` transaction. Material API/view fixtures
use `MaterialTransactionTestMixin` only to retain NetBox helper methods while
delegating setup, fixture loading, per-test class data and flush to the real
transaction lifecycle. Production has no test-wrapper exemption: a new owner
requires actual autocommit, and staged cleanup independently requires confirmed
commit. Run the real
OpenBao and broker tests before claiming end-to-end provider acceptance.

```bash
cd <netbox>/netbox
python manage.py test netbox_openbao

# Include the live-OpenBao tests — a fake proves nothing about whether hvac
# and OpenBao agree on check-and-set semantics.
export NETBOX_OPENBAO_TEST_ADDR=http://127.0.0.1:8200
export NETBOX_OPENBAO_TEST_TOKEN=devroot
python manage.py test netbox_openbao
```

`docker-compose.dev.yml` brings up PostgreSQL, Redis, and OpenBao 2.6 dev mode.
Full procedure in [`docs/development.md`](docs/development.md).

Broker-mode tests need a running
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker)
and skip cleanly without one:

```bash
export NETBOX_OPENBAO_BROKER_ADDR=https://localhost:8201
export NETBOX_OPENBAO_BROKER_CERT=/path/netbox-prod.pem
export NETBOX_OPENBAO_BROKER_KEY=/path/netbox-prod.key
export NETBOX_OPENBAO_BROKER_CA=/path/client-ca.pem
```

### Two things that will cost you an hour otherwise

- **A "hanging" test run has two causes, and the second one is invisible.**

  The obvious one is stale Postgres connections: killing a `--keepdb` run leaves
  backends holding the test database, and the next run blocks on them.

  ```sql
  SELECT pg_terminate_backend(pid) FROM pg_stat_activity
   WHERE datname LIKE 'test_%' AND pid <> pg_backend_pid();
  ```

  The other is the test database itself being unusable, which presents as a hang
  rather than as an error. A killed run can leave `test_openbao_test`
  half-migrated — the next run then dies on something like
  `column "status" of relation "dcim_module" already exists`, or, if Django
  decides to ask whether to delete it, blocks forever on a **prompt you cannot
  see**: with stdout block-buffered (any non-tty — a pipe, a CI log, an agent's
  captured output) the question never reaches you.

  In both cases `pg_stat_activity` shows `idle in transaction` waiting on
  `ClientRead`, which points at the database and tells you nothing. Look at what
  the process is blocked on instead:

  ```bash
  ls -l /proc/$PID/fd/0            # a tty or socket here -> it is waiting on input
  ```

  Two habits avoid the whole class. **Pass `--noinput` and redirect stdin** in
  any non-interactive run, so a prompt fails loudly instead of hanging — and
  when a run has been killed, **drop the test database** rather than trusting
  `--keepdb` to sort it out:

  ```sql
  DROP DATABASE IF EXISTS test_openbao_test;
  ```

  ```bash
  python manage.py test netbox_openbao --noinput --keepdb < /dev/null
  ```

  One more, on the diagnosis itself: `pgrep -f "manage.py test ..."` matches
  **the shell you typed it in**, so `until ! pgrep -f ...; do sleep 5; done`
  never exits and a "still running" reading can be entirely your own loop. Match
  on the interpreter instead:

  ```bash
  for p in $(pgrep -x python); do readlink /proc/$p/exe | grep -q nb47 && echo "$p"; done
  ```

- **Never `pkill -f "manage.py test"`.** The pattern matches the shell that ran
  it, so the kill takes your own session with it (exit 144). Match narrowly on
  the interpreter path, or find the process by its database connection.

### Why the live tests are not optional

Three separate defects have hidden behind a passing fake in this repository:
a whole-path delete where a version-scoped one was needed, tombstoned versions,
and an empty `custom_metadata` value that **both** OpenBao and Vault reject —
that last one broke credential creation against every real server while 200+
tests stayed green (#17). A fake only fails in ways its author already thought
of. Run against a real server before believing a green suite.

Current beta2 state: **308 tests** pass against exact NetBox 4.7.0-beta2 with a
live OpenBao 2.6 development server (`18` optional live-backend tests skip when
their endpoints are not configured). `ruff check` and
`makemigrations --check` are clean. The hosted compatibility matrix also keeps
NetBox 4.6.5 as the backward-regression target.

## When changing things

- **A new credential type** → `CredentialTypeChoices` + `CREDENTIAL_SCHEMAS` +
  (if needed) an extractor returning only `EXTRACTABLE_FIELDS` keys +
  `SECRET_INPUT_FIELDS`/`SENSITIVE_INPUT_FIELDS` in `forms.py`.
- **`Credential.credential_type` has no Django `choices` on purpose.** Django
  validates a choices field in `clean_fields()`, which would reject every
  operator-defined `CredentialTypeSchema` slug. Membership is checked in
  `clean()` instead, and the model supplies `get_credential_type_display()`
  because tables and panels call it.
- **`CredentialTypeSchema.extractor` must stay a registry name.** If it ever
  becomes a dotted path resolved with `import_string`, the model is remote code
  execution with a JSON Schema attached.
- **A new backend** → subclass `SecretBackend`, register it in
  `backends/BACKENDS` and `BackendChoices`, and add an integration subclass of
  `_KVIntegrationTests`. Never raise a vendor exception, never log material.
  A backend tested only against a different server proves nothing about it.
- **A method the plugin calls on a backend must be `@abstractmethod`.** The ABC
  exists so a third party can implement it without forking, so a method that is
  called but not declared is a trap: the subclass imports, instantiates, passes
  every abstract-method check, and fails later inside a background job.
  `read_metadata` was exactly that for a while — `CredentialVerifyJob` calls it
  and all three shipped backends implemented it, so the omission was invisible.
  `tests/test_backends` now **derives** the required set by walking the package
  AST for calls on a backend, rather than from a transcribed list — a
  transcribed list is a second place to forget, and forgetting both is the same
  single mistake. The scanner follows names bound from `get_backend()` as well
  as the literal name `backend`, so a rename does not disarm it, and
  `test_the_scan_finds_known_call_sites` fails if it stops matching anything.
  Reach a backend through `getattr` or a long attribute chain and the scan will
  not see it; do not, or extend `_BackendCallScanner` in the same change.
- **Configuration is database-backed, and the read path has five properties
  that are load-bearing.** `config.get_config()` resolves per-request memo →
  `OpenBaoSettings` row → `PLUGINS_CONFIG` → default.
  1. **A read must never create the row** — `.first()`, never `get_or_create()`.
     A read that creates it makes `PLUGINS_CONFIG` permanently unreachable, and
     the 19 `override_settings` tests across six files would then pass while
     asserting against defaults rather than against what they set.
  2. **The complete row is memoised once per request or job, not once per key.**
     This path runs on *every object detail page in NetBox*, because the
     credentials panel is globally registered and scoped per render. Five
     `get_config()` calls therefore cost one indexed single-row query. The
     `_MISSING` sentinel preserves the no-row result within that lifetime.
  3. **There is deliberately no shared Django cache.** A concurrent reader can
     otherwise restore stale security controls after another process commits
     and invalidates the old entry, and a cache outage makes every settings read
     fail. Turning one query per request into zero is not worth either failure
     mode.
  4. **Settings signals clear the writing thread's memo immediately.** Reads
     after a write remain unmemoised until the surrounding transaction ends,
     because Django has no rollback hook that could discard an uncommitted
     snapshot. A rollback therefore cannot leave its value authoritative for
     the rest of the request or job.
  5. **Direct ORM writes do not gain validation from being settings writes.** As
     with every Django model, an instance `save()` does not call `full_clean()`;
     direct callers must do that first, although the save signal still clears
     the current memo. `QuerySet.update()`, `bulk_update()`, and raw SQL bypass
     both validation and signals. An in-flight request may retain its earlier
     snapshot, but the next request reloads the row. Use API/form saves, or call
     `full_clean()` before an instance save.
- **`middleware.SettingsCacheMiddleware` is not optional and must not be
  removed.** The thread-local memo is only safe because something discards it
  after each response. Drop the middleware and a gunicorn worker thread keeps
  the configuration it read on its first request for the life of the process, so
  a settings change applies on the thread that saved it and silently not on any
  other — no error, nothing logged, and the save looks like it did not take.
  NetBox clears its own config the same way, in `netbox.middleware`. The plugin
  declares it through `PluginConfig.middleware`, which NetBox appends to
  `MIDDLEWARE` at startup, so it needs nothing from the operator.
- **RQ jobs must clear the settings memo around every run.** They do not pass
  through HTTP middleware, and a worker process is long-lived. The shared job
  decorator clears at the start and in a `finally` block so one job never
  inherits another's snapshot and a failure cannot leave stale state behind.
- **The five job intervals still come from `PLUGINS_CONFIG` and still need a
  restart.** `@system_job` evaluates its interval at *import*, requires a plain
  `int`, and `rqworker` reads the resulting registry at *worker startup*. Fields
  for them exist on the settings model so the rescheduling work needs no second
  migration — do not wire the decorators to them until that work lands, because
  a value that appears live and reverts at the next worker restart is worse than
  one that is honestly restart-required.
- **The settings audit lives on a signal, not in the edit view.**
  `ObjectEditView` builds its form directly and calls `form.save()` inside its
  own transaction — it never routes through `get_form()` or `form_valid()`, so
  overriding either does nothing, and reimplementing `post()` is the mistake
  recorded above. A `post_save` receiver also covers the REST API and management
  commands, which matters because `change_openbaosettings` can widen
  `reveal_rate_limit` — the control bounding a leaked token — and an audit that
  saw only the UI would be the wrong audit. The actor comes from
  `netbox.context.current_request`; a save with no request records no user,
  which is accurate rather than convenient. **Field names only, never values.**
- **Startup diagnostics that need the database are Django system checks, not
  `ready()` hooks.** Querying during app initialisation earns Django's own
  `Accessing the database during app initialization is discouraged` warning, and
  on a fresh install the table does not exist. `checks.py` holds them; they run
  on `manage.py check`, `runserver`, and `migrate`, which is when an operator can
  act on what they say.
- **A constant in a model class body trips `check_no_secret_fields.py`.** That
  script parses class-body assignments looking for fields, so a helper constant
  there is noise in the one signal it exists to keep clean. Put it at module
  scope — `NOT_AUDITED` in `models/settings.py` is there for that reason.
- **`OpenBaoSettings` holds configuration, never material.** No AppRole, no
  SecretID, no token — the same rule as `Credential`, and an easier place to
  talk yourself into breaking it. `scripts/check_no_secret_fields.py` guards
  both models.
- **`path_prefix` becomes immutable when the first credential exists.** The
  settings row cannot be deleted then either, because restoring a different
  fallback prefix has the same effect as changing it. The AppRole's OpenBao
  policy is scoped to `secret/data/<path_prefix>/credentials/*`, while existing
  credential paths are stamped once. Prefix updates and credential creation
  use `select_for_update()` on the settings row and then re-check committed
  state. A transaction-level advisory lock covers a fresh installation where
  there is no row to lock yet. A later prefix change would make every new write
  fail with a permission error that looks like a vault outage while all old
  credentials kept working. Validation also rejects empty prefixes, leading or
  trailing slashes, empty or traversal segments, and whitespace. A stale model
  instance cannot recreate a deleted row. When credentials predate the first
  row, its prefix must match their stamped paths. Credential path derivation
  applies the same validator to a legacy `PLUGINS_CONFIG` fallback and fails
  closed when that configuration is unsafe.
- **`path_alias_template` is deliberately absent from `OpenBaoSettings`.** It
  is declared and documented but unused by the package. Do not turn a dead
  setting into an operator-facing database field before it is either
  implemented or removed.
- **A plugin integrating with this one registers its assignable models in
  `ready()`** — `netbox_openbao.registry.register_assignable_models(...)` — it
  does not ask the operator to edit `PLUGINS_CONFIG`. The resolved allowlist is
  `assignable_models` ∪ registry − `assignable_models_deny`, computed in
  `config.assignable_model_labels()`. Three properties are load-bearing:
  **deny wins**, so an operator can refuse an integration's choice without
  patching someone else's plugin; the result is **sorted**, because it is
  rendered into `CredentialAssignment.clean()`'s error message and that message
  is the only way an operator can discover what a running instance permits; and
  a bad label is **rejected and logged at ERROR, never raised** — this runs in
  `AppConfig.ready()`, where an exception takes the whole NetBox instance down
  instead of failing one integration. "Bad" means shape *and* existence: a label
  must match `app_label.model` **and** name a model the app registry has, because
  `dcim.rakc` is well-formed and names nothing. That lookup is safe from
  `ready()` — `apps.populate()` imports every app's models before it invokes any
  `ready()` hook, so an earlier note in this file claiming otherwise was wrong.
  Registration must happen in `ready()` — anywhere later and it will work in
  development and fail on a worker that never imported the module.
- **Do not describe the assignable-model allowlist as a boundary against a
  plugin.** A NetBox plugin runs in-process with full ORM access and can reach
  every `Credential` row regardless, so registration grants nothing it did not
  already have. What the allowlist bounds is *accident* — a mistyped content
  type, a bulk import aimed at the wrong model. The deny list is an operational
  control for turning an integration off, not containment for one you distrust.
  Same class of overclaim as the per-tier AppRole and broker-mode sentences
  above.
- **A `PluginTemplateExtension` must never carry a `models` list built from
  `assignable_model_labels()`.** NetBox's `register_template_extensions()` reads
  `models` **once**, during this plugin's `ready()`, and files the class under
  each label. A snapshot therefore freezes the allowlist: a model registered by
  a plugin whose `ready()` runs later is permitted to hold assignments and gets
  no panel, purely because of where `netbox_openbao` sits in `PLUGINS`. Same
  config, different UI, no error. `template_content.CredentialsPanel` is
  registered **globally** (no `models`) and checks the live list per render in
  `_is_assignable()`. Keep it that way.
- **`BrokerBackend` is a transport swap, not a different store.** It speaks to
  [`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
  which holds the AppRole so NetBox does not, and it must stay
  indistinguishable from direct mode above `SecretBackend` — same exception
  types for the same conditions. Three traps:
  - **Never send `kv_mount` or `namespace`.** They are the broker's own
    configuration. Sending them would let a compromised NetBox address mounts
    the operator never granted, which inverts the point of the mode.
  - **The client certificate is keyed on `env_prefix`**, exactly as the AppRole
    is. The broker identifies callers by certificate CN, so flattening this to
    one certificate would silently give every `CredentialPolicy` tier the same
    access.
  - **Never relay the broker's error text.** It is written not to leak policy,
    but this side cannot verify that, and forwarding a remote string gives up
    the guarantee `backends/exceptions.py` exists to provide.
- **Do not write that broker mode makes "a NetBox compromise not a secret
  compromise".** It does not, the README said so once, and it was wrong: an
  attacker with code execution in NetBox can still ask the broker and be
  answered. What it buys is that the database and configuration no longer carry
  vault credentials and that the audit log is out of reach. Claim that, not
  more.
- **Anything touching the reveal path** → re-read
  [`docs/security.md`](docs/security.md) first and make sure
  `tests/test_security.py` still fails when you break the invariant.
- **A behaviour change** → update `docs/` and this file in the same change,
  and rebuild the site: `pip install '.[docs]' && mkdocs build --strict`. The
  nav in `mkdocs.yml` is explicit, so a new page that is not listed there is
  built but unreachable — except under `docs/reference/`, which
  `scripts/gen_ref_pages.py` generates from the package at build time.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. In
short: every change that alters behaviour updates `docs/` and this file in the
same commit, `ruff check .` and `makemigrations --check` must be clean, and a
change to the reveal, write, or backend paths is expected to come with a test
that fails when the invariant it protects is broken.
