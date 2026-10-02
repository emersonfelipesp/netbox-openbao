# Changelog

## 0.2.0 - 2026-10-02

- **Upgrade action required.** OpenBao login material (AppRole role and secret
  IDs, token, Kubernetes role, broker client certificate) and every plugin
  setting now live in encrypted NetBox models instead of `PLUGINS_CONFIG` and
  `NETBOX_BAO_*` environment variables. Runtime code no longer reads those
  sources; only the one-time `openbao_configure import-legacy-settings` and
  `import-env` commands do. Follow `docs/upgrading.md` in a maintenance window
  before relying on the upgraded plugin; until authentication material is
  stored, OpenBao access fails. Also added: a Settings page and API, and the
  `openbao_configure` management command for headless setup, connection tests
  and re-encryption after a `SECRET_KEY` rotation.
- One consolidated migration, `0024_engine_auth_material`, covers everything
  added since 0.1.0.post2: the service endpoint and credential schema models
  with their seed, the unique credential import source constraint, the
  idempotent `SSH` service template seed, each policy's former environment
  prefix retained as non-executable metadata, and the encrypted authentication
  material model. Databases that already recorded that name skip it.
- Service endpoints and an SSH public-key inventory, a permission-constrained
  metadata-only credential resolver, an atomic endpoint-with-credential write
  and a revision-bound endpoint reveal. Provider-specific imports remain the
  responsibility of consuming plugins.
- SSH credentials (`ssh-keypair`, `ssh-password`) must now be tied to an SSH
  Application Service: the chain is OpenBao Credential > Application Service
  (`ipam.Service`) > Device or Virtual Machine. Assigning an SSH credential
  directly to a Device or VM is rejected (other targets such as hypervisor
  endpoints are unaffected).
- Added a seeded `SSH` service template (`tcp/22`). Quick-add now builds the
  Application Service from a chosen service template and creates the
  credential on the same form; the optional "create service" checkbox is gone
  and the REST quick-add accepts `service_template` and `service_name` instead
  of `create_service`.
- NetBox 4.7 is now required; the 4.6 `protocol` + `ports` service path was
  removed. Existing direct Device/VM assignments of SSH credentials are not
  rewritten and stay editable; the Application Service rule applies to new
  assignments.

## 0.1.0.post2 - 2026-10-01

- Added atomic SSH quick-add and server-side SSH key-generation REST actions
  with bounded no-store responses, live target and permission enforcement,
  request-scoped secret custody, transactional compensation, and explicit
  unknown-outcome handling.
- Restored NetBox 4.6 and 4.7 quick-add compatibility by accepting the stable
  numeric content-type primary-key contract, rejecting labels and unassignable
  models, and preserving the configured key type when generated-key requests
  provide JSON `null`.
- Added exact `import_source` filtering to the credential API so audited RPC
  consumers resolve one imported legacy credential without receiving unrelated
  credential metadata and falsely reporting an ambiguous mapping.
- Added security, transaction, metadata-projection, quick-add compatibility,
  and credential-provenance regression coverage for these public API changes.
- No model or migration changes.

## 0.1.0.post1 - 2026-09-18

- Fixed the OpenBao procedure-run list page (Audit > Procedure runs), which
  failed with `TypeError: BaseForm.__init__() got an unexpected keyword argument
  'model'` because its filter form declared no model and carried secret-engine
  fields. The form now filters by engine, procedure, initiator (several at
  once), tag, and free-text search, and the list and detail pages are covered
  by view tests.
- Fixed the `main_branch` production deployment override, which invoked the
  inner plugin helper before any authorization existed and always failed with
  `deployment descriptor is missing or malformed`. The workflow now calls the
  authorizing `deploy-main` entry point with the claimed NMS proof.
- No model or migration changes.

## 0.1.0 - 2026-09-17

- Added immutable package-first Gitea publication with a canonical schema-1
  release manifest bound to the source commit and exact wheel/sdist bytes.
- Added reviewed `develop` staging deployment and proof-v3 NMS production
  deployment workflows for the netbox-openbao plugin.
- Added TestPyPI release-candidate and PyPI final publishing through distinct,
  fail-closed GitHub event contracts.
- Documented release, validation, production recovery, and rollback procedures.

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 - 2026-10-02 (detailed changes)

### Added

- Added `openbao_configure import-legacy-settings` with validated dry-run diff
  and effective-value verification. The upgrade sequence now preserves all
  non-default legacy security settings before legacy configuration is removed,
  and policy-specific environment prefixes remain as reversible, non-editable
  migration metadata until identity imports are verified. The explicit
  `cleanup-legacy-prefixes --confirm-imports-verified` command then clears the
  retained values without an automatic schema drop.

- Replaced runtime environment and `PLUGINS_CONFIG` authentication with
  database-only configuration. The new owner-scoped `EngineAuthMaterial` model
  encrypts AppRole, token, Kubernetes, and broker mTLS values with a versioned
  key derived from Django's `SECRET_KEY`; UI and REST surfaces expose only
  configured/missing status. The singleton Settings dashboard now shows every
  effective plugin and engine parameter, and `openbao_configure` supports
  headless settings, engine, authentication, connection-test, one-time legacy
  environment import, and `SECRET_KEY` re-encryption workflows. Token and TLS
  session caches are revision-bound and invalidated on authentication rotation.
  Standard `EngineAuthMaterial` add/change permissions gate the write-only UI
  and REST editors, while changelog, webhook, GraphQL, search, filter, table,
  CSV, clone, and administration-audit surfaces expose no plaintext or
  ciphertext.

### Fixed

- Enforced object restrictions, add permission, post-save conformance, and
  `If-Match` validation on the settings singleton API. The Settings dashboard
  now restricts engines, policies, clusters, authentication status, and related
  host devices independently.
- Serialized authentication-material rotations under a row lock, merged only
  submitted fields, allocated unique revisions, and deferred exact token and
  TLS-session invalidation until commit so concurrent rotations cannot retain
  a superseded identity.

- Added authoritative service endpoint and SSH public-key inventory, a
  permission-constrained metadata-only credential resolver, and an idempotent
  copy-only importer for legacy NMS/network device, VM, service, and
  observability credentials. Dry runs perform no database or OpenBao writes.

- Complete the pinned OpenBao 2.6.2 Web UI replacement with guarded Raft join;
  typed lease lookup, renewal, revocation, prefix revocation, and force
  revocation; request-scoped wrapping, hashing, random-data, and token tools;
  safe UI response-header controls; and exact runtime conformance diagnostics.
  Dedicated permissions, durable preflight audit, stale impact checks, no-store
  material handling, direct-mode live coverage, broker fail-closed behavior,
  browser accessibility checks, and end-to-end operating guidance close all 19
  parity families.

- Secrets-engine administration now provides cluster-scoped Web UI and REST
  actions for mount listing, configuration, tuning, enable, remount status, and
  guarded disable. A classified OpenBao 2.6.2 operation explorer intersects
  bounded runtime discovery with a fixed mounted-path grammar, dedicated
  read/write/delete permissions, capability-digest freshness, exact destructive
  confirmations, metadata-only audit, no-store material responses, and direct
  transport controls that prevent caller-selected origins, methods, headers,
  namespaces, identities, redirects, and mutation retries.

- An OpenBao administration foundation introduces first-class cluster
  inventory, a compatibility migration from existing engine connections,
  dedicated discovery/operation permissions, bounded runtime OpenAPI
  normalization, direct and broker transport contracts, `no-store` Web UI and
  REST capability views, and a metadata-only append-only administration log.
  A strict OpenBao 2.6.2 UI parity manifest assigns every remaining
  administration family without treating an advertised operation as
  executable.

- Execution-bound automation credential resolution with exact target and
  assignment checks, explicit same-version field bundles, signed RPC dispatch
  authority, and separate initiating-actor and executor audit correlation.
  Durable one-use receipts reject retries after an unknown outcome without
  caching secret material. Assignments can be disabled for automation.
  Final authorization follows every provider lock wait and uses fresh exact
  RPC execute/approve restrictions and a verified dispatch expiry. Permissions
  are checked again after material I/O before any bundle is returned.
  Version-bound live SSH identity is independently verified
  even when optional public display extraction is disabled.
- Explicit outer material transactions cover owner and assignment persistence,
  multiple writes and the final database commit. Definitive rollback removes
  only operation-owned versions; uncertain commit outcomes preserve material
  and emit non-secret reconciliation evidence. Staged forms acquire ordered
  source/destination locks before saving metadata. Discard commits its pointer
  change before exact staged-version cleanup and reports committed cleanup
  failures explicitly. Compatible Proxbox, NMS and other material-write
  adapters are release prerequisites; older consumers fail closed until they
  adopt the complete transaction-owner contract.
  New owners require actual autocommit; manually managed transactions cannot
  substitute a savepoint for final commit. Staged cleanup independently
  requires the confirmed commit witness.

- **A settings page, with the fields grouped as decisions.** Storage, reveal
  controls, generation, assignable object types, audit and expiry, and the
  background-job intervals. Reachable from the plugin menu under Configuration.

  `path_prefix` renders read-only once any credential exists. The model refuses
  the change regardless — that guard is the enforcement and it covers the API
  and direct ORM writes too — but offering an editable box that will be rejected
  on save is a worse experience than saying why up front.

  The five interval fields are shown disabled with the reason. They are stored
  but not yet acted on, so an edit would appear to apply and revert at the next
  worker restart; a field that says so beats a field that lies.

- **Refused changes are audited where the record can survive.** A refusal
  raised inside a transaction takes its audit row down with it when that
  transaction rolls back, so the guard was writing the record into exactly the
  transaction that discarded it — the one entry an operator reconstructing an
  incident most wants, reliably absent. Deletion and bulk deletion now record
  the refusal after their own transaction has unwound. A caller that wraps the
  whole operation in a transaction of its own, such as DRF's bulk destroy, is
  still outside reach; the guard, not the record, is the enforcement.

- **A second settings row is refused before it reaches the constraint.** Two
  concurrent creates both pass form and serializer validation, because the
  `exists()` check there runs before either inserts. The loser reached
  PostgreSQL's unique key as an `IntegrityError`, which `ObjectEditView` does
  not catch — a 500 on the add page of an already-configured install. The model
  re-checks under the singleton advisory lock it already holds, which
  serialises the two, and the API translates the refusal into the same
  structured 400 it returned before.

- **The settings list offers only the actions that exist.** `ObjectListView`
  provides bulk import, export, edit, rename, and delete by default, and none
  of them has a route here — bulk operations on a singleton are meaningless.
  Left at the default they rendered as controls that fail rather than as
  controls that are absent, which is the same defect as the missing list route
  in the other direction.

- **A system check reports every ignored legacy plugin key.** Runtime settings
  are database-only. The check names obsolete values left in
  `configuration.py` so operators can remove the dead configuration.

- **Settings changes are audited.** `change_openbaosettings` can widen the reveal
  rate limit, which bounds how fast a leaked token drains the store, so the
  change is recorded in `CredentialAccessLog` with a new `configure` action as
  well as in NetBox's changelog — putting it in the same timeline as the reveals
  it governs. Written from a model signal, so it covers the REST API and
  management commands and not only the UI. Field names only, never values.


### Added

- **Configuration is stored in the database and editable through the REST API,
  UI, and CLI.** A singleton `OpenBaoSettings` row holds every runtime setting.
  Resolution is per-request memo, then the settings row, then the model field
  default. A sentinel preserves the no-row result within the request. A read
  never creates the row; only an explicit operator write does.

  `reveal_rate_limit` is validated on save, so an unparseable rate is refused
  there rather than surfacing later as a failed credential reveal, where the
  rate limit is the last place anyone would look.

  The settings row holds **configuration only**. There is no AppRole, SecretID,
  or token field, and `scripts/check_no_secret_fields.py` now guards this model
  as well as `Credential`.

### Fixed

- The exact-source NetBox 4.6.5 and 4.7.0-beta2 compatibility gate now checks
  out the private `netbox-rpc` dependency at an immutable commit, verifies its
  source SHA and installed `0.1.8.post1` distribution, and installs it before
  netbox-openbao. The protected-branch gate no longer asks the public package
  index for an unpublished runtime dependency or certifies a source revision
  that predates the credential-authority contract. The OpenBao cluster owner
  field now records the running NetBox release's reverse-relation state,
  preventing a false pending migration on NetBox 4.6 while retaining NetBox
  4.7 behavior. The plugin now declares the Pydantic runtime used by the RPC
  integration, maps procedure dispatch to change permission on the existing
  engine, uses NetBox object-permission restrictions for RPC execution and
  approval, tolerates the model serializer fields available in each supported
  NetBox release, and preserves secret compensation across both versions'
  bulk-create validation order. The harness rejects dirty NetBox inputs, tests
  an archive of the verified commit, and creates its virtual environment only
  beneath the validated unique work root. Constrained bulk creates now return
  HTTP 403 and leave neither database rows nor secret material behind.

- **The shared Django settings cache has been removed.** A concurrent fill
  could restore stale security controls after another process committed and
  invalidated the old entry, while a cache outage made every configuration read
  fail. The per-request memo still reduces several setting reads to one indexed
  single-row query. Saving clears the writing thread's memo, uncommitted values
  are not memoised, and middleware and background jobs bound each snapshot's
  lifetime.

- **Concurrent settings creation now returns a structured HTTP 400 instead of
  an unhandled integrity error.** The database singleton constraint remains the
  authority and the API translates the losing create transaction.

- **`path_prefix` is now validated before it can create a partial outage.** It
  must be a safe relative path and cannot change, or be restored to a fallback
  by deleting the settings row, after credentials exist. Credential creation
  and prefix updates now select the settings row for update, with an advisory
  transaction lock covering its initial absence, so a credential cannot appear
  between validation and commit. The AppRole policy remains scoped to the
  original prefix while new writes would otherwise target the replacement. A
  stale instance cannot recreate a deleted settings row, the first row must
  match prefixes stamped into existing credential paths, and the same prefix
  validator now rejects invalid effective values during every credential path
  derivation.

- **`rpc.py` called `get_config()` with no arguments**, against a signature
  requiring a key — a `TypeError` on the `provision_netbox_approle` dispatch
  path. The following line indexed the result as a dict, so a shape the function
  has never returned was expected. Now correct and covered by a test.

### Unchanged, deliberately

- **The five background-job intervals come from `OpenBaoSettings` and still
  require a worker restart.** `@system_job` reads its interval at import time
  and `rqworker` reads the resulting registry at worker startup. Bootstrap and
  database-outage imports use the model defaults.

### Changed — action required for third-party backends

- **`SecretBackend` now requires `read_metadata`.** It is declared
  `@abstractmethod`, so **any `SecretBackend` subclass outside this repository
  that does not implement it will raise `TypeError` on instantiation after this
  upgrade** — at startup, or at the first backend construction. Every backend
  shipped here already implements it and is unaffected.

  To adapt an external backend, add:

  ```python
  def read_metadata(self, path):
      """Return the KV metadata for `path`. Never a secret value."""
      # Must carry at least `current_version` and `custom_metadata`,
      # and raise OpenBaoNotFound when the path does not exist.
  ```

  This is a deliberate correction rather than a new demand.
  `CredentialVerifyJob` has always called `read_metadata`; the ABC simply failed
  to say so, which meant a conforming third-party backend imported cleanly,
  instantiated cleanly, passed every abstract-method check, and then failed
  inside a background job — detached from the change that caused it. Failing at
  instantiation, with the method named, is the better half of that trade.

  A new test derives the required method set by scanning the package for calls
  made on a backend, rather than from a transcribed list, so the ABC cannot fall
  behind its call sites again.

### Added

- **Plugins can register their own assignable object types.**
  `netbox_openbao.registry.register_assignable_models(...)`, called from an
  integrating plugin's `AppConfig.ready()`, adds that plugin's models to the
  allowlist `CredentialAssignment` enforces. Without registration every integration was
  silently inert until an operator read the right paragraph — and the failure
  it produced was a validation error about a settings file they had never been
  pointed at.

  The resolved allowlist is `assignable_models` unioned with the registry, minus
  a new `assignable_models_deny` setting, which lets an operator refuse a model
  an integration registered without patching a plugin they did not write. Deny
  beats both configuration and registration.

  To be clear about what this allowlist is: it bounds *accident* — a mistyped
  content type, a bulk import pointed at the wrong model — and it is **not** a
  boundary against an installed plugin, which runs in-process with full ORM
  access and could reach every credential regardless. The documentation says so
  where an operator will read it.

  A bad registration is rejected, logged at ERROR naming the value, and
  retrievable from `registry.rejected_assignable_models()`. It is checked for
  shape *and* against the app registry, because `dcim.rakc` is a well-formed
  label that names nothing and accepting it would leave a broken integration
  indistinguishable from one nobody configured. It does not raise, because this
  runs in `AppConfig.ready()` where an exception takes the whole instance down
  rather than failing one integration.

  The list is also sorted now, because `CredentialAssignment.clean()` renders it
  into its rejection message and that message is the only way to discover what a
  running instance actually permits.

### Fixed

- **The credentials panel no longer depends on the order of `PLUGINS`.** It was
  registered against a snapshot of the assignable-model list taken when
  `template_content` was imported. NetBox reads a template extension's `models`
  attribute exactly once, during the owning plugin's `ready()`, so a model that
  an integrating plugin registered from its own `ready()` was permitted to hold
  assignments and got no panel whenever `netbox_openbao` came first in
  `PLUGINS`. Same configuration, different UI, no error anywhere. The panel is
  now registered globally and filters on the live allowlist at render time.

  That filter resolves the object's label through
  `ContentType.objects.get_for_model()` rather than from `obj._meta`, which also
  fixes a **proxy model** losing its panel: the content type resolves a proxy to
  its concrete model, so assignments were stored under one label and the render
  gate compared another.

### Security

- **The audit log's REST endpoint now honours ObjectPermission constraints.**
  `CredentialAccessLogViewSet` extended DRF's plain `ReadOnlyModelViewSet`,
  which sits outside the hierarchy where NetBox applies object permissions
  (`BaseViewSet.initial()` is what calls `queryset.restrict()`). The
  model-level permission was still enforced, but every *constraint* on the
  granting ObjectPermission was ignored — so a role scoped to one policy tier
  was held to that constraint in the UI list view and read the whole estate's
  log through the API, including credential names, usernames, reveal reasons,
  and source IPs. It now extends `NetBoxReadOnlyModelViewSet`; the endpoint
  remains append-only.

- **The `CredentialPolicy` group gate is now enforced on every surface.** It
  was implemented only in the REST viewset's authorization helper, so a user
  belonging to none of a tier's permitted groups was refused a reveal over the
  API and served the same material by the credential page. The check moved to
  `services.enforce_policy_access()` — the same chokepoint every surface goes
  through — and now also covers the full-page UI reveal, the HTMX reveal, the
  UI promote and discard actions, the edit form's material write, and
  `PATCH`/`PUT` of `secret_data` (which is routed by DRF's own `update()` and
  never reached the helper). Refusals are recorded in the access log.

- **A credential can no longer be moved between policy tiers to escape the
  group gate.** `policy` is a writable field, and the gate originally applied
  only to updates carrying `secret_data`. So a user in `lab`'s groups but not
  `production`'s could be refused a reveal on a production credential, `PATCH`
  its `policy` to `lab` — an update with no material, and therefore ungated —
  and reveal it. Credential paths are UUID-derived under one shared prefix, so
  the receiving tier's AppRole reads the same secret; layer 2 and layer 3 both
  fell to one request that never touched material. The gate now runs on every
  update of an existing credential, against the **committed** row: NetBox's
  `ValidatedModelSerializer` and Django's `ModelForm` both mutate the instance
  before the check would see it, so `credential.policy` at that point is the
  incoming tier rather than the one the caller must satisfy. A deployment whose
  permissions carried per-policy constraints was never exposed — `change` on a
  production credential returned `404` — so this protects deployments relying
  on group membership alone.
- **Replacing secret material now requires `rotate_credential`, whatever verb
  it arrives on.** `PUT`, `PATCH`, and the bulk list endpoint all reach
  `perform_update()` under `change_credential`, and a `secret_data` key in that
  body wrote a new version — so a principal deliberately denied rotation could
  still inject replacement credentials or take an integration offline. The UI
  edit form had the same gap, including its staged-rotation path. Metadata-only
  edits still need only `change_credential`, which is the point of the split.

- **Deleting a credential no longer destroys its material before the deletion
  commits.** The `pre_delete` signal did the irreversible half first, so any
  later failure in the same transaction restored the row and left it pointing
  at material that no longer existed. `perform_bulk_destroy()` puts N deletions
  in one transaction, which made that routine rather than exotic. Destruction
  is now a `post_delete` handler deferred with `transaction.on_commit`, and the
  audit entry records the credential by snapshot rather than by a foreign key
  that no longer resolves.
- **Constrained permissions are enforced against the result of a write, not
  only its starting point.** These viewsets override
  `perform_create`/`perform_update` to thread the material write through
  `store_credential`, and dropped NetBox's post-save `_validate_objects()`
  check along with the rest of its implementation — so a constrained
  `add_credential` grant could create a credential outside its allowed policy,
  and a constrained `change_credential` grant could move an existing one out of
  scope. A rotate constraint compounded it: checking only the pre-update row
  meant a constraint scoped to `lab` was satisfied by a `PATCH` that
  simultaneously moved the credential to `prod` and wrote the new material
  through prod's policy and AppRole. Both ends are now checked, from inside the
  compensated region so a refusal cannot strand an OpenBao write.

- **Bulk updates carrying `secret_data` are refused.** `BulkUpdateModelMixin`
  wraps the batch in one transaction and rolls all of it back if a later item
  fails, while the write-path compensator only fires for the exception raised
  inside its own atomic block — so an early item's OpenBao write survived while
  its row and its audit entry disappeared. That residue is worse than an
  orphan: unaudited, colliding with the next check-and-set, and on a credential
  with no `live_kv_version` it becomes the value served as latest. The same
  window in the UI edit flow is closed by moving the post-save permission check
  inside `store_credential`'s atomic block.

### Fixed

- The audit log's REST endpoint returned **500** for `?brief=true`, `?fields=`,
  and `?omit=`. NetBox's `BaseViewSet` passes those down as serializer keyword
  arguments and a plain DRF `ModelSerializer` does not accept them. Introduced
  by adopting `NetBoxReadOnlyModelViewSet` above; the serializer now extends
  `BaseModelSerializer`.

- Documentation overstated what per-tier AppRoles provide. They were described
  as a layer a NetBox permission bug could not pass, and as making the two
  NetBox gates survivable. They are not: the backend selects the AppRole from
  the credential's *own* policy, so a NetBox bug that yields a `prod-core`
  credential reads it with the `prod-core` AppRole — the identity authorized
  for that path. What they genuinely buy is blast radius, and the docs now say
  that instead, across `security.md`, `configuration.md`, the architecture
  pages, the policy-tier guide, and the model and backend docstrings.

- Documentation claimed `CredentialVerifyJob` reports orphaned material. It
  cannot: the job iterates existing credential rows, so it detects a row whose
  secret is missing and is blind to a secret whose row is missing. Corrected
  everywhere, with the `ORPHANED SECRET` log line named as the only current
  signal.

- The field check that CI reports as a restatement of the central invariant was
  a name heuristic dressed as a guarantee. It is now an **allowlist**: every
  `Credential` field is enumerated in `scripts/check_no_secret_fields.py`
  having been reviewed as non-secret, and anything else fails whatever it is
  called. A denylist of secret-sounding names passed `material =
  models.JSONField()` and `payload = models.JSONField()` outright, and missed
  annotated and tuple-assigned targets entirely. `tests/test_security.py`
  imports the same allowlist and applies it to the live model and to the
  serializer's read representation.

### Added

- A Material for MkDocs documentation site (`mkdocs.yml`, `docs/`), covering
  the architecture, operator how-to guides, and a code reference generated from
  the source. Build it with `pip install -e '.[docs]' && mkdocs build`.
- `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.
- A GitHub Actions workflow mirroring the existing static-checks job, so pull
  requests opened on GitHub are gated the same way.

### Changed

- The package version is single-sourced from `netbox_openbao.__version__`
  instead of being duplicated in `pyproject.toml`.
- Compatibility is now certified on exact NetBox `v4.7.0-beta2` while the
  NetBox 4.6 floor remains a required regression target. Development setup
  examples now include beta2's validated host and secret configuration.

## [0.1.0]

Initial release. Early alpha.

### Added

- Five models: `SecretEngine`, `CredentialPolicy`, `Credential`,
  `CredentialAssignment`, `CredentialAccessLog`, plus operator-defined
  `CredentialTypeSchema`.
- A `SecretBackend` abstraction with OpenBao, HashiCorp Vault, and broker
  implementations, verified against live servers by one shared suite.
- A REST API whose `reveal` action is a permission of its own, JSON-only,
  `no-store`, and rate limited.
- Staged rotation — write, verify, promote — so replacing a credential never
  breaks a running consumer and always has a way back.
- Server-side SSH key generation, quick-add SSH access for devices and VMs,
  credential type schemas and extractors, five background jobs, and an
  importer for `netbox-secrets`.

[Unreleased]: https://github.com/emersonfelipesp/netbox-openbao/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/emersonfelipesp/netbox-openbao/releases/tag/v0.1.0
