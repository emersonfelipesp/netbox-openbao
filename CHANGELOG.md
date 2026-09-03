# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- **A system check reporting `PLUGINS_CONFIG` keys the settings row supersedes.**
  Once a row exists it is authoritative and a key left in `configuration.py` is
  silently ignored — an operator edits a value they can see and observes nothing.
  The check names them, and the settings page shows the same list. Interval keys
  are excluded because they genuinely are still read from the file.

  Run as a Django system check rather than from `AppConfig.ready()`: querying the
  database during app initialisation earns Django's own warning about it, and on
  a fresh install the table does not exist yet.

- **Settings changes are audited.** `change_openbaosettings` can widen the reveal
  rate limit, which bounds how fast a leaked token drains the store, so the
  change is recorded in `CredentialAccessLog` with a new `configure` action as
  well as in NetBox's changelog — putting it in the same timeline as the reveals
  it governs. Written from a model signal, so it covers the REST API and
  management commands and not only the UI. Field names only, never values.


### Added

- **Configuration is now stored in the database and editable through the REST
  API and the CLI.** A singleton `OpenBaoSettings` row holds every runtime
  setting, exposed at `/api/plugins/openbao/settings/` — which is all `nbx`
  needs, so the CLI works without anything further.

  `PLUGINS_CONFIG` is **not** removed. It becomes three things: a **seed**, so a
  data migration copies whatever a deployment currently configures and upgrading
  changes nobody's behaviour; a **fallback**, so an installation with no row
  behaves exactly as before; and later a deprecation surface. Removing support
  for it outright would break every existing deployment and needs its own
  release cycle.

  Resolution is per-request memo, then the settings row, then `PLUGINS_CONFIG`,
  then the hard default. A sentinel preserves the no-row result within the
  request. The credentials panel is registered globally, so this read path runs
  on every object detail page in NetBox; memoising the complete row keeps five
  setting reads to one query rather than one query per key.

  A read never creates the row. It is created by the migration when effective
  non-default values need seeding, or by an explicit save, so a deployment with
  no row keeps `PLUGINS_CONFIG` reachable —
  which is also what lets the existing test suite go on configuring the plugin
  with `override_settings`.

  `reveal_rate_limit` is validated on save, so an unparseable rate is refused
  there rather than surfacing later as a failed credential reveal, where the
  rate limit is the last place anyone would look.

  The settings row holds **configuration only**. There is no AppRole, SecretID,
  or token field, and `scripts/check_no_secret_fields.py` now guards this model
  as well as `Credential`.

### Fixed

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
  validator now rejects unsafe legacy fallbacks during every credential path
  derivation.

- **The settings migration compares set-like configuration canonically.** A
  reordered list, tuple representation, or case-and-whitespace-only model label
  difference no longer creates an authoritative database row and accidentally
  disables later `PLUGINS_CONFIG` edits. Unsafe legacy path prefixes are not
  copied into a row that runtime validation would reject.

- **`rpc.py` called `get_config()` with no arguments**, against a signature
  requiring a key — a `TypeError` on the `provision_netbox_approle` dispatch
  path. The following line indexed the result as a dict, so a shape the function
  has never returned was expected. Now correct and covered by a test.

### Unchanged, deliberately

- **The five background-job intervals still come from `PLUGINS_CONFIG` and
  still require a restart.** `@system_job` reads its interval at import time and
  `rqworker` reads the resulting registry at worker startup, so switching only
  the model read would make a value revert at the next worker restart.
  The fields exist on the model so that work needs no second schema change, but
  presenting them as live before the rescheduling exists would be worse than
  leaving the current restart-required semantics visible.

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
  allowlist `CredentialAssignment` enforces. Until now the only way to widen
  that list was to hand-edit `PLUGINS_CONFIG`, so every integration was
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
