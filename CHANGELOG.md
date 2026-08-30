# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
