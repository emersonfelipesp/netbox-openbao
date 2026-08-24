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

- The public CI workflow's dependency-free field check tested three of the five
  forbidden tokens and only plain assignments, so `secret_data =
  models.JSONField()` or an annotated `token: str = ...` would have passed
  every check it advertised. It is now `scripts/check_no_secret_fields.py`,
  which handles both assignment forms and scans every model, and whose token
  list is imported by `tests/test_security.py` so the two cannot drift.

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
