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
