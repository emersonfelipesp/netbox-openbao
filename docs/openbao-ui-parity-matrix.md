# OpenBao 2.6.2 UI parity closure matrix

The authoritative machine-readable manifest is
`netbox_openbao/administration/openbao-ui-v2.6.2.json`. This summary connects
the replacement requirement to implementation, tests, and operating guidance.
Every family is complete for the pinned OpenBao 2.6.2 router and runtime
contract; later minor releases require a new compatibility review.

| Requirement | Implementation | Primary tests | Operating documentation |
|---|---|---|---|
| Cluster session, login, direct OIDC, logout | `administration/authentication.py`, `api/authentication_views.py` | authentication focused/browser/live suites | [Authentication and MFA](how-to/administer-openbao-authentication.md) |
| Initialization, unseal, seal, HA, Raft, snapshots | `administration/cluster.py`, `api/views.py` | cluster focused and JavaScript suites | [Cluster administration](how-to/administer-openbao-cluster.md) |
| Auth methods and MFA | `administration/authentication.py`, `api/authentication_views.py` | authentication focused/browser/live suites | [Authentication and MFA](how-to/administer-openbao-authentication.md) |
| Mount lifecycle and classified API explorer | `administration/engines.py`, `api/engine_views.py` | engine focused/browser/live suites | [Secret engines](how-to/administer-openbao-secret-engines.md) |
| KV, transit, database, SSH, TOTP, PKI, Kubernetes | `administration/engine_journeys.py`, `api/engine_views.py` | engine focused/browser/live suites | [Secret engines](how-to/administer-openbao-secret-engines.md) |
| Policies, identity, aliases, OIDC, namespaces | `administration/access.py`, `api/access_views.py` | access focused/browser/live suites | [Access administration](how-to/administer-openbao-access.md) |
| Leases and guarded revocation | `administration/finalization.py`, `api/finalization_views.py` | finalization focused/browser/live suites | [Leases, tools, and UI configuration](how-to/administer-openbao-leases-tools.md) |
| Wrapping, hash, random data, token lookup | `administration/finalization.py`, `administration/backends.py` | finalization Python/JavaScript/live suites | [Leases, tools, and UI configuration](how-to/administer-openbao-leases-tools.md) |
| UI response headers and compatibility diagnostics | `openbao-final-v2.6.2.json`, `api/finalization_views.py` | parity and finalization focused/live suites | [Leases, tools, and UI configuration](how-to/administer-openbao-leases-tools.md) |
| Authorization, audit, no-store, unknown outcomes | Object permissions, administration audit, all administration API mixins | security, focused, browser, and live suites | [Administration architecture](architecture/administration-plane.md), [Security](security.md) |
| Migration, rollback, backup, restore, incidents, retirement | Migrations 0011 through 0020 and operator procedures | migration, compatibility, and full suites | Cluster and finalization runbooks |

The closure gates are:

1. `python scripts/check_openbao_ui_parity.py` validates all 19 route families,
   exact route/equivalence/evidence mappings, and evidence paths.
2. `openbao-final-v2.6.2.json` pins the final 17 API operations to upstream
   commit `dd9c19c37a878cf4a81b18efb8d6f0599c7da923`.
3. Runtime conformance fails for a missing, duplicate, unclassified, or stale
   matching contract.
4. Direct mode is live-tested. Broker mode fails closed until it advertises an
   equivalent reviewed contract.
5. Material responses are JSON-only, no-store, request-scoped, and absent from
   database and audit records.
