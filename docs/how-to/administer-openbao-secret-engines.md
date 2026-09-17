# Administer OpenBao secret engines

The secret-engine workspace gives NetBox operators a cluster-scoped Web UI and
REST API for OpenBao 2.6.x mount lifecycle, first-class KV v1/v2, transit,
database, SSH, TOTP, PKI, and Kubernetes journeys, and the reviewed generic mounted-operation
fallback. It
uses the cluster's configured service identity; an OpenBao token is never sent
to the browser or accepted from an API caller.

## Before you begin

The OpenBao cluster must be initialized, unsealed, and reachable through its
configured direct or broker transport. Broker mode requires all six
administration families on the instance and an exact version-and-digest match
for the bounded broker contract. Grant only the object-constrained permissions
required for the operator's role:

| Permission | Capability |
|---|---|
| `view_secret_engines_openbaocluster` | List mounts and read mount configuration and tuning metadata |
| `manage_secret_engines_openbaocluster` | Enable, tune, and remount engines |
| `disable_secret_engines_openbaocluster` | Disable an entire engine |
| `explore_secret_operations_openbaocluster` | Load the classified mounted-operation catalog |
| `execute_secret_operations_openbaocluster` | Run reviewed non-destructive writes |
| `delete_secret_operations_openbaocluster` | Delete or destroy mounted resources |
| `reveal_secret_operations_openbaocluster` | Run reads whose response can contain secret material |
| `reveal_kv_secrets_openbaocluster` | Browse and read KV data, metadata, versions, and diffs |
| `manage_kv_secrets_openbaocluster` | Write, patch, undelete, and configure KV data |
| `destroy_kv_versions_openbaocluster` | Delete or irreversibly destroy KV versions and metadata |
| `use_transit_openbaocluster` | Encrypt, decrypt, rewrap, sign, verify, hash, HMAC, and generate random data |
| `manage_transit_keys_openbaocluster` | Create, configure, and rotate transit keys |
| `delete_transit_keys_openbaocluster` | Delete transit keys after exact confirmation |
| `generate_database_credentials_openbaocluster` | Generate dynamic or static database credentials |
| `manage_database_roles_openbaocluster` | Manage database connections, dynamic roles, and static roles |
| `delete_database_resources_openbaocluster` | Delete database connections, dynamic roles, and static roles after exact confirmation |
| `rotate_database_credentials_openbaocluster` | Rotate root/static credentials or reset a connection after confirmation |
| `issue_ssh_credentials_openbaocluster` | Issue OTP credentials, sign keys, and use SSH lookup/verification |
| `manage_ssh_roles_openbaocluster` | Manage SSH roles |
| `delete_ssh_roles_openbaocluster` | Delete SSH roles after exact confirmation |
| `generate_totp_codes_openbaocluster` | Generate and validate TOTP codes |
| `manage_totp_keys_openbaocluster` | Create and inspect TOTP keys |
| `delete_totp_keys_openbaocluster` | Delete TOTP keys after exact confirmation |
| `view_pki_openbaocluster` | Read PKI configuration, issuers, keys, roles, and certificates |
| `manage_pki_configuration_openbaocluster` | Manage PKI cluster, CRL, issuer, URL, ACME, and auto-tidy configuration |
| `manage_pki_issuers_openbaocluster` / `delete_pki_issuers_openbaocluster` | Manage or delete PKI issuers |
| `manage_pki_keys_openbaocluster` / `generate_pki_keys_openbaocluster` / `delete_pki_keys_openbaocluster` | Import/manage, generate, or delete PKI keys through separate grants |
| `manage_pki_roles_openbaocluster` / `delete_pki_roles_openbaocluster` | Manage or delete PKI issuance roles |
| `issue_pki_certificates_openbaocluster` | Issue and sign certificates and intermediate requests |
| `revoke_pki_certificates_openbaocluster` | Revoke certificates after exact confirmation |
| `rotate_pki_roots_openbaocluster` / `delete_pki_roots_openbaocluster` | Generate/rotate roots or delete every issuer and key through separate confirmed grants |
| `tidy_pki_openbaocluster` | Start or cancel PKI tidy work after exact confirmation |
| `view_kubernetes_engine_openbaocluster` | Read Kubernetes configuration and roles |
| `manage_k8s_configuration_openbaocluster` / `delete_k8s_configuration_openbaocluster` | Configure or remove the Kubernetes connection through separate grants |
| `manage_kubernetes_roles_openbaocluster` / `delete_kubernetes_roles_openbaocluster` | Manage or delete Kubernetes credential roles |
| `generate_k8s_credentials_openbaocluster` | Generate request-scoped Kubernetes credentials |

The OpenBao service policy remains a separate authorization boundary. A NetBox
permission does not grant an upstream capability that the service identity
lacks.

## Use the Web UI

Open the cluster and select **Secret engines**. Refresh mounted engines before
changing lifecycle state. Enable and tune requests accept only reviewed,
bounded configuration fields. Remounting and disabling require the exact
cluster-specific confirmation shown by the page.

Load the classified operation catalog before using the explorer. The page
offers only operations that are both advertised by the current OpenBao 2.6.x
document and admitted by the plugin's fixed method, path-template, operation-ID,
and mounted-path registry. Choose a live
non-system mount, complete the displayed resource, query, and body fields, and
provide an operational reason. Destructive operations display an exact
confirmation that binds the HTTP method, compiled path, and cluster slug.

Prefer **First-class engine journeys** when the task appears there. The catalog
is the intersection of a static OpenBao 2.6.2 journey registry, the selected
mount's exact runtime OpenAPI operations, its KV version when applicable, and
the current user's object-constrained permission. It includes:

- KV v1/v2 browse, read, write, patch, metadata, configuration, version diff,
  delete, undelete, and irreversible destroy operations;
- transit key lifecycle plus encrypt, decrypt, rewrap, sign, verify, hash,
  HMAC, and random generation;
- database connection, dynamic-role, static-role, credential, rotation, and
  reset operations;
- SSH role, OTP credential, CA signing, lookup, public-key, and verification
  operations; and
- TOTP key, code-generation, and validation operations;
- PKI cluster, CRL, ACME, issuer, key, role, certificate, issuance, signing,
  legacy and multi-issuer root/intermediate, delete-all-root, revocation, and
  tidy operations; and
- Kubernetes connection, role, and credential-generation operations.

KV diff reads two explicitly selected positive versions during one request and
returns both values for operator comparison. It does not persist either value.
Browse and list journeys fix the upstream `list=true` query themselves; callers
cannot override it. If two valid mount names collapse to the same OpenBao
OpenAPI parameter name, such as `team-db` and `team_db`, the typed catalog
omits both mounts and execution fails closed until the collision is removed.
Destructive journeys require the dedicated engine permission and the exact
confirmation displayed after the mount and resource path are compiled.

Explorer and first-class results may contain secret material. Copy required values directly to
approved custody and select **Clear result**. PKI generation, issuance, and Kubernetes
credential journeys expose a request-scoped **Download result** action when the
journey returns material. The JSON file is created only after the operator clicks
the button, its object URL is revoked immediately, and no server-side copy is retained.
The page also clears both result surfaces and cancels the prior expiry timer
before a journey selection, catalog reload, new request, failed request, or
unrelated advanced operation. It clears results after five minutes and when
the page is left. Responses use `Cache-Control: no-store`;
the browser workspace does not use cookies, local storage, session storage, or
URLs for material.

## Use the REST API

Cluster actions are below the normal OpenBao cluster detail endpoint:

```text
GET  /api/plugins/openbao/clusters/{id}/secret-engines/
POST /api/plugins/openbao/clusters/{id}/secret-engines/configuration/
POST /api/plugins/openbao/clusters/{id}/secret-engines/tuning/
POST /api/plugins/openbao/clusters/{id}/secret-engines/enable/
POST /api/plugins/openbao/clusters/{id}/secret-engines/tune/
POST /api/plugins/openbao/clusters/{id}/secret-engines/remount/
POST /api/plugins/openbao/clusters/{id}/secret-engines/remount-status/
POST /api/plugins/openbao/clusters/{id}/secret-engines/disable/
GET  /api/plugins/openbao/clusters/{id}/secret-operations/
POST /api/plugins/openbao/clusters/{id}/secret-operations/execute/
GET  /api/plugins/openbao/clusters/{id}/secret-engine-journeys/
POST /api/plugins/openbao/clusters/{id}/secret-engine-journeys/execute/
```

The execution request must echo the latest catalog's `capability_digest` and
select its `operation_key`. The server reloads the document, checks that digest,
resolves the operation again, verifies declared fields, primitive JSON types,
and the live mount, and compiles the upstream path. Callers cannot select an
origin, raw URL, method,
headers, namespace, identity, or redirect behavior.

```json
{
  "operation_key": "secret_mount_path :: kv-read-data-path :: GET /{secret_mount_path}/data/{path}",
  "capability_digest": "<64 lowercase hexadecimal characters>",
  "mount_path": "secret",
  "resource_path": "applications/database",
  "path_parameters": {},
  "query": {},
  "body": {},
  "reason": "Validate the application credential"
}
```

Never retry a mutation after a transport or response-parsing failure. Its
upstream outcome may be unknown; refresh the mount or resource state and
reconcile it first.

First load `secret-engine-journeys/`, retain its `capability_digest`, and select
one returned `journey_id` with its returned `mount_path`. The execution route
reloads the runtime schema, rejects a stale digest or cross-mount journey,
validates only schema-declared typed fields, checks the journey's dedicated
permission, and compiles the path server-side.

```json
{
  "journey_id": "transit.encrypt",
  "capability_digest": "<64 lowercase hexadecimal characters>",
  "mount_path": "transit",
  "resource_path": "",
  "path_parameters": {"name": "payments"},
  "query": {},
  "body": {"plaintext": "Ym91bmRlZC1pbnB1dA=="},
  "reason": "Encrypt an application payload"
}
```

## Operate PKI safely

Treat generated private keys and signed certificates as custody-bearing material.
Download or copy them once into the approved certificate/key store, verify the
stored copy, and clear the browser result. Do not use NetBox audit records as a
backup: request and response bodies are deliberately excluded.

Root generation and rotation, key generation, issuer/key/role deletion,
certificate revocation, and tidy mutations require dedicated permissions and
the exact confirmation displayed by the workspace. Before rotation, confirm
that relying parties trust the new chain and that the previous issuer remains
available for the intended overlap. Before revocation or tidy, capture the
serial, issuer, reason, retention window, and expected CRL impact. OpenBao
storage snapshots—not exported browser results—are the recovery boundary for
issuer, key, role, certificate, and revocation state.

If an issuance, rotation, revocation, or tidy response is lost, do not retry it.
Read the issuer, key, certificate, CRL, or tidy status and reconcile the result
first. During an incident, stop new issuance if custody is uncertain, preserve
the relevant audit request ID, rotate or revoke through the typed journey, and
validate CRL distribution before restoring service. Before retiring a PKI
mount, inventory active chains and certificates, preserve required audit and
snapshot evidence, migrate relying parties, and disable the mount only through
the separately confirmed lifecycle action.

## Operate Kubernetes credentials safely

Configure the Kubernetes API endpoint, CA material, and reviewer service-account
JWT through the typed configuration journey. Limit each OpenBao role to the
required namespaces, service account or role rules, audiences, and TTLs. Generated
service-account tokens are request-scoped secret material: transfer them directly
to the intended workload or approved custody, then clear the result. They are not
stored in NetBox, its audit log, browser storage, or URLs.

If credential generation has an unknown outcome, inspect Kubernetes and OpenBao
state before retrying. For suspected reviewer-token or generated-token exposure,
remove or rotate the Kubernetes credential at its source, update OpenBao
configuration, and validate a newly generated short-lived credential. Before
retiring the integration, stop consumers, delete roles with explicit confirmation,
remove the engine configuration, and retain only the required audit evidence.

## Compatibility and limitations

The reviewed execution contract starts at OpenBao 2.6.2 and accepts only the
2.6.x release line. It supports advertised GET, LIST, POST, PUT, PATCH, and
DELETE operations for KV and plugin-style mounted schemas when their templates,
required path parameters, query parameters, and bodies satisfy the reviewed
grammar. Merely advertised operations outside that grammar remain display-only.
KV, transit, database, SSH, TOTP, PKI, and Kubernetes are first-class typed
journeys. Unsupported future OpenBao operations remain display-only until their
method, path, field, authorization, confirmation, and material-handling contracts
are reviewed.
