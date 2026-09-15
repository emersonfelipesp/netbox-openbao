# Administer OpenBao secret engines

The secret-engine workspace gives NetBox operators a cluster-scoped Web UI and
REST API for OpenBao 2.6.x mount lifecycle, first-class KV v1/v2, transit,
database, SSH, and TOTP journeys, and the reviewed generic mounted-operation
fallback. It
uses the cluster's configured service identity; an OpenBao token is never sent
to the browser or accepted from an API caller.

## Before you begin

The OpenBao cluster must be initialized, unsealed, and reachable through its
configured direct transport. Broker mode fails closed until the broker
implements the same administration contract. Grant only the object-constrained
permissions required for the operator's role:

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
- TOTP key, code-generation, and validation operations.

KV diff reads two explicitly selected positive versions during one request and
returns both values for operator comparison. It does not persist either value.
Browse and list journeys fix the upstream `list=true` query themselves; callers
cannot override it. If two valid mount names collapse to the same OpenBao
OpenAPI parameter name, such as `team-db` and `team_db`, the typed catalog
omits both mounts and execution fails closed until the collision is removed.
Destructive journeys require the dedicated engine permission and the exact
confirmation displayed after the mount and resource path are compiled.

Explorer results may contain secret material. Copy required values directly to
approved custody and select **Clear result**. The page also clears the result
after five minutes and when it is left. Responses use `Cache-Control: no-store`;
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

## Compatibility and limitations

The reviewed execution contract starts at OpenBao 2.6.2 and accepts only the
2.6.x release line. It supports advertised GET, LIST, POST, PUT, PATCH, and
DELETE operations for KV and plugin-style mounted schemas when their templates,
required path parameters, query parameters, and bodies satisfy the reviewed
grammar. Merely advertised operations outside that grammar remain display-only.
KV, transit, database, SSH, and TOTP are first-class typed journeys. PKI and
Kubernetes credentials remain planned typed workspaces; their reviewed generic
mounted operations remain available when the runtime schema and permissions
admit them.
