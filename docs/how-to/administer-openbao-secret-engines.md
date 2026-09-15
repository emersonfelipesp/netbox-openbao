# Administer OpenBao secret engines

The secret-engine workspace gives NetBox operators a cluster-scoped Web UI and
REST API for OpenBao 2.6.x mount lifecycle and the initial reviewed KV v2
mounted operations. It
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

## Compatibility and limitations

The reviewed execution contract starts at OpenBao 2.6.2 and accepts only the
2.6.x release line. It supports advertised GET, LIST, POST, PUT, PATCH, and
DELETE operations for KV and plugin-style mounted schemas when their templates,
required path parameters, query parameters, and bodies satisfy the reviewed
grammar. Merely advertised operations outside that grammar remain display-only.
Engine-specific guided journeys such as KV version history, PKI issuance,
database credentials, transit signing, and Kubernetes credentials remain
optimized typed workspaces layered over the generic reach.
