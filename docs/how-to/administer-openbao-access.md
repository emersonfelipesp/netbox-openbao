# Administer OpenBao policies, identity, OIDC, and namespaces

The **Policies and identity** workspace replaces the corresponding stable
OpenBao 2.6.2 Web UI routes with NetBox-authenticated, object-permissioned Web
UI and REST operations. It covers ACL and password policies, identity entities,
groups and aliases, entity merge, OIDC clients, keys, assignments, providers
and scopes, and namespace lifecycle.

NetBox authorizes the person and records the reason. OpenBao separately
authorizes the configured cluster service identity. Both boundaries must allow
an operation. The browser never receives or stores that service identity.

## Prerequisites

1. Configure an initialized, unsealed `OpenBaoCluster` that reports OpenBao
   2.6.2 through the reviewed 2.6.x line.
2. Configure the cluster service identity outside the database.
3. Grant `view_openbaocluster` and `view_access_openbaocluster`, constrained to
   the intended cluster objects.
4. Grant only the mutation permissions required by the operator role.

| Permission | Capability |
|---|---|
| `manage_policies_openbaocluster` | Create and update ACL or password policies |
| `delete_policies_openbaocluster` | Delete ACL or password policies |
| `generate_passwords_openbaocluster` | Generate one request-scoped password from a password policy |
| `manage_identity_openbaocluster` | Create and update entities, groups, aliases, and membership |
| `delete_identity_openbaocluster` | Delete identity resources |
| `merge_identity_openbaocluster` | Merge source entities into one destination entity |
| `manage_oidc_openbaocluster` | Create and update OIDC resources |
| `reveal_oidc_client_secrets_openbaocluster` | Read generated OIDC client credentials |
| `delete_oidc_openbaocluster` | Delete OIDC resources |
| `rotate_oidc_keys_openbaocluster` | Rotate an OIDC signing key |
| `manage_namespaces_openbaocluster` | Create and update child namespaces |
| `delete_namespaces_openbaocluster` | Remove child namespaces |

The OpenBao policy attached to the service identity must independently permit
the corresponding fixed upstream paths. A NetBox permission never expands the
service identity's OpenBao policy.

## Use the workspace

Open a cluster and select **Policies and identity**. The resource and operation
selectors contain only the intersection of:

- the static OpenBao 2.6.2 reviewed registry;
- the operations advertised by the cluster's current OpenAPI document; and
- the requesting user's constrained object permissions.

Select a resource and operation, enter its canonical identifier and typed
fields, and provide a reason. Policy documents and OIDC scope templates are
submitted as inert bounded strings. They are never evaluated or rendered as
HTML by NetBox.

Structured list and map fields use JSON. For example, an internal group can be
written with:

```json
{
  "member_entity_ids": ["11111111-1111-4111-8111-111111111111"],
  "metadata": {"owner": "network-automation"},
  "policies": ["device-read"],
  "type": "internal"
}
```

Entity and group aliases require the canonical UUID and the exact auth mount
accessor. OIDC assignments accept canonical entity and group UUIDs. Unknown
fields, malformed UUIDs, encoded identifiers, path traversal, and unsupported
runtime schemas fail closed.

## Destructive operations

Policy, identity, OIDC, and namespace deletion, entity merge, and OIDC key
rotation require a fresh impact preview. Review the current upstream resource,
then type the displayed confirmation exactly. The API binds execution to both
the capability digest and impact digest. If either changes, execution is
refused and a new preview is required.

Entity merge previews the destination and every source entity. Merge requests
accept canonical UUIDs only. After a successful merge, source entity IDs no
longer identify independent entities.

## Request-scoped material

Password generation and confidential OIDC client credentials are classified as
material. Their responses are `no-store`, available only to the dedicated
permission, and displayed in the current browser result for at most five
minutes. Changing the resource or operation, clearing the result, leaving the
page, or starting another request removes the prior result. Download is an
explicit action backed by a short-lived object URL that is immediately revoked.

Transfer generated material directly to approved custody. NetBox does not put
it in a model, session, cache, task, audit record, URL, exception, or browser
storage.

## Namespace boundary

`OpenBaoCluster.namespace` fixes the namespace header used by every request.
The namespace resource identifier is exactly one child segment relative to
that boundary; `/`, encoded separators, traversal, leading or trailing
whitespace, and absolute paths are rejected. To administer a different or
nested boundary, create or select the appropriately scoped cluster record and
service identity. A request cannot override the configured namespace header.

Namespace writes require an explicit `custom_metadata` object and replace the
complete upstream metadata value, including when the object is empty. The
workspace does not expose namespace `seal` or `pgp_keys` creation fields:
OpenBao can return new unseal shares for those requests, so they require a
separate custody workflow and permission boundary rather than a metadata
operation.

## Unknown outcomes

OpenBao mutation transport loss or a response that cannot be safely parsed has
an unknown outcome. The plugin returns a fixed do-not-retry response. Read the
resource again through the reviewed operation and reconcile current state
before deciding whether another mutation is safe.

## References

- [OpenBao policy API](https://openbao.org/api-docs/system/policies/)
- [OpenBao identity API](https://openbao.org/api-docs/secret/identity/)
- [OpenBao namespaces API](https://openbao.org/api-docs/system/namespaces/)
- [OpenBao 2.6.2 release](https://github.com/openbao/openbao/releases/tag/v2.6.2)
