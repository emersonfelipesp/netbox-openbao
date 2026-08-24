# Scope an OpenBao policy

The plugin should not be able to read secrets it did not write. That is a
policy decision made in OpenBao, not in NetBox, and it is the layer that holds
when NetBox is wrong.

## The minimum that works

```hcl
path "secret/data/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

Substitute your mount for `secret` and your `path_prefix` for `netbox`.

!!! danger "Both paths are required, and forgetting the second one is subtle"

    KV v2 splits every secret across two API paths: `data/` holds versions, and
    `metadata/` holds version history **and `custom_metadata`**.

    Every credential this plugin writes carries `custom_metadata` — its NetBox
    ID, UUID, type, policy, and assignments — written as a second call
    immediately after the data write.

    With `data/` alone, the write succeeds and the metadata call is refused.
    The transaction unwinds, the [compensator](../architecture/write-path.md)
    removes the orphaned path, and the operator sees a failed create with no
    obvious cause. It reads as "writes don't work" rather than "the policy is
    half right".

## What each capability is for

| Capability | Needed by |
|---|---|
| `create`, `update` on `data/` | writing and rotating material |
| `read` on `data/` | `reveal` |
| `delete` on `data/` | discarding a staged version, and the write-path compensator |
| `create`, `update` on `metadata/` | `custom_metadata` on every write |
| `read` on `metadata/` | `versions`, and `CredentialVerifyJob` |
| `delete` on `metadata/` | destroying a credential's material when its row is deleted |
| `list` on `metadata/` | discovering orphans under the prefix |

## A read-only tier

A tier that may reveal but never write:

```hcl
path "secret/data/netbox/credentials/*" {
  capabilities = ["read"]
}
path "secret/metadata/netbox/credentials/*" {
  capabilities = ["read", "list"]
}
```

Credentials on this tier cannot be created or rotated through NetBox at all.
That is a legitimate posture for material another system owns and NetBox only
inventories and resolves.

## Two tiers, two AppRoles

This is the arrangement that makes `CredentialPolicy` more than a label.

```hcl
# netbox-lab
path "secret/data/netbox/credentials/*"     { capabilities = ["create","read","update","delete"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["create","read","update","delete","list"] }
```

```hcl
# netbox-prod-core — same paths, separate AppRole, separate SecretID delivery
path "secret/data/netbox/credentials/*"     { capabilities = ["create","read","update","delete"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["create","read","update","delete","list"] }
```

Because the plugin's paths are UUID-derived, the two policies cannot be
distinguished by path — the separation is in **which AppRole reaches which
policy**, and that is enough: a NetBox-side permission bug on a `prod-core`
credential still routes through the `prod-core` AppRole, and if that AppRole
was never delivered to this NetBox, the read simply fails.

→ [Set up a policy tier](policy-tiers.md)

!!! tip "If you want path-level separation, use separate mounts"

    Give each tier its own `SecretEngine` pointing at a different `kv_mount`,
    and scope each policy to that mount. Then the tiers differ by path as well
    as by AppRole, and an OpenBao policy can express the boundary directly.

## Do not grant the whole mount

```hcl
# Don't.
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
```

Every secret on the mount becomes readable by anything holding NetBox's
AppRole, including secrets NetBox has no row for and no audit trail about.
Scope to the prefix.

## Token lifetime

```bash
bao write auth/approle/role/netbox-prod \
    token_policies=netbox-prod \
    token_ttl=1h \
    token_max_ttl=4h
```

The plugin caches the token in Django's cache and discards it at **80% of the
lease**, so a token is never presented at the moment it expires. A short `ttl`
is cheap: re-authentication is one round-trip, amortised over an hour.

## Checking your work

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://netbox.example.net/api/plugins/openbao/engines/1/health/
```

`healthy` proves the URL, TLS, and authentication. It does **not** prove the
policy is right — `sys/health` needs no capabilities at all.

Create a throwaway credential and delete it again. That exercises every
capability in the table above, which is the only way to find out you forgot
`metadata/`.
