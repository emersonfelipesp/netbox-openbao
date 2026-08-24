# Your first credential

End to end, in about ten minutes: an engine, a policy tier, a credential, an
assignment, and a reveal. Assumes the plugin is
[installed](../installation.md) and OpenBao is reachable.

## 1. Make sure OpenBao is ready

You need a KV **v2** mount, a policy scoped to the plugin's prefix, and an
AppRole.

```bash
bao secrets enable -version=2 -path=secret kv

bao policy write netbox-lab - <<'POLICY'
path "secret/data/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
POLICY

bao auth enable approle
bao write auth/approle/role/netbox-lab \
    token_policies=netbox-lab token_ttl=1h token_max_ttl=4h
```

Both paths matter. `data/` alone lets the plugin write secrets but not the
`custom_metadata` every credential carries, so **every create fails** at the
metadata step and is then rolled back — which reads as "writes don't work"
rather than "the policy is half right". See [Scope an OpenBao
policy](../how-to/scope-openbao-policies.md).

## 2. Deliver the AppRole to NetBox

The engine's slug derives the environment prefix: `primary` →
`NETBOX_BAO_PRIMARY`. Nothing about this goes in `configuration.py` or the
database.

```bash
ROLE_ID=$(bao read -field=role_id auth/approle/role/netbox-lab/role-id)
SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/netbox-lab/secret-id)
```

```ini
# /etc/netbox/openbao.env   (chmod 600, owned by the NetBox user)
NETBOX_BAO_PRIMARY_ROLE_ID=...
NETBOX_BAO_PRIMARY_SECRET_ID=...
```

!!! warning "Apply it to the RQ worker too"

    `netbox.service` **and** `netbox-rq.service` both need the drop-in. The
    background jobs authenticate as well, and a worker without the material
    reports every engine as `unauthorized` — which looks like an OpenBao
    problem and is not.

Restart both after adding it.

## 3. Create the engine

**OpenBao → Secret engines → Add**, or:

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/engines/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "Primary",
        "slug": "primary",
        "backend": "openbao",
        "api_url": "https://bao.example.net:8200",
        "kv_mount": "secret",
        "kv_version": 2,
        "auth_method": "approle",
        "is_default": true
      }'
```

Check it resolved before going further:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://netbox.example.net/api/plugins/openbao/engines/1/health/
```

`{"status": "healthy", ...}` means the URL, TLS, and authentication all work.
Anything else: [Troubleshoot](../how-to/troubleshooting.md).

## 4. Create a policy tier

The tier is what maps NetBox authorization onto a real OpenBao policy.

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/policies/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "Lab",
        "slug": "lab",
        "engine": 1,
        "openbao_policy": "netbox-lab",
        "max_reveal_ttl": 300,
        "require_reason": false
      }'
```

For anything production, give the tier its **own** AppRole via
`approle_env_prefix` — that is the layer a NetBox-side permission bug cannot
get past. See [Set up a policy tier](../how-to/policy-tiers.md).

## 5. Create a credential

=== "API"

    ```bash
    curl -X POST https://netbox.example.net/api/plugins/openbao/credentials/ \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{
            "name": "core-sw-01 admin",
            "credential_type": "ssh-keypair",
            "policy": 1,
            "username": "admin",
            "secret_data": {
              "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
            }
          }'
    ```

    `engine` may be omitted — it defaults to the policy's engine.

=== "UI"

    **OpenBao → Credentials → Add.** Choose the type and the policy, then
    either paste the private key or tick **Generate a new keypair**.

=== "Device page (fastest)"

    **Add SSH access** on the device, which also creates the `ipam.Service`
    and both assignments. See [Grant a device SSH
    access](../quick-add-ssh.md).

The response carries the **extracted public material** and no private material:

```json
{
  "id": 1,
  "uuid": "0d2f…",
  "path": "netbox/credentials/0d2f…",
  "public_key": "ssh-ed25519 AAAA…",
  "fingerprint": "SHA256:2f9c…",
  "key_type": "ed25519",
  "kv_version": 1
}
```

That extraction is the point of the whole design — see [Credential
types](../architecture/credential-types.md).

## 6. Assign it to something

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/assignments/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "credential": 1,
        "assigned_object_type": "dcim.device",
        "assigned_object_id": 88,
        "purpose": "login",
        "is_primary": true
      }'
```

`is_primary` is unique per `(object, purpose)`, so *"which credential does
automation use to log in here?"* has exactly one answer.

The device's page now shows a **Credentials** panel — inventory only. Revealing
happens on the credential's own page, behind its own permission.

## 7. Grant the reveal permission

`reveal` is a permission of its own. Under **Administration → Permissions**,
create one with:

- Object types: **NetBox OpenBao › credential**
- Actions: **View** and **Reveal**
- Constraints (optional): `{"policy__slug": "lab"}`

That constraint means a production credential returns **404**, not 403 — a 403
would confirm it exists.

A role with **View** and not **Reveal** can inventory every credential in the
estate and read none. That is the normal grant for auditors, capacity planners,
and most automation.

## 8. Reveal it

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/1/reveal/?reason=CHG-1234'
```

In the UI, the **Reveal** panel on the credential page. It is a POST form, not
a link, so a secret is never fetched by a bookmark, a prefetch, or a history
replay.

Either way the access is recorded — who, when, from where, and the reason —
under **OpenBao → Access log**.

## What to do next

- Answer *"what expires in the next 30 days?"* with zero OpenBao reads:
  [Report on expiry](../how-to/expiry-reporting.md)
- Replace a key without breaking anything: [Rotate without breaking
  consumers](../how-to/rotate-a-credential.md)
- Understand what is actually guaranteed: [Security model](../security.md)
