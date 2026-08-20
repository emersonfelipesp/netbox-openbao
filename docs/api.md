# REST API

Base path: `/api/plugins/openbao/`.

All models expose standard NetBox CRUD via `NetBoxModelViewSet`, so `pynetbox`
and `netbox-cli` work unmodified.

| Endpoint | Purpose |
|---|---|
| `GET/POST /engines/` | Secret engines |
| `GET /engines/{id}/health/` | Probe and record engine status |
| `GET/POST /policies/` | Credential policy tiers |
| `GET/POST /credentials/` | Credential inventory |
| `GET`/`POST` `/credentials/{id}/reveal/` | **Resolve material** — needs `view_credential` + `reveal_credential` |
| `POST /credentials/{id}/rotate/` | Write a new version — needs `view_credential` + `rotate_credential` and a write-enabled token |
| `GET /credentials/{id}/versions/` | Version metadata, never values |
| `GET/POST /assignments/` | Credential ↔ object bindings |
| `GET /access-logs/` | Audit trail (read-only) |

## Writing material

`secret_data` is accepted on create and update and is **write-only** — it never
appears in any response.

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/credentials/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "core-sw-01 admin",
        "credential_type": "ssh-keypair",
        "policy": 3,
        "username": "admin",
        "secret_data": {"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
      }'
```

`engine` may be omitted — it defaults to the policy's engine. The response
carries the extracted public material (`public_key`, `fingerprint`,
`key_type`) and no private material.

Creates use `cas=0` against OpenBao, so a create can never silently overwrite
material already at that path. Updates that include `secret_data` are treated
as rotations and check-and-set against the recorded `kv_version`.

## Revealing

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/142/reveal/?reason=CHG-1234'
```

```json
{
  "id": 142,
  "uuid": "0d2f...",
  "name": "core-sw-01 admin",
  "credential_type": "ssh-keypair",
  "username": "admin",
  "kv_version": 3,
  "ttl": 300,
  "secret_data": {"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
}
```

Contract:

- Requires `netbox_openbao.reveal_credential`, which is **separate from
  `view_credential`**. Object-permission constraints apply, and a constrained
  miss returns `404` rather than `403` so the response does not confirm the
  credential exists.
- `POST` is accepted as well as `GET`, which keeps the reason out of the URL
  and the access log of every intermediary.
- `reason` is mandatory when the credential's policy sets `require_reason`.
- `version` selects an older KV version.
- JSON only — the browsable renderer is removed — and `Cache-Control: no-store`.
- Rate limited per user; default `30/hour`.
- `ttl` is the lower of the plugin's `reveal_ttl` and the policy's
  `max_reveal_ttl`. It is advice to the consumer, not an enforced expiry.
- Every call is audited, successful or not.

## Filtering

The point of keeping non-secret attributes in NetBox is that these cost one
indexed query and **zero OpenBao reads**:

```
?expires_within_days=30           # renewal dashboard
?expires_before=2026-12-31T00:00:00Z
?has_expiry=true
?fingerprint=SHA256:abc...        # where is this key deployed?
?credential_type=x509-keypair&status=active
?policy=prod-core
?assigned_object_type=dcim.device&assigned_object_id=88
?purpose=login
?q=core-sw-01                     # name, username, fingerprint, subject, serial
```

## Permissions on the custom actions

`reveal` and `rotate` accept POST, and NetBox's default API permission map
treats POST as *create* (`add_<model>`). Left alone that would mean anyone who
can rotate can already create, and a role holding only `rotate_credential`
could not rotate at all. The plugin remaps POST to `view_<model>` for these two
actions, so the operative permission is the dedicated one:

| Action | Required |
|---|---|
| `reveal` | `view_credential` + `reveal_credential` |
| `rotate` | `view_credential` + `rotate_credential`, write-enabled token |
| `versions` | `view_credential` |

Object-permission constraints apply to all three through `restrict()`.

## Errors

| Status | Meaning |
|---|---|
| `400` | Payload does not match the credential type's schema |
| `403` | Permission denied, or the policy's group gate refused |
| `404` | No such credential, **or** one your constraints exclude |
| `409` | Check-and-set conflict — a concurrent write intervened |
| `429` | Reveal rate limit exceeded |
| `502` | OpenBao unreachable, sealed, or rejected the plugin's credentials |
| `503` | Engine unavailable |

Error bodies never contain OpenBao's response text: a `403` from OpenBao can
enumerate policy rules, so backend errors are re-raised as fixed strings.
