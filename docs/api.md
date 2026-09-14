# REST API

Base path: `/api/plugins/openbao/`.

Inventory models expose standard NetBox CRUD via `NetBoxModelViewSet`, so
`pynetbox` and `netbox-cli` work unmodified. Access logs are read-only, and
internal automation resolution receipts have no CRUD endpoint.

| Endpoint | Purpose |
|---|---|
| `GET/POST /clusters/`, `GET/PATCH/DELETE /clusters/{id}/` | Administrative cluster inventory; never authentication material |
| `GET /clusters/{id}/health/` | Probe cluster health, persist safe observed status, and write an administration audit record |
| `GET /clusters/{id}/capabilities/` | Normalize bounded OpenAPI metadata; requires `discover_openbaocluster` and never makes an operation executable |
| `GET /clusters/{id}/state/` | Read typed initialization, seal, HA, leader, and Raft state |
| `POST /clusters/{id}/initialize/` | Initialize once and return custody material once; JSON-only and `no-store` |
| `POST /clusters/{id}/unseal/` | Submit one unseal share or reset accumulated progress |
| `POST /clusters/{id}/seal/` | Seal an initialized active cluster |
| `POST /clusters/{id}/raft/remove-peer/` | Remove a non-leader peer after index and quorum checks |
| `GET/POST /clusters/{id}/raft/snapshot/` | Stream an active-node Raft snapshot; session users require a confirmed CSRF-protected POST, while API tokens may use GET |
| `POST /clusters/{id}/raft/snapshot/restore/` | Stream a bounded snapshot into normal restore |
| `POST /clusters/{id}/raft/snapshot/restore-force/` | Stream a bounded snapshot into force restore under a separate permission |
| `GET/POST /settings/`, `GET/PATCH/DELETE /settings/{id}/` | Singleton runtime configuration; deletion is refused while any credential exists and requires the standard `OpenBaoSettings` model permissions |
| `GET/POST /engines/` | Secret engines |
| `GET /engines/{id}/health/` | Probe and record engine status |
| `GET/POST /policies/` | Credential policy tiers |
| `GET/POST /credentials/` | Credential inventory |
| `GET`/`POST` `/credentials/{id}/reveal/` | **Resolve material** — needs `view_credential` + `reveal_credential` |
| `POST /credentials/{id}/rotate/` | Write a new version and make it live immediately |
| `POST /credentials/{id}/stage/` | Write a new version **without** putting it into service |
| `POST /credentials/{id}/promote/` | Put the staged version into service |
| `POST /credentials/{id}/discard/` | Destroy the staged version, leaving the live one untouched |
| `GET /credentials/{id}/versions/` | Version metadata, never values |
| `GET/POST /assignments/` | Credential ↔ object bindings |
| `GET /access-logs/` | Audit trail (read-only) |
| `GET /administration-logs/` | Administrative audit trail (read-only) |

## Cluster administration foundation

Cluster inventory separates an OpenBao API endpoint and namespace from an
individual `SecretEngine` mount. The list and detail representations include
only connection configuration and observed metadata. Authentication material
comes from the cluster-derived environment prefix and is never serialized.

`GET /clusters/{id}/capabilities/` requires both normal API authentication and
the object-constrainable `netbox_openbao.discover_openbaocluster` action. Its
response shape is:

```json
{
  "openapi_version": "3.0.2",
  "product_version": "2.6.2",
  "digest": "<sha256>",
  "classified_count": 1,
  "unclassified_count": 0,
  "operations": [
    {
      "operation_id": "sysHealth",
      "operation_key": "GET /sys/health",
      "method": "GET",
      "path_template": "/sys/health",
      "summary": "Read health",
      "tags": ["system"],
      "family": "cluster",
      "risk_level": "read",
      "response_class": "public-metadata",
      "required_permission": "netbox_openbao.discover_openbaocluster",
      "classified": true,
      "executable": false
    }
  ]
}
```

The endpoint is metadata discovery, not a generic proxy. It accepts no caller
path, method, headers, or body. Every operation is returned with
`executable=false`; unknown operations have no required permission and remain
unclassified. The response is `no-store`, and every success or failure is
written synchronously to `OpenBaoAdministrationLog`. See the
[administration-plane contract](architecture/administration-plane.md).

## Cluster lifecycle and Raft requests

Cluster lifecycle actions require `view_openbaocluster` plus the dedicated
object permission named for the action. JSON mutations include a non-empty
`reason` and the exact `confirmation` shown by the Web UI. Initialization uses
either `secret_shares` plus `secret_threshold`, or `recovery_shares` plus
`recovery_threshold`; the two modes cannot be mixed. Optional PGP key arrays
must contain exactly one key per configured share. Each key is a standard-base64
binary OpenPGP public-key export. The complete export, binding signatures,
explicit encryption flags, and practical encryption capability are validated
before OpenBao is contacted.

Initialization responses contain custody material and use the JSON renderer
only. They are marked `Cache-Control: no-store`. The plugin never persists or
audits the response. If the initialization request loses its response, the API
does not retry: re-read cluster state and enter incident recovery, because a
successful retry could never reproduce the original keys.

Snapshot restore does not use multipart parsing. Send exactly
`application/octet-stream`, a valid `Content-Length` from 1 through 536870912,
and these metadata headers:

| Header | Value |
|---|---|
| `X-OpenBao-Reason` | Operator or change reason |
| `X-OpenBao-Confirmation` | `RESTORE SNAPSHOT <cluster-slug>` or `FORCE RESTORE SNAPSHOT <cluster-slug>` |
| `X-OpenBao-Cluster-ID` | Cluster ID from the fresh state response |
| `X-OpenBao-Raft-Index` | Configuration index from the fresh state response |

The server checks the cluster ID and Raft index again before reading the body,
requires an initialized and unsealed Raft cluster, and refuses an HA standby.
Normal and force restore use different URLs and different permissions. Transfer
errors have unknown outcome and are never retried automatically. See the
[cluster administration runbook](how-to/administer-openbao-cluster.md).

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
| `rotate`, `stage`, `promote`, `discard` | `view_credential` + `rotate_credential`, write-enabled token |
| `versions` | `view_credential` |

Object-permission constraints apply to all three through `restrict()`.

## Staged rotation

`rotate` replaces material and makes it live in one step. That is fine for a
credential nothing depends on yet, and wrong for one deployed to hundreds of
hosts: there is no verification step and no way back except reading an old
version by number.

`stage` writes the replacement and leaves consumers on the current version:

```bash
curl -X POST .../credentials/142/stage/ -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"secret_data": {"private_key": "..."}}'
```

```json
{"id": 142, "status": "staged", "kv_version": 7, "live_kv_version": 6, "has_staged_version": true}
```

Every `reveal` still returns version 6 while this is true. Deploy the new key,
confirm it works, then:

```bash
curl -X POST .../credentials/142/promote/ -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"verified": true, "note": "confirmed on core-sw-01"}'
```

If it does not work, `discard` removes **only** the staged version — the live
one is never touched — and the credential returns to `active`.

`verified` and `note` are recorded in the access log. Actually testing the
credential against a device is out of scope for this plugin; this is where the
record that someone did lives.

### Three version numbers, three meanings

| Field | Meaning |
|---|---|
| `kv_version` | Highest version ever written. Check-and-set compares against this. |
| `live_kv_version` | What consumers are served. Empty means "latest". |
| `staged_kv_version` | A candidate awaiting a decision. Empty when none. |

`kv_version` and `live_kv_version` legitimately diverge after a discard —
OpenBao's version counter never goes backwards — which is why "is something
staged?" has its own field rather than being inferred from a comparison.

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
## Execution-bound automation

`POST /api/plugins/openbao/credentials/resolve-automation/` accepts a signed RPC
dispatch lease, execution ID, step ID, and frozen reference name. It never
accepts a caller-selected actor or raw credential reference. See
[Automation resolution](automation-resolution.md) for the exact request,
response, permission, version and one-use retry contract.
