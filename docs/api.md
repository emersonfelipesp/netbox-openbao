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
| `GET /clusters/{id}/secret-engines/` | List bounded secrets-engine mount metadata |
| `POST /clusters/{id}/secret-engines/configuration/` | Read one mount's public configuration metadata |
| `POST /clusters/{id}/secret-engines/tuning/` | Read one mount's public tuning metadata |
| `POST /clusters/{id}/secret-engines/enable/` | Enable a reviewed secrets-engine type with bounded configuration |
| `POST /clusters/{id}/secret-engines/tune/` | Tune a live mount with bounded OpenBao 2.6.2 fields |
| `POST /clusters/{id}/secret-engines/remount/` | Start a confirmed mount move and return its migration identifier |
| `POST /clusters/{id}/secret-engines/remount-status/` | Read bounded remount status metadata |
| `POST /clusters/{id}/secret-engines/disable/` | Disable a mount under separate permission and exact confirmation |
| `GET /clusters/{id}/secret-operations/` | Return the classified mounted-operation catalog and current capability digest |
| `POST /clusters/{id}/secret-operations/execute/` | Execute one reviewed mounted operation with stale-state, schema, permission, and confirmation checks |
| `GET /clusters/{id}/secret-engine-journeys/` | Return permission-filtered KV, transit, database, SSH, TOTP, PKI, and Kubernetes journeys proven by the live mount-specific schema |
| `POST /clusters/{id}/secret-engine-journeys/execute/` | Execute one typed journey with stale-digest, mount/version, field, permission, audit, and exact-confirmation checks |
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
      "operation_key": "global :: sysHealth :: GET /sys/health",
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

## Secrets-engine lifecycle and mounted operations

All secrets-engine actions use the cluster's configured service identity and
return `Cache-Control: no-store`; callers cannot supply an origin, raw path,
HTTP method, token, namespace, header, TLS policy, or redirect behavior. Object
permissions separate mount metadata reads, lifecycle management, whole-engine
disable, catalog discovery, ordinary mounted writes, mounted deletion or
destruction, and material-bearing reads. The exact permission names and request
examples are documented in the [secret-engine administration
runbook](how-to/administer-openbao-secret-engines.md).

Lifecycle mutations include a non-empty `reason`. Remount and disable also use
the exact cluster-bound confirmations shown by the Web UI. The server reloads
live mount state before every mutation. A transport failure, malformed success,
or HTTP 5xx after a mutation returns an explicit unknown outcome with
`X-OpenBao-Operation-Outcome: unknown`; clients must reconcile state and must
not retry automatically.

Mounted execution requires the latest catalog `capability_digest`, an exact
`operation_key`, a live non-system mount, bounded resource and path parameters,
declared query/body fields with matching primitive types, and an audit reason.
Destructive operations additionally bind confirmation to the advertised method,
compiled path, and cluster slug. Material responses use the JSON renderer only
and are neither persisted nor included in audit records.

The executable registry accepts runtime-advertised GET, LIST, POST, PUT, PATCH,
and DELETE operations only when they belong to the mounted-secrets family,
match the reviewed `/{secret_mount_path}` grammar, declare every path placeholder
as required and typed, and pass the request and response controls above. An
advertised operation outside that grammar remains display-only.

The PKI journey family covers cluster, CRL, issuer, URL, ACME, and auto-tidy
configuration; issuer, key, and role lifecycle; certificate listing and reads;
issuance and signing; legacy and multi-issuer root/intermediate generation,
issuer-scoped intermediate signing, root rotation and delete-all-root state;
revocation; and tidy status, start, and cancellation. Certificate serial path parameters
accept colon- or hyphen-delimited hexadecimal serials and normalize them to the
canonical lowercase hyphen form before path compilation. Root/key generation,
rotation, deletion, revocation, and tidy operations retain their dedicated
permissions and exact confirmations after runtime capability resolution.

The Kubernetes journey family covers connection configuration, roles, and
credential generation. Generated PKI and Kubernetes material is returned only
in the current `no-store` response. Journey catalog entries may declare a
download filename for the Web UI, but the REST representation remains JSON and
the server does not create or retain a file. See the runbook for the complete
permission table, custody procedure, and unknown-outcome recovery rules.

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

## Authentication and MFA administration

Authentication actions are cluster-scoped under:

```text
/api/plugins/openbao/clusters/<cluster-id>/
```

Every response is `no-store`. POST and DELETE requests require the standard
NetBox write token or a CSRF-protected NetBox session plus the dedicated
`OpenBaoCluster` object permission. Mutations include a `reason`; destructive
actions also require the exact `confirmation` documented in the
[authentication runbook](how-to/administer-openbao-authentication.md).

| Relative route | Methods | Purpose |
|---|---|---|
| `auth-methods/` | GET, POST | List or enable reviewed auth mounts |
| `auth-methods/<mount>/` | GET, POST, DELETE | Read, tune, or disable a mount |
| `auth-remount/` | POST | Begin an asynchronous auth remount |
| `auth-remount/<migration-id>/` | GET | Read remount status |
| `auth-config/<mount>/` | GET, POST | Read or write a method's reviewed configuration |
| `auth-resources/<mount>/<family>/[<name>/]` | GET, POST, DELETE | Typed resource list/read/write/delete |
| `auth-approle/<mount>/<role>/role-id/` | GET, POST | Read or assign an AppRole RoleID |
| `auth-approle/<mount>/<role>/secret-id/` | POST | Issue one SecretID |
| `auth-approle/<mount>/<role>/secret-id-accessor/` | POST, DELETE | Look up or destroy by accessor |
| `auth-login/<mount>/` | POST | Run one request-scoped login |
| `auth-oidc/<mount>/start/` | POST | Start direct OIDC and return an in-memory polling contract |
| `auth-oidc/<mount>/poll/` | POST | Complete direct OIDC after validating the signed envelope |
| `auth-mfa/validate/` | POST | Complete a login MFA challenge |
| `auth-mfa/methods/` | GET | List MFA methods |
| `auth-mfa/methods/<type>/[<method-id>/]` | POST, GET, DELETE | Create, read, update, or delete TOTP/Duo/Okta/PingID configuration |
| `auth-mfa/totp/<method-id>/self/` | POST | Generate one-shot TOTP setup with a submitted request-scoped token |
| `auth-mfa/totp/<method-id>/self/reset/` | POST | Derive the submitted token's entity and reset its TOTP setup after exact confirmation |
| `auth-mfa/totp/<method-id>/entities/<entity-id>/` | POST, DELETE | Generate or destroy entity TOTP setup |
| `auth-mfa/enforcements/[<name>/]` | GET, POST, DELETE | List, read, write, or delete login enforcements |
| `auth-tokens/<operation>/` | POST | Look up, renew, or revoke self tokens and accessors |

Advanced configuration and resource writes use this envelope:

```json
{
  "reason": "CHG-1234: update the corporate OIDC role",
  "payload": {
    "role_type": "oidc",
    "user_claim": "sub",
    "allowed_redirect_uris": [
      "https://bao.example.net:8200/v1/auth/oidc/oidc/callback"
    ]
  }
}
```

The server accepts only fields and types in its static OpenBao 2.6.2 registry.
Runtime OpenAPI schemas are display-only. Passwords, JWTs, tokens, RoleIDs,
SecretIDs, provider secrets, MFA codes, and OIDC challenges are never persisted
or audited. A successful login, renewal, SecretID issue, MFA validation, or
TOTP setup returns material once; the client must custody or discard it
immediately. OIDC `oauth2_metadata` values (`access_token`, `id_token`, and
`refresh_token`) are treated as one-shot material rather than ordinary identity
metadata.

JWT/OIDC role writes reject `oidc_disable_confirmation` and
`verbose_oidc_logging`; existing direct roles with either setting enabled
cannot start through NetBox. Namespaced direct callbacks use
`/v1/<namespace>/auth/<mount>/oidc/callback` so the identity-provider request
arrives in the same OpenBao namespace without relying on a request header.

Mutation transport loss after dispatch, or an accepted response that fails
bounded parsing, returns HTTP 503 with `outcome: unknown`, `audit_status:
preflight-only`, and a fixed do-not-retry instruction. Clients must reconcile
the fixed upstream path before deciding whether another request is required.
If browser transport or response parsing fails before the API payload can be
validated, the Web UI reports `outcome: unknown` with `audit_status:
unconfirmed`; it does not infer that a preflight audit committed.

## Policy, identity, OIDC, and namespace administration

These cluster-scoped routes provide the permission-filtered contract used by
the **Policies and identity** workspace:

| Relative route | Method | Purpose |
|---|---|---|
| `access-resources/` | GET | List runtime-advertised reviewed resources and operations |
| `access-resources/preview/` | POST | Read destructive impact and return its digest and exact confirmation |
| `access-resources/execute/` | POST | Execute one reviewed list, read, write, delete, merge, rotation, or generation operation |

Execution accepts `resource`, `operation`, an optional canonical `identifier`,
a typed `payload`, `reason`, and the current `capability_digest`. Destructive
operations additionally require the current `impact_digest` and exact
`confirmation`. Every response is JSON and `no-store`. Generated passwords and
OIDC client credentials are material responses; they require their dedicated
object permission and are never persisted or audited. See the [access
administration runbook](how-to/administer-openbao-access.md).

Namespace writes require `custom_metadata` and replace it in full. Namespace
seal configuration and PGP key submission are rejected because their response
can contain unseal shares and no namespace-custody API is exposed. Durable
mutation audit records include only validated non-secret target identifiers;
request bodies and response bodies remain excluded.

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
