# Service endpoints and NMS credential import

`netbox-openbao` is the authoritative inventory and material owner for device,
virtual-machine, and service credentials. Source-plugin rows are migration
inputs only; the importer copies them and never deletes or updates them.

## Service endpoint model

`ServiceEndpoint` binds an SSH, Telnet, NETCONF, RESTCONF, gNMI, SNMP, or HTTP
listener to any object admitted by the same assignable-model registry used by
`CredentialAssignment`. It stores connection metadata, host-key policy, and an
optional `Credential` relationship. Secret material remains only in OpenBao.

`SSHPublicKey` records a user's public key for one SSH endpoint. Its fingerprint
is derived from the OpenSSH public key when saved. The model has no private-key
field.

### The nested `credential` is permission-bounded, not the full credential

`ServiceEndpointSerializer.credential` and `ResolveView`'s `credential`
representation are never the full `CredentialSerializer` output. Both apply
the same rule: **null unless `Credential.objects.restrict(request.user,
'view')` contains the credential**, checked against the credential itself —
not against `view_serviceendpoint`, which a caller can hold without holding
`view_credential` or a constrained grant of it. When the check passes, the
representation is bounded to `id`, `url`, `display`, `name`,
`credential_type`, and `username` (`ServiceEndpointCredentialSerializer` in
`api/serializers.py`), never the credential's full field set (`policy`,
`engine`, `path`, fingerprints, certificate fields, and so on). This applies
on list, detail, and `resolve`. `SSHPublicKey` has no `credential` field to
nest — it stores public material for a `service_endpoint`, not a credential.

## Metadata-only resolution

```http
GET /api/plugins/openbao/resolve/?object_type=dcim.device&object_id=42&service_type=ssh&purpose=login
```

Resolution applies NetBox object-permission restrictions to the target,
endpoints, and assignments. It returns endpoint metadata and credential
identity (`id`, `uuid`, type, username, and the existing reveal URL), null
unless the caller may also view the credential itself — see above. It never
reads OpenBao and never includes material. A caller that needs material must
use `credentials/{id}/reveal/`, which enforces `CredentialPolicy` and records a
`CredentialAccessLog` entry.

## Import command

Validate importer readiness without reading source rows or writing NetBox or
OpenBao state:

```bash
python manage.py openbao_import_nms_credentials_preflight
```

The command performs bounded reads only: a literal database connectivity probe
and an existence check for the credential policy required by apply. It also
checks that `netbox_openbao` and its required `netbox_rpc` plugin completed
startup and that the effective, database-backed `path_prefix` returned by
`get_config()` is safe. Standard output is
exactly one compact JSON object with the closed keys `version`, `action`,
`category`, `process_started`, and `summary`. `category` is one of `startup`,
`configuration`, `database`, or `complete`; `summary` is always null. Failure
details, exception text, stderr, URLs, filesystem paths, source rows,
credential metadata, and secret material are never copied into the record.
Checks run in the fixed order startup, literal database probe, effective
configuration, then policy existence. A database error while resolving the
effective configuration is therefore reported as `database`, not
`configuration`, without exposing the exception.

Once the importer enters `handle()`, both dry-run and apply unconditionally
write and flush `{"version":1,"event":"openbao_import_started"}` plus a newline
as the first bytes on stdout. The marker precedes source-model discovery and
all importer database reads or writes and appears exactly once. If plugin
startup, Django system checks, or command resolution prevents `handle()` from
running, the marker is absent.

Preview the available source rows without database or OpenBao writes:

```bash
python manage.py openbao_import_nms_credentials --dry-run
```

Copy rows and record the old-to-new identifiers:

```bash
python manage.py openbao_import_nms_credentials --id-map /secure/path/openbao-id-map.json
```

The command discovers optional source models through Django's application
registry, so neither source plugin is an import-time dependency. It copies six
source model families: device credentials, device services, user SSH public
keys, Proxmox SSH bindings, cloud VM credentials, and observability secrets.
It requires an existing `CredentialPolicy`, preferring one on the default
engine. Provenance markers (`import_source`) make repeated runs idempotent:
re-running the command finds the row it already created instead of writing a
duplicate. Missing source plugins and missing referenced VMs/endpoints are
reported and skipped.

**A `DeviceService` re-import reconciles the existing `ServiceEndpoint` on
every run**, not only the first: credential, target, host, port, SSH
settings, and options are all rewritten to the source row's current state.
This matters most for `credential` — the common case is a `DeviceService`
importing before its matching `DeviceCredential` exists, which leaves the
endpoint's credential null on the first run; the next run picks it up once
the credential import has caught up, rather than leaving the endpoint
permanently uncredentialed.

**`Credential.import_source` is protected by a partial unique constraint**
(`import_source != ''`; migration `0022`) — every writer stamps a globally
unique provenance string (`<app_label>.<Model>:<pk>` here, or a
`<SOURCE_SYSTEM>:<id>` prefix for the separate `netbox_secrets` importer), so
two rows sharing one non-blank value is always a bug. `_create_credential()`
serializes concurrent claims of the same source row with a session-scoped
PostgreSQL advisory lock (`pg_advisory_lock`/`pg_advisory_unlock`, keyed on
the `import_source` string) around the whole check-then-create sequence. It
is session-scoped rather than transaction-scoped because the credential write
happens inside `store_credential()`'s own outermost `material_transaction()`,
which refuses to run nested inside a caller's own `transaction.atomic()`. As
a second line of defense — the lock bounds this command's own concurrent
runs, not a concurrent writer through another path entirely —
`store_credential()` calls the row-persisting `persist()` callback (and
therefore hits the unique constraint) before it ever writes to the OpenBao
backend, so an `IntegrityError` there means no OpenBao path was written by
that attempt; `_create_credential()` recovers by re-reading the row the other
writer committed instead of retrying the write.

Protect the ID-map file as operational metadata. It contains no secret values,
but it exposes inventory relationships and source identifiers.

## Atomic endpoint and credential write

```http
POST /api/plugins/openbao/service-endpoints/with-credential/
```

Creates or updates a `ServiceEndpoint` (matched on object, service type, and
port) together with the credential it uses, in one database transaction and
one material write. Pass either `existing_credential` (a credential the caller
can view) or `new_credential` (`name`, `credential_type`, `policy`,
`username`, write-only `secret_data`). A credential whose type cannot serve
the protocol is rejected before anything is written (for example SNMP accepts
only `snmp_v2c`/`snmp_v3`; SSH accepts password and key types). If anything
after the material write fails, the new OpenBao version is compensated, so no
orphaned secret remains. Requires `add_serviceendpoint`, `change_serviceendpoint`,
`view` on the target, and `add_credential` when creating a credential.

## Revision-bound reveal through an endpoint

```http
POST /api/plugins/openbao/service-endpoints/{id}/reveal-credential/
{"reason": "...", "endpoint_revision": "<last_updated>", "object_type": "dcim.device",
 "object_id": 42, "credential_uuid": "...", "credential_type": "...", "kv_version": 3}
```

For approval-gated automation: the credential is revealed only if the endpoint
is still enabled (`options.enabled` is not false), still assigned to the same
object, unchanged since `endpoint_revision`, and still bound to the expected
credential identity and kv version. The state is verified before the audited
reveal and re-verified after it; if anything changed, the response is `409`
with no material. Requires `view_serviceendpoint` and `reveal_credential` on the
credential (plus its policy gate).
