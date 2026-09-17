# Administer OpenBao leases, tools, and UI configuration

This runbook covers the final OpenBao 2.6.2 administrative workspace exposed
by netbox-openbao: lease inspection and revocation, response wrapping, hashing,
random data, token lookup, UI response headers, and parity diagnostics. Open the
cluster detail page and select **Leases and tools**.

The workspace uses the cluster's configured service identity, API origin, TLS
policy, and namespace. An operator cannot supply a token, origin, raw path,
method, header, or TLS override. Every response is `Cache-Control: no-store`.
Wrapping tokens, unwrapped values, hashes, and random data remain in the current
page only, expire after five minutes, and clear on operation changes, explicit
clear, or page exit.

## Compatibility and transport modes

The contract is pinned to OpenBao 2.6.2 and commit
`dd9c19c37a878cf4a81b18efb8d6f0599c7da923`. Direct mode requires an initialized,
unsealed OpenBao 2.6.x cluster at or above 2.6.2. The runtime OpenAPI document
must advertise each selected operation and retain the catalog digest used by
the page.

Broker mode fails closed because the current broker does not advertise this
administrative contract. It does not fall back to direct access. Add a reviewed
broker contract before enabling these operations through a broker; do not proxy
arbitrary paths to simulate support.

## Permissions

Grant `view_openbaocluster` and `view_operations_openbaocluster` together with
only the operation permissions required by the role. Constrain each grant with
NetBox ObjectPermission rules for the intended clusters.

| Permission | Capability |
|---|---|
| `view_leases_openbaocluster` | List lease prefixes and look up lease metadata |
| `manage_leases_openbaocluster` | Request renewal of a renewable lease |
| `revoke_leases_openbaocluster` | Revoke one lease or a prefix after impact preview |
| `force_revoke_leases_openbaocluster` | Ignore backend cleanup errors and force-revoke a prefix |
| `use_wrapping_openbaocluster` | Wrap, inspect, and rewrap request-scoped data |
| `unwrap_material_openbaocluster` | Unwrap and reveal request-scoped data |
| `use_tools_openbaocluster` | Hash base64 input and generate entropy |
| `manage_tokens_openbaocluster` | Look up a caller-supplied token through the fixed token lookup route |
| `view_ui_configuration_openbaocluster` | List and read configured OpenBao UI headers |
| `manage_ui_configuration_openbaocluster` | Replace or delete an OpenBao UI header after impact preview |

Do not combine force revoke, unwrap, or UI configuration management with a
routine read-only role. The configured OpenBao cluster credential policy must separately grant the
matching paths and `sudo` capabilities required by OpenBao.

## Lease workflow

Lease prefixes are canonical OpenBao paths such as
`database/creds/readonly` or `ssh/creds/otp`. The page preserves path
separators, rejects traversal and encoded separators, and removes a trailing
slash before compiling mutation paths.

1. Select **leases → list**, enter the prefix, and inspect the returned keys.
2. Select **leases → lookup** and submit the complete `lease_id` to inspect its
   issue time, expiration, path, TTL, and renewable flag.
3. Select **leases → renew** only when `renewable` is true. `increment` is a
   requested number of seconds; OpenBao may grant a different duration.
4. For one lease, select **revoke**, enter the `lease_id`, choose synchronous
   handling only when the operator must wait for completion, preview impact,
   type the exact confirmation, and submit once.
5. For a prefix, use **revoke-prefix**. Review every listed child before
   confirming because the operation can revoke many credentials.

**Force revoke is an emergency operation.** It tells OpenBao to discard lease
records even when the backing system cannot confirm credential cleanup. The
database account, cloud key, or other credential can remain valid after the
OpenBao record is gone. Require an incident or change reference in `reason`,
verify the current prefix listing, type the exact cluster-bound confirmation,
submit once, and validate the backing system independently afterward.

If a mutation returns `outcome: unknown`, do not retry. Re-list or look up the
lease, inspect the backing system, and correlate the NetBox administration log
with the OpenBao audit device before deciding whether another operation is
safe.

## Request-scoped tools

### Response wrapping

**wrap** accepts one JSON object and a Go-style duration such as `5m` or
`1h30m`. The object is sent as the raw OpenBao request body. The duration is
sent only as `X-Vault-Wrap-TTL`; callers cannot add other headers. Transfer the
returned wrapping token directly to the intended recipient.

**lookup** returns creation metadata without consuming the token. **rewrap**
consumes the old wrapping token and returns a replacement. **unwrap** consumes
the token and reveals its data under the dedicated material permission. Clear
the result after custody transfer. Never place a wrapping token or unwrapped
value in a ticket, audit reason, URL, browser storage, or NetBox object.

### Hash, random data, and token lookup

- Hash input must already be base64. Choose one reviewed SHA-2 or SHA-3
  algorithm and `hex` or `base64` output. SHA-3 may be unavailable under some
  FIPS policies.
- Random data accepts 1 through 4096 bytes from `platform` or `all`, with `hex`
  or `base64` output. Treat the result as material when it becomes a key,
  password, nonce, or seed.
- Token lookup sends the supplied token in the request body and returns bounded
  metadata. The token is a password input, is not audited, and is cleared with
  other request-scoped material.

## UI response headers

OpenBao UI response headers affect the built-in OpenBao UI, not NetBox pages.
List or read the current values before changing one. Header names accept only
letters, digits, and hyphens and cannot contain path syntax. Values are a JSON
list of strings.

Replacement and deletion require a fresh read, an impact digest, a reason, and
the exact confirmation shown by the page. If another operator changes the
header after preview, the stale impact digest is refused. Validate the header
through the management listener after the change. Avoid weakening
`Content-Security-Policy`, `X-Frame-Options`, or other browser controls merely
to work around an embedding problem.

## REST API

Fetch the permission-filtered catalog and retain its capability digest:

```http
GET /api/plugins/openbao/clusters/42/final-resources/
```

Execute a metadata operation:

```json
POST /api/plugins/openbao/clusters/42/final-resources/operate/
{
  "resource": "leases",
  "operation": "lookup",
  "payload": {"lease_id": "ssh/creds/otp/example"},
  "reason": "Investigate the credential expiry alert.",
  "capability_digest": "<digest>"
}
```

For destructive or configuration operations, first send the same request with
`"preview": true`. Preserve the returned `impact_digest` and exact
`confirmation`, then send both in the execution request. Never cache or retry a
material or mutation response.

Check the complete pinned/runtime contract:

```http
GET /api/plugins/openbao/clusters/42/final-conformance/
```

HTTP 409 means the runtime is missing a reviewed operation, contains a
duplicate or unclassified matching operation, or no longer reports exactly
2.6.2. Treat this as a compatibility stop, not as permission to bypass the
plugin.

## Backup, restore, migration, and rollback

Lease records, wrapping tokens, and UI header configuration live in OpenBao's
storage and are covered by the normal OpenBao Raft snapshot procedure. NetBox
stores only cluster inventory, object permissions, and metadata-only
administration logs. Use the [cluster administration runbook](administer-openbao-cluster.md)
for authenticated snapshot download and restore.

Before migrating from the built-in OpenBao UI, inventory operator roles and map
them to the dedicated permissions above. Compare the pinned parity endpoint,
exercise direct-mode read paths, verify audit correlation, then enable mutation
permissions in stages. Keep the built-in UI available on the management network
during validation, but do not run both interfaces against the same change
without coordination.

Rollback removes the new NetBox permissions and UI access; it does not undo an
OpenBao mutation. Restore an OpenBao snapshot only under the disaster-recovery
procedure because it can revert unrelated leases and configuration. Migration
`0020_finalization_permissions` contains no material or durable operation
state, so reversing it removes permission rows without changing OpenBao.

## Incident response and retirement

- Unknown mutation: stop retries, inspect current state and the backing system,
  and correlate both audit trails.
- Lost wrapping response: do not repeat the operation until lookup or the
  intended recipient proves whether the token was consumed.
- Suspected material exposure: revoke or rotate the affected token or secret,
  clear the page, preserve metadata-only evidence, and follow the credential
  incident process.
- Conformance failure after upgrade: remove mutation grants or disable the
  workspace route, pin the supported OpenBao version, and open a compatibility
  review with a newly captured OpenAPI fixture.
- Retirement: revoke the cluster service identity, remove ObjectPermissions,
  export required metadata-only audit records, remove the cluster inventory,
  and independently retire or transfer the OpenBao server. NetBox deletion is
  not an OpenBao data-destruction mechanism.

## Verification

```bash
python scripts/check_openbao_ui_parity.py
npm test
```

Run the opt-in live suite against an isolated OpenBao 2.6.2 server:

```bash
NETBOX_OPENBAO_TEST_ADDR=http://127.0.0.1:8200 \
NETBOX_OPENBAO_TEST_TOKEN='<test-root-token>' \
python -m unittest -v netbox_openbao.tests.test_finalization_administration_live
```

The live suite creates uniquely named SSH OTP mounts, exercises genuine dynamic
leases, and removes each mount in `finally`. Never point it at production.

## References

- [OpenBao lease API](https://openbao.org/docs/api/system/leases/)
- [OpenBao tools API](https://openbao.org/docs/api/system/tools/)
- [OpenBao wrapping API](https://openbao.org/docs/api/system/wrapping-wrap/)
- [OpenBao UI configuration API](https://openbao.org/docs/api/system/config-ui/)
- [OpenBao 2.6.2 release](https://github.com/openbao/openbao/releases/tag/v2.6.2)
