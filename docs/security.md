# Security model

This plugin's job is to hold the most sensitive data in a NetBox estate. The
properties below are what make that defensible, and each is enforced
structurally — by a type, a constraint, or an absent column — rather than by a
convention the next contributor has to remember.

Each is covered by a test in `netbox_openbao/tests/test_security.py`. If you
change one, that test should fail; if it doesn't, the test is wrong.

## 1. No model field can hold secret material

`Credential` has no column that material could be written to. That is the claim
everything else rests on, because it makes whole categories of leak impossible
rather than merely unlikely:

- A changelog entry cannot contain a private key. (This matters more than it
  sounds: `ObjectChange` records are permanent, and a leaked key in one is
  effectively unrecallable.)
- An export template cannot be written to emit one.
- The REST representation has nothing secret to omit.
- A `SELECT *` by a DBA, a replica, or a backup restore surfaces nothing.

The test walks `Credential._meta.get_fields()` and fails on any name containing
`password`, `private`, `secret`, `passphrase`, or `token`.

## 2. `secret_data` is write-only

The API accepts material through a `write_only` serializer field. DRF itself
refuses to serialize it, so it cannot appear in a `GET`, a `brief=true`
response, the browsable API, an export, or an OpenAPI example — regardless of
what any view does. It is consumed by the viewset, handed to the backend, and
dropped.

## 3. `reveal` is a permission in its own right

`Credential.Meta.permissions` declares `reveal` and `rotate`, which NetBox 4.7
auto-registers as model actions. They appear as checkboxes in the standard
ObjectPermission form and accept constraints like any other action.

The consequence worth stating plainly: **a role can inventory every credential
in the estate and read none of them.** Auditors, capacity planners, and most
automation want exactly that.

Constraints work too. A permission with `{"policy__slug": "lab"}` yields a
`404` on a production credential — not a `403`, which would confirm it exists.

## 4. Reveal responses are unstorable

- `renderer_classes` is overridden to `[JSONRenderer]` on the action.
  `BrowsableAPIRenderer` would template the secret into an HTML page, and HTML
  is what caches, history, and "save page as" retain.
- `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`.
- Rate limited per user (`reveal_rate_limit`, default `30/hour`), bounding how
  fast a leaked token can drain the store.

The **UI** reveal is POST-only, so a secret is never fetched by a bookmark, a
browser prefetch, a link scanner, or a history replay.

## 5. No GraphQL surface at all

The plugin registers no `graphql_schema`, so its models are not exposed through
NetBox's GraphQL API in any form — not even metadata.

This is deliberate rather than unfinished. GraphQL queries are logged verbatim
by most gateways, and a graph API's response shape is harder to audit than a
single named REST action. If metadata-only GraphQL types are added later, a
reveal field must never be among them.

## 6. No auth material in the database

`SecretEngine` has no `role_id`, `secret_id`, or `token` column. Material is
read from the process environment at login, or from a file the environment
points at. Storing the vault's own credentials in the database this plugin
exists to keep secrets out of would defeat the entire design.

## 7. Per-tier AppRoles

Each `CredentialPolicy` maps to a real OpenBao policy and can carry its own
AppRole. Three independent layers must pass:

1. NetBox object permissions, with constraints.
2. The policy's group gate.
3. The OpenBao policy reached through that tier's AppRole.

Layer 3 is what makes layers 1 and 2 survivable. A NetBox-side permission bug
on `prod-core` credentials still cannot read them, because OpenBao's own policy
refuses the AppRole the request is carrying.

A `Credential`'s engine is validated to match its policy's engine. Without
that, a tier's AppRole could be scoped to one instance while the material sat
on another — the exact mismatch per-tier AppRoles exist to prevent.

## 8. Backend exceptions carry no server text

An OpenBao `403` body can enumerate policy rules. `hvac` embeds the response
body in its exception text, so letting one propagate would put the shape of
your authorization model into Sentry, into `logging`, and into DRF error
responses.

Every backend exception is caught and re-raised as a
`netbox_openbao.backends.exceptions` type built from a fixed string, with
`from None` so the original is not chained onto the traceback either. The
incoming message is inspected internally — that is how a check-and-set conflict
is told from any other `400` — and then discarded.

## 9. Every access is audited

`CredentialAccessLog` records who, when, from where, which action, and whether
it succeeded. **Never the value.**

- It is append-only and exposed read-only through the API. The same token that
  reveals a secret cannot erase the record of having done so.
- It survives deletion of the credential, via name and UUID snapshots.
- Failures are audited too — a refused reveal is the entry you most want.
- It is written **synchronously**. The original design deferred it to RQ for
  latency, but an indexed INSERT costs ~1ms against an OpenBao round-trip of
  tens of ms, and an audit record a queue failure can silently drop is not an
  audit record.

OpenBao's own audit device remains authoritative for what happened at the
vault. It only ever sees an AppRole, though, so it cannot say *which NetBox
user* asked. This table is the other half; `request_id` correlates the two.

## 10. Write atomicity and orphaned secrets

OpenBao writes are not transactional with PostgreSQL, and **Django has no
rollback hook** — `transaction.on_commit` fires only on commit. So compensation
is explicit: the backend write happens inside the atomic block, the written
path is recorded, and the enclosing `except` deletes the orphaned path before
re-raising.

If the compensating delete itself fails, it is logged at ERROR and
`CredentialVerifyJob` reports the residue as an orphan on its next pass. The
`managed_by: netbox-openbao` custom metadata is what lets it recognise material
under the plugin's prefix that NetBox no longer has a row for.

Deleting a `Credential` destroys its material via a `pre_delete` signal, so
removing a row never leaves a readable secret behind on the mount.

## 11. A rotation cannot break a consumer, and cannot lose the old secret

`stage` writes replacement material without putting it into service, so a
rotation has a verification step and a way back. Two properties matter:

- While a version is staged, `reveal` continues to return the **live** version.
  Resolution consults `live_kv_version` before falling back to latest.
- `discard` deletes **only** the staged version. Compensation elsewhere in the
  write path is scoped the same way, for the same reason: destroying a whole
  path to clean up a failed rotation would take the working secret with it.

A credential written before staged rotation existed has no live pointer, which
means "serve latest". Staging pins the pointer to what is live *now* before
writing the candidate — otherwise the first stage on such a credential would
put the unverified version straight into service, which is the exact outcome
staging exists to prevent.

## 12. Check-and-set on every write

Creates use `cas=0`, which requires the path not to exist — so a create cannot
silently overwrite material written outside NetBox. Rotations use the recorded
`kv_version`, so a rotation cannot clobber a concurrent write it never saw.
Both are verified against a live OpenBao in the integration tests, because a
mock proves nothing about whether `hvac` and OpenBao agree on what `cas` means.

## 13. The reveal countdown is a convenience, not a control

Revealed material clears itself from the page after the policy-capped TTL, and
there is a "clear now" button. Both are worth having: a screen left unattended
stops displaying a secret.

Neither is a security boundary, and the UI says so rather than implying
otherwise. The material has already left the server by the time it renders;
anyone who wants to keep it can. Clearing the page does not revoke anything,
and the access-log entry stands regardless.

The fragment ships inline script, which is only safe because values reach the
DOM through `textContent` and the node is dropped with `remove()`. Building
markup from a value would let material containing HTML execute in the
operator's session — `test_fragment_uses_no_innerhtml` enforces that by
substring so it cannot creep back.

## 14. An operator-defined type cannot execute code or leak material

`CredentialTypeSchema` lets operators define credential types as data. Two
limits keep that from being a privilege-escalation surface:

- **`extractor` names a function from a fixed registry.** It is never an import
  path, never a dotted callable, never anything resolvable to arbitrary code. A
  JSONField that could name any importable object would be remote code
  execution wearing a schema. Validated in the model's `clean()`, so the API
  enforces it as well as the form.
- **Extraction output is filtered against `EXTRACTABLE_FIELDS`** regardless of
  what the schema declares, and the payload itself never reaches a model field.
  So a type whose properties are named after model columns still cannot get
  them written.

A stored type also may not shadow a built-in slug, since the plugin's own code
paths assume the built-in definitions.

Schema validation errors report the failing **path**, never the value —
`jsonschema`'s own message embeds the failing instance, which for a secret
payload is the material.

## 15. Form inputs are not echoed

Secret form fields use widgets with `render_value=False`. On a validation error
the browser gets an empty box, not the key the user just pasted — which would
otherwise land in the back/forward cache and in any saved HTML or screenshot.

## Deployment notes

- **Leave `tls_verify` on.** With verification off, every secret an engine
  serves is exposed to anyone who can intercept the connection.
- **Scope the OpenBao policy to the path prefix**, not the whole mount. The
  plugin should not be able to read secrets it did not write.
- **Give each tier a genuinely separate AppRole** and deliver its SecretID
  separately. Reusing one AppRole across tiers collapses layer 3.
- **Add a Sentry `before_send` scrubber** for `netbox_openbao.*` if you run
  Sentry. The plugin does not put material in exceptions, but defence in depth
  is the point.


## Broker mode

An engine set to the `broker` backend reaches OpenBao through
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
which holds the AppRole so this NetBox does not.

**It does not make "NetBox compromise ≠ secret compromise" true.** An attacker
with code execution in NetBox can still ask the broker for material, and the
broker will answer for anything NetBox is authorized to request. Deploying it
is not a reason to relax anything documented above.

What it does change:

- Stealing NetBox's **database or configuration** no longer yields credentials
  that read the vault directly. The AppRole's SecretID never exists on the
  NetBox host.
- The broker's **audit log is outside NetBox's blast radius** — a compromise
  can read, but it cannot erase the record of having read.
- Authorization gains a second, independent layer: the broker re-checks every
  path against the prefixes it was configured to serve *this instance*, before
  it uses the AppRole. A NetBox-side permission bug is not sufficient on its
  own for a path outside them.

Authorization there is **per instance, not per user**. Enforcing per-user would
mean shipping this plugin's object permissions, constraints, and group
membership to the broker — a second implementation of the authorization model
this plugin exists to keep singular. NetBox remains the authority on who may
ask.

The same scrubbing rule applies in both directions: `BrokerBackend` discards the
broker's error text rather than relaying it. The broker is written not to leak
policy, but the plugin cannot verify that from here, and a backend that forwards
a remote string has given up the guarantee this page describes.
