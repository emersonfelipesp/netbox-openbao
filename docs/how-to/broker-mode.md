# Run broker mode

Normally the plugin authenticates to OpenBao directly, which means the NetBox
host possesses credentials able to read production secret material.

In broker mode it presents a **client certificate** to
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
which holds the AppRole and answers on NetBox's behalf. NetBox keeps something
that lets it *ask*; the broker keeps the thing that can actually *read*.

## What it is honestly worth

Read this before deploying it, because it is easy to oversell and an operator
might relax controls elsewhere on the strength of it.

!!! danger "It does **not** make 'NetBox compromise ≠ secret compromise' true"

    An attacker with code execution in NetBox can still ask the broker for
    material, and the broker will answer for anything NetBox is authorized to
    request.

    The README said otherwise once. It was wrong, and it is worth being exact
    about it rather than repeating a comfortable version.

What it genuinely buys:

- **Stealing the database or the configuration no longer yields vault
  credentials.** The AppRole's SecretID never exists on the NetBox host at all.
  That is a real improvement against offline compromise, backup theft, and
  configuration leakage.
- **The broker's audit log is outside NetBox's blast radius.** A compromise can
  read, but it cannot erase the record of having read.
- **A second, independent authorization layer.** The broker re-checks every
  path against the prefixes it was configured to serve *this instance*, before
  it uses the AppRole. A NetBox-side permission bug is not sufficient on its
  own for a path outside them.

Authorization there is **per instance, not per user**. Enforcing per-user would
mean shipping this plugin's object permissions, constraints, and group
membership to the broker — a second implementation of the authorization model
this plugin exists to keep singular. NetBox remains the authority on who may
ask.

## Setting it up

### 1. Run the broker

See its own repository. It needs the AppRole, the KV mount, a client CA, and a
per-instance configuration naming which path prefixes each certificate CN may
reach.

### 2. Point an engine at it

Set the engine's **backend** to `Broker (netbox-openbao-broker)` and its **API
URL** at the broker.

```bash
curl -X PATCH https://netbox.example.net/api/plugins/openbao/engines/1/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "backend": "broker",
        "api_url": "https://bao-broker.example.net:8201",
        "ca_cert_path": "/etc/netbox/openbao/broker-ca.pem"
      }'
```

Nothing above the `SecretBackend` abstraction changes. Credentials, policies,
assignments, reveals, and staged rotations all behave identically.

### 3. Deliver the client certificate

These are **paths on the NetBox host, not material**, which is why there is no
`_FILE` form — there is no value here to keep out of `/proc/<pid>/environ`.

```ini
# /etc/netbox/openbao.env
NETBOX_BAO_PRIMARY_CLIENT_CERT=/etc/netbox/openbao/netbox-prod.pem
NETBOX_BAO_PRIMARY_CLIENT_KEY=/etc/netbox/openbao/netbox-prod.key
```

The key file must be readable by the NetBox user and the RQ worker, and by
nobody else.

A `CredentialPolicy` tier can present its **own** certificate under its own
prefix — `NETBOX_BAO_PROD_CORE_CLIENT_CERT`, and so on. The broker identifies
callers by the certificate's subject CN, so a different certificate is a
different instance with a different set of permitted prefixes. The tiering that
AppRoles give you in direct mode is preserved rather than flattened.

### 4. Restart both units and check

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://netbox.example.net/api/plugins/openbao/engines/1/health/
```

The health message says *"through the broker"* when it is working, and
distinguishes an unreachable broker from a broker that cannot reach OpenBao —
different problems, different fixes.

## Three engine fields are ignored, deliberately

| Field | Why |
|---|---|
| **KV mount** | The broker reads its own. Letting NetBox choose would let a compromised NetBox address mounts the operator never granted, which inverts the point of the mode. |
| **Namespace** | Likewise. |
| **Authentication method** | The client certificate *is* the authentication. |

The engine's **CA certificate path** and **TLS verify** apply to the *broker's*
server certificate.

## TLS verification cannot be turned off

Direct mode tolerates `tls_verify = False`, and the cost there is a short-lived
token presented to whoever answers. Here the client certificate **is** the
credential and it is long-lived, so an unverified peer is a credential handed
to a man in the middle.

A self-signed broker certificate is served by pointing **CA certificate path**
at it, so this refuses nothing legitimate.

## Two operational notes

**KV v2 only.** An engine set to version 1 is refused before any request is
sent.

**`may_delete = false` on the broker instance disables the rollback
compensator.** The plugin can read, write, and rotate but not delete — so when
a credential write succeeds in OpenBao and the NetBox transaction then fails,
the material it wrote cannot be removed. That becomes a logged `ORPHANED
SECRET` for
[`CredentialVerifyJob`](../architecture/background-jobs.md#credentialverifyjob)
to report.

Both postures are defensible. Choose deliberately rather than discovering it
during a cleanup.

## Errors

The broker's own error text is **never relayed**. It is written not to leak
policy, but this side cannot verify that, and a backend that forwards a remote
string has given up the guarantee the exception layer exists to provide.

| You see | Means |
|---|---|
| `401`, "did not accept this NetBox instance's client certificate" | The certificate is missing, expired, or not signed by the CA the broker trusts |
| `403`, "refused this request for this NetBox instance" | The certificate is fine; the path is outside this instance's permitted prefixes, or the operation is one it may not perform |
| "The broker is unreachable" | Transport failure — the broker, not OpenBao |
| "The broker is up, but cannot reach OpenBao" | The other half |

The two authorization cases raise the same exception type, so nothing above
`SecretBackend` behaves differently — but they are entirely different operator
problems, and sending someone to check the wrong one costs an afternoon.
