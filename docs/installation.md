# Installation

## Requirements

| Component | Version | Why |
|---|---|---|
| NetBox | **4.6.0 – 4.7.99** | See [NetBox 4.6 and 4.7](#netbox-46-and-47) |
| Python | 3.12+ | NetBox 4.7 requires it |
| PostgreSQL | 15+ **with `ltree`** | NetBox 4.7 backs hierarchical models with ltree |
| Redis | 6+ | Job queue and the OpenBao token cache |
| OpenBao | 2.6.x | KV v2 mount |

`bcrypt` is pulled in as a dependency. NetBox does not ship it, and
`cryptography` delegates the OpenSSH bcrypt KDF to it — without it, loading a
passphrase-protected OpenSSH private key fails with
`UnsupportedAlgorithm: Need bcrypt module`.

## Install

```bash
source /opt/netbox/venv/bin/activate
pip install netbox-openbao
```

Add to `configuration.py`:

```python
PLUGINS = ['netbox_openbao']

PLUGINS_CONFIG = {
    'netbox_openbao': {
        # All settings have defaults; override only what you need.
    },
}
```

Apply migrations and restart. NetBox must restart **both** the web service and
the RQ worker — the plugin registers background jobs, and a stale worker will
not pick them up:

```bash
python manage.py migrate
systemctl restart netbox netbox-rq
```

## OpenBao side

Create a KV v2 mount and a policy scoped to the plugin's path prefix. Scope it
to the prefix, not the whole mount: the plugin should not be able to read
secrets it did not write.

```bash
bao secrets enable -version=2 -path=secret kv

bao policy write netbox-prod - <<'POLICY'
path "secret/data/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/netbox/credentials/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
POLICY

bao auth enable approle
bao write auth/approle/role/netbox-prod \
    token_policies=netbox-prod \
    token_ttl=1h \
    token_max_ttl=4h
```

Read the RoleID and a SecretID:

```bash
bao read -field=role_id auth/approle/role/netbox-prod/role-id
bao write -f -field=secret_id auth/approle/role/netbox-prod/secret-id
```

## Delivering the AppRole to NetBox

**Never put this in `configuration.py`, a model field, or a tracked file.** The
plugin reads it from the environment at login time, keyed by a prefix derived
from the engine's slug: slug `prod-core` becomes `NETBOX_BAO_PROD_CORE`.

With systemd, use an `EnvironmentFile` that is `0600` and owned by the NetBox
user:

```ini
# /etc/systemd/system/netbox.service.d/openbao.conf
[Service]
EnvironmentFile=/etc/netbox/openbao.env
```

```bash
# /etc/netbox/openbao.env  (chmod 600)
NETBOX_BAO_PRIMARY_ROLE_ID=...
NETBOX_BAO_PRIMARY_SECRET_ID=...
```

Apply the same drop-in to `netbox-rq.service` — background jobs authenticate
too, and a worker without the material will report every engine as
misconfigured.

For Docker or Kubernetes, prefer the `_FILE` indirection so the value never
appears in the process environment (where it is readable via
`/proc/<pid>/environ`):

```bash
NETBOX_BAO_PRIMARY_SECRET_ID_FILE=/run/secrets/bao-secret-id
```

## Broker mode

Optional. Set a `SecretEngine`'s **backend** to `Broker (netbox-openbao-broker)`
and point its **API URL** at a running
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker).
NetBox then presents a client certificate to the broker, and the broker holds
the AppRole. Nothing above the backend abstraction changes.

Read [the broker's threat model](https://github.com/emersonfelipesp/netbox-openbao-broker#what-this-buys-stated-honestly)
before deploying it. In short: an attacker with code execution in NetBox can
still *ask* the broker for material and be answered. What changes is that
stealing the database or the configuration no longer yields vault credentials,
and that the audit record is outside NetBox's reach.

The client certificate is named by **paths on the NetBox host**, keyed on the
engine's environment prefix — the same prefix the AppRole would use:

```bash
NETBOX_BAO_PRIMARY_CLIENT_CERT=/etc/netbox/openbao/netbox-prod.pem
NETBOX_BAO_PRIMARY_CLIENT_KEY=/etc/netbox/openbao/netbox-prod.key
```

These are paths, not material, so there is no `_FILE` form — there is no value
here to keep out of `/proc/<pid>/environ`. The key file must be readable by the
NetBox user and by the RQ worker, and by nobody else.

The engine's **CA certificate path** and **TLS verify** fields verify the
*broker's* server certificate. Set the CA path if the broker's certificate is
issued by an internal PKI, which it usually is.

**Verification cannot be turned off in broker mode.** Direct mode tolerates
`tls_verify = False` and the cost is a short-lived token presented to whoever
answers; here the client certificate is the credential and it is long-lived, so
an unverified peer is a credential handed to a man in the middle. A self-signed
broker certificate is served by pointing the CA certificate path at it, so this
refuses nothing legitimate.

A `CredentialPolicy` tier can present its **own** certificate by setting
`<TIER_PREFIX>_CLIENT_CERT` / `_CLIENT_KEY`. The broker identifies callers by
the certificate's subject common name, so a different certificate is a
different broker instance with a different set of permitted path prefixes —
the tiering that AppRoles give you in direct mode is preserved, not flattened.

Three engine fields are **ignored** in broker mode, deliberately:

| Field | Why |
|---|---|
| KV mount | The broker reads its own. Letting NetBox choose would let a compromised NetBox address mounts the operator never granted. |
| Namespace | Likewise. |
| Authentication method | The client certificate *is* the authentication. |

The broker serves **KV v2 only**; an engine set to version 1 is refused before
any request is sent.

For Web UI and REST administration parity, enable `access`, `authentication`,
`cluster`, `finalization`, `mounted-secrets`, and `secret-engines` in the
broker instance's `administration_families`. The plugin verifies contract
version `1`, the pinned registry digest, and exact operation classifications.
Partial or incompatible contracts fail closed and never fall back to direct
OpenBao. See [Run broker mode](how-to/broker-mode.md) for the configuration,
upgrade, rollback, and retirement procedures.

One operational note that has already caught a test suite: if the broker
instance is configured `may_delete = false`, the plugin can read, write, and
rotate but **cannot delete** a credential's secret material — those calls come
back as an authorization failure naming the instance's permissions.

That also disables the rollback compensator. When a credential write succeeds in
OpenBao and then the NetBox transaction fails, the plugin normally removes what
it wrote; a broker that refuses the delete turns that into a logged
`ORPHANED SECRET` — and nothing will find it afterwards, because
`CredentialVerifyJob` scans existing rows and this residue has none. Both
postures are defensible; if you choose `may_delete = false`, alert on that log
line rather than expecting a job to reconcile it.

## Using HashiCorp Vault instead

Set a `SecretEngine`'s **backend** to `HashiCorp Vault`. Everything else is
identical — same KV v2 mount, same AppRole setup, same environment variables.

That is not an aspiration: the plugin's entire wire-protocol contract runs as a
single shared test suite against both servers, and every case passes on both —
check-and-set on create and on a stale version, per-version reads, version
listing, version-scoped deletes, `custom_metadata` round-trips, and error
scrubbing.

The differences that do exist are cosmetic and handled:

- Vault's `sys/health` returns a strict superset of OpenBao's payload, adding
  `performance_standby`, `enterprise`, `clock_skew_ms`, `echo_duration_ms`, and
  `replication_primary_canary_age_ms`. Every field the plugin reads is present
  on both.
- A Vault performance standby is reported with a message saying so, since it
  serves reads and an operator otherwise has to guess why a "standby" node is
  answering.
- **Version strings are not comparable between the two projects.** Never infer
  capability from them.

To run the suite against Vault yourself:

```bash
docker run -d --name vault-dev -p 8300:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=devroot --cap-add=IPC_LOCK \
  hashicorp/vault:latest server -dev

export NETBOX_VAULT_TEST_ADDR=http://127.0.0.1:8300
export NETBOX_VAULT_TEST_TOKEN=devroot
python manage.py test netbox_openbao
```

Both integration classes skip cleanly when their address is unset.

## First engine

Create a `SecretEngine` in the UI (**OpenBao → Secret engines**) or via the API,
then check it resolved:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://netbox.example.net/api/plugins/openbao/engines/1/health/
```

A `healthy` status means the URL, TLS, and authentication all work. `unauthorized`
almost always means the environment variables are missing from the unit that is
actually running — check the RQ worker as well as the web service.

## NetBox 4.6 and 4.7

Both are supported. This section used to say 4.7 was a hard floor and list four
reasons; three of them turned out not to be true, and they are worth correcting
rather than deleting, because the same mistake is easy to repeat.

Each name the plugin uses was imported under both releases. **61 of 64 NetBox
imports, and 29 of 30 `netbox.ui` attributes, are identical.**

| Claimed 4.7-only | Actually |
|---|---|
| `ipam.Service` moved its parent to a generic foreign key | Already true in 4.6 |
| `register_model_actions` for custom permissions | Present in 4.6 |
| The declarative `netbox.ui` panel framework | Present in 4.6 |
| `GenericObjectChoiceField` | **Genuinely 4.7-only** |

So the real differences are four, all handled in `netbox_openbao/compat.py`:

- **Service ports.** 4.7 uses a `port_mappings` array; 4.6 uses `protocol` +
  `ports`. Quick-add writes whichever the model has.
- **`Choice`.** 4.7 wraps choice entries in a class carrying a description;
  4.6 uses plain tuples. Descriptions do not render on 4.6.
- **`ArrayAttr`.** 4.7 renders list attributes as chips; on 4.6 they are joined
  into text.
- **`GenericObjectChoiceField`.** The assignment form uses one combined
  selector on 4.7 and a separate type + ID pair on 4.6. Same assignment, but
  the 4.6 object list does not narrow as you choose a type.

Nothing about how secrets are stored, revealed, or audited differs between the
two.

### One wart, on 4.6 only

`makemigrations --check` is not clean on 4.6. NetBox's own inherited `owner`
field renders with `related_name='+'` on 4.7 and the default on 4.6, and the
committed migration can only record one of them.

It is state-only — `related_name` never touches the database, so the migration
Django wants to generate would produce no SQL — and it does not affect
`migrate`, which is what installs and upgrades run. Do not run
`makemigrations` for this plugin on 4.6 and commit the result.
