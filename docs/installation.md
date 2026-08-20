# Installation

## Requirements

| Component | Version | Why |
|---|---|---|
| NetBox | **4.7.0+** | See [Why 4.7 only](#why-47-only) |
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

## Why 4.7 only

NetBox 4.7 is a hard floor, not a conservative default:

- `ipam.Service` replaced `protocol` and `ports` with a single `port_mappings`
  array, and moved its parent to a generic foreign key.
- Custom permission actions register through `register_model_actions`, which is
  what gives `reveal` its own assignable, constrainable permission.
- The declarative `netbox.ui` panel framework replaced hand-written detail
  templates.
- `GenericObjectChoiceField` handles the assignment form's generic relation.

Supporting 4.6 would mean branching on every one of these.
