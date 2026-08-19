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
        'default_engine': 'primary',
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
