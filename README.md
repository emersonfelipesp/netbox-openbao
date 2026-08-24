# netbox-openbao

Keep device, VM, and service **secret material in OpenBao**, while **NetBox
owns the credential inventory and its relationships**.

```
netbox-secrets        stores secrets *in* NetBox.
netbox-vault-secrets  reads secrets in the *browser*.
netbox-openbao        keeps secrets in OpenBao and resolves them *server-side
                      over the API* — so your automation, not just your
                      operators, can use them.
```

That third line is the gap this plugin exists to close.

> **Status:** early alpha. The data model, REST API, and security invariants are
> implemented and tested against NetBox 4.7 and OpenBao 2.6. See
> [Roadmap](#roadmap) for what is deliberately not here yet.

---

## The idea

Split **secret material** from **credential metadata**. Material lives only in
OpenBao. Everything non-secret lives in NetBox, fully searchable, filterable,
and API-queryable.

For an SSH keypair:

| Goes to OpenBao | Stays in NetBox (plaintext, indexed) |
|---|---|
| private key | public key |
| passphrase | SHA256 fingerprint |
| password | username |
| API token | key type and bit length |
| certificate private key | serial, issuer, subject, `not_before`, `not_after` |

So you can answer *"which certificates expire in the next 30 days?"*, *"which
devices trust fingerprint X?"*, or render a config template containing a public
key — **with zero OpenBao reads and no reveal permission**. That is the headline
feature, and it falls out of the split rather than being bolted on.

## Why a Django plugin and not a sidecar service

This is a credentials plugin. A separate service resolving secrets would have
to answer *"is this NetBox user allowed to see this credential?"* itself — and
then you have two authorization implementations for your most sensitive data,
which will drift. Every drift is a privilege-escalation bug.

As a Django plugin it reuses NetBox's tokens, object permissions, constraints,
and changelog directly. Blocking I/O is handled with NetBox's own RQ job
framework: a single reveal is synchronous and sub-100ms; bulk work is a
background job.

## Security properties

These are enforced structurally, not by convention, and each is covered by a
test in `netbox_openbao/tests/test_security.py`:

- **No model field can hold secret material.** There is no column to leak, so
  the changelog, export templates, and the REST representation are safe by
  construction rather than by careful configuration.
- **`secret_data` is `write_only`.** DRF itself refuses to serialize it — into a
  `GET`, a `brief=true` response, the browsable API, or an OpenAPI example.
- **`reveal` is a permission of its own**, separate from `view` and
  constrainable in the standard ObjectPermission UI. A role can inventory every
  credential and read none.
- **Reveal responses are JSON-only and `no-store`.** The browsable renderer
  would template the secret into cacheable HTML; it is explicitly removed.
- **The UI reveal is POST-only**, so a secret is never fetched by a bookmark, a
  prefetch, a link scanner, or a history replay.
- **No auth material in the database.** RoleIDs and SecretIDs come from the
  process environment, or a file it points at.
- **Per-tier AppRoles.** A NetBox-side permission bug still cannot read material
  the tier's OpenBao policy does not grant.
- **Backend exceptions carry no server text.** An OpenBao 403 body can
  enumerate policy rules; it never reaches a log, a traceback, or a response.
- **Every access is audited** — who, when, from where, and whether it
  succeeded. Never the value.

## Requirements

| | |
|---|---|
| NetBox | **4.7** (4.7.0 or later; 4.6 and earlier are not supported) |
| Python | 3.12+ |
| PostgreSQL | 15+ with the `ltree` extension (a NetBox 4.7 requirement) |
| Redis | 6+ |
| OpenBao | 2.6.x, KV v2 mount |
| HashiCorp Vault | supported as an alternative backend — see below |
| Broker mode | optional; needs [`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker) |

NetBox 4.7 is required deliberately rather than incidentally: it replaced
`ipam.Service`'s `protocol`/`ports` with `port_mappings` and moved the service's
parent to a generic foreign key, and it introduced the declarative UI panel
framework and `register_model_actions` that this plugin builds on. Supporting
4.6 would mean branching on all of it.

## Install

```bash
pip install netbox-openbao
```

```python
# configuration.py
PLUGINS = ['netbox_openbao']

PLUGINS_CONFIG = {
    'netbox_openbao': {
        'assignable_models': [
            'dcim.device',
            'virtualization.virtualmachine',
            'ipam.service',
        ],
    },
}
```

```bash
python manage.py migrate
systemctl restart netbox netbox-rq
```

Then export the AppRole material for each engine. The prefix is derived from
the engine's slug — slug `prod-core` becomes `NETBOX_BAO_PROD_CORE`:

```bash
NETBOX_BAO_PRIMARY_ROLE_ID=...
NETBOX_BAO_PRIMARY_SECRET_ID=...
```

Either variable also accepts a `_FILE` form pointing at a mounted secret, which
keeps the value out of `/proc/<pid>/environ`:

```bash
NETBOX_BAO_PRIMARY_SECRET_ID_FILE=/run/secrets/bao-secret-id
```

Full detail in [`docs/installation.md`](docs/installation.md) and
[`docs/configuration.md`](docs/configuration.md), or on the documentation site:
<https://emersonfelipesp.github.io/netbox-openbao/>.

## Using it

```bash
# Inventory — never returns material
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/?credential_type=x509-keypair'

# Everything expiring in the next 30 days — zero OpenBao reads
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/?expires_within_days=30'

# What does device 88 hold?
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/?assigned_object_type=dcim.device&assigned_object_id=88'

# Resolve material — requires netbox_openbao.reveal_credential
curl -H "Authorization: Bearer $TOKEN" \
  'https://netbox.example.net/api/plugins/openbao/credentials/142/reveal/?reason=CHG-1234'
```

## OpenBao or Vault

The plugin is named for OpenBao and that is its reference backend, but a
`SecretEngine` can be pointed at **HashiCorp Vault** instead by changing one
field. The two share the KV v2 and AppRole surfaces, and the plugin's whole
wire-protocol contract is run as one shared suite against both servers, so this
is verified rather than claimed.

## Broker mode, and what it is honestly worth

A third backend, `broker`, points an engine at
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker)
instead of at OpenBao. NetBox then holds a **client certificate** that lets it
*ask*, and the broker holds the AppRole that can actually *read*.

It is worth being precise about what that buys, because it is easy to oversell
and an operator might relax controls elsewhere on the strength of it:

> **It does not make "NetBox compromise ≠ secret compromise" true.** An attacker
> with code execution in NetBox can still ask the broker for material, and the
> broker will answer for anything NetBox is authorized to request.

What it does buy: stealing NetBox's database or configuration no longer yields
credentials that read the vault directly, the broker's audit log sits outside
NetBox's blast radius, and the AppRole's SecretID never exists on the NetBox
host at all. That is a real improvement against offline compromise, backup
theft, and configuration leakage — and it is not the stronger claim.

Optional throughout. The default deployment is unchanged, and nothing above the
`SecretBackend` abstraction knows which mode is in use. See
[`docs/installation.md`](docs/installation.md#broker-mode).

## Data model

| Model | Role |
|---|---|
| `SecretEngine` | One OpenBao instance and KV mount. Holds no auth material. |
| `CredentialPolicy` | An authorization tier mapped onto a real OpenBao policy, with its own AppRole. |
| `Credential` | The inventory record: identity, public material, lifecycle. Never the secret. |
| `CredentialAssignment` | Many-to-many binding to Devices, VMs, and Services, with a purpose. |
| `CredentialAccessLog` | Append-only correlation between a NetBox user and an OpenBao read. |

The OpenBao path is UUID-derived and immutable
(`<prefix>/credentials/<uuid>`). A path derived from the object graph would
break the first time a credential is renamed or reassigned, and a broken path
is an orphaned secret nobody can find. Discovery instead comes from KV v2
`custom_metadata`, which also lets the health job spot orphans.

## Roadmap

Implemented: the five models, the backend abstraction with the OpenBao
implementation, credential type schemas and extractors, the full REST API with
the security invariants above, list/detail/edit UI, Device/VM/Service panels,
the background jobs, and staged rotation (write, verify, promote — never break
running access).

Also shipped since: the
[Ansible lookup plugin](https://github.com/emersonfelipesp/netbox-openbao-ansible)
and [broker mode](#broker-mode-and-what-it-is-honestly-worth), whose earlier
description here — "so a NetBox compromise is not a secret compromise" —
claimed more than the design delivers and has been corrected above.

Deliberately not yet here:

- Dynamic secrets (database and cloud credential engines), which are a
  different lifecycle rather than a bigger version of this one

## Giving a device SSH access

There is an **Add SSH access** button on every Device and VM page. One form
creates the `ipam.Service`, generates or accepts the keypair, writes the
private half to OpenBao, and assigns the credential — in a single transaction.
If it generates the key, the **public** half is shown once so it can go
straight into `authorized_keys`.

## Coming from netbox-secrets?

```bash
python manage.py openbao_import_secrets --engine primary --policy imported --dry-run
```

The importer copies — it never deletes — infers each secret's type and proves
the inference by extraction, and is resumable. See
[`docs/migration-from-netbox-secrets.md`](docs/migration-from-netbox-secrets.md).

## Development

```bash
docker compose -f docker-compose.dev.yml up -d
```

See [`docs/development.md`](docs/development.md) for running the suite against
real NetBox 4.7 and a live OpenBao dev server, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for what a change is expected to bring
with it.

The documentation site builds from the checkout with no package install and no
NetBox — `mkdocstrings` reads the source statically:

```bash
pip install '.[docs]'
mkdocs serve
```

## License

Apache-2.0.
