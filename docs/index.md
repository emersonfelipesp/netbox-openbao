---
hide:
  - navigation
---

# netbox-openbao

Secret material in **OpenBao**. Credential inventory and relationships in
**NetBox**.

```
netbox-secrets        stores secrets *in* NetBox.
netbox-vault-secrets  reads secrets in the *browser*.
netbox-openbao        keeps secrets in OpenBao and resolves them
                      *server-side over the API* — so your automation,
                      not just your operators, can use them.
```

That third line is the gap this plugin exists to close.

!!! warning "Status: early alpha"

    The data model, REST API, and security invariants are implemented and
    tested against NetBox 4.7 and OpenBao 2.6. Dynamic secrets — database and
    cloud credential engines — are deliberately not here yet; they are a
    different lifecycle rather than a bigger version of this one.

## The idea, in one table

Split **secret material** from **credential metadata**. Material lives only in
OpenBao. Everything non-secret lives in NetBox, fully searchable, filterable,
and API-queryable.

For an SSH keypair or a TLS certificate:

| Goes to OpenBao | Stays in NetBox (plaintext, indexed) |
|---|---|
| private key | public key |
| passphrase | SHA256 fingerprint |
| password | username |
| API token | key type and bit length |
| certificate private key | serial, issuer, subject, `not_before`, `not_after` |

So you can answer *"which certificates expire in the next 30 days?"*, *"which
devices trust fingerprint X?"*, or render a config template containing a public
key — **with zero OpenBao reads and no reveal permission**.

That is the headline feature, and it falls out of the split rather than being
bolted on. It is also why [`ExpiryScanJob`](architecture/background-jobs.md)
stays correct and fast while an engine is sealed: it never contacts one.

## Start here

<div class="grid cards" markdown>

-   :material-download: **[Install it](installation.md)**

    ---

    Requirements, the OpenBao side, and how the AppRole reaches NetBox without
    ever touching the database.

-   :material-rocket-launch: **[Your first credential](getting-started/first-credential.md)**

    ---

    Engine, policy tier, credential, assignment, reveal — end to end, in about
    ten minutes.

-   :material-sitemap: **[How it works](architecture/index.md)**

    ---

    The five models, the single write chokepoint, the reveal path, and why
    rotation has three states rather than one.

-   :material-shield-lock: **[What is guaranteed](security.md)**

    ---

    Fifteen properties, each enforced by a type, a constraint, or an absent
    column — and each with the test that fails when you break it.

</div>

## Why a Django plugin and not a sidecar service

This is a credentials plugin. A separate service resolving secrets would have
to answer *"is this NetBox user allowed to see this credential?"* itself — and
then you have two authorization implementations for your most sensitive data,
which will drift. Every drift is a privilege-escalation bug.

As a plugin it reuses NetBox's tokens, object permissions, constraints, and
changelog directly. Blocking I/O goes through NetBox's own RQ framework: a
single reveal is synchronous and sub-100 ms; bulk work is a background job.

The same reasoning applies *inside* the plugin, which is why every path that
touches material funnels through
[`services.py`](architecture/write-path.md#the-single-chokepoint) rather than
each view calling a backend for itself.

## What it is not

- **It is not a password manager.** Humans reveal credentials here; they do not
  browse them. If you want shared vaults, folders, and browser autofill for
  people, you want a password manager, and the two coexist fine.
- **It does not make NetBox trustworthy with secrets.** It makes NetBox stop
  holding them. [Broker mode](how-to/broker-mode.md) narrows the blast radius
  further, and its documentation is careful about how much — an attacker with
  code execution in NetBox can still ask the broker and be answered.
- **It is not a certificate authority.** It records certificates and their
  expiry. Issuing them is OpenBao's `pki` engine, and that is a different
  integration.

## Requirements

| | |
|---|---|
| NetBox | **4.7** (4.7.0 or later — [why](installation.md#why-47-only)) |
| Python | 3.12+ |
| PostgreSQL | 15+ with the `ltree` extension |
| Redis | 6+ |
| OpenBao | 2.6.x, KV v2 mount |
| HashiCorp Vault | supported as an alternative — [how](how-to/use-vault.md) |
| Broker mode | optional — [how](how-to/broker-mode.md) |

## License

Apache-2.0.
