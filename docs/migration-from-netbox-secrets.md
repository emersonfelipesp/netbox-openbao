# Migrating from netbox-secrets

`netbox-secrets` stores secrets encrypted **in NetBox's own database**. This
plugin moves the material to OpenBao and leaves NetBox holding only non-secret
metadata. The importer copies; it never deletes.

## Before you start

You need:

- A `SecretEngine` that is healthy, and a `CredentialPolicy` on it for the
  imported credentials to land on.
- A **netbox-secrets session key** for a user whose UserKey can decrypt the
  secrets you want to move.

## The session key is never a command-line argument

`argv` is readable by any process on the host via `/proc/<pid>/cmdline`, and it
lands in shell history. A key passed that way is compromised the moment it is
typed, so the command does not accept one. Use the environment:

```bash
read -rs NETBOX_SECRETS_SESSION_KEY   # not echoed, not in history
export NETBOX_SECRETS_SESSION_KEY
```

or run interactively and be prompted.

## Dry run first

```bash
python manage.py openbao_import_secrets --engine primary --policy imported --dry-run
```

This writes nothing and prints the **inferred type per secret**, which is the
thing worth checking before committing:

```
Planning 3 secret(s) onto engine 'primary':
  plan  #1 core-sw-01 admin -> password
  plan  #2 fleet ssh key -> ssh-keypair
  plan  #3 legacy blob -> generic-kv

would import: 3   skipped: 0   failed: 0
```

### How typing works

`netbox-secrets` has no type field — a secret is just a string. The importer
infers a type and then **proves it**: a candidate is only accepted if this
plugin's own extractors can genuinely parse the material as that type.

| Material | Type |
|---|---|
| Parses as an SSH/PEM private key | `ssh-keypair` |
| Parses as a certificate, with a key alongside | `x509-keypair` |
| Parses as a certificate alone | `x509-ca` |
| A single line with no structure | `password` |
| Anything else | `generic-kv` |

Anything that fails to parse falls back to `generic-kv`, which stores the value
faithfully and claims nothing about it. That fallback matters: metadata derived
from a wrong guess is worse than no metadata, because it looks authoritative.

Material is copied **byte-identically**. Detection ignores surrounding
whitespace; storage does not.

## Run it

```bash
python manage.py openbao_import_secrets --engine primary --policy imported
```

Each secret is its own transaction, so one failure does not abandon the rest,
and the run is **resumable** — provenance is recorded in
`Credential.import_source`, and re-running skips anything already moved:

```bash
python manage.py openbao_import_secrets --engine primary --policy imported
  skip  #1 core-sw-01 admin (already imported)
```

`--limit N` moves a first batch if you would rather verify a sample.

## Roles

By default every imported credential lands on the `--policy` you named.
`--map-roles` instead creates a `CredentialPolicy` per `netbox-secrets` role.

That is opt-in for a reason: a `netbox-secrets` role has no counterpart in
OpenBao, so a policy created from one names an OpenBao policy that **does not
exist yet**. Creating those silently would turn a successful-looking import
into a pile of credentials that fail at the first reveal. With `--map-roles`
the command lists exactly which policies you still need to create:

```
These policies were created and name an OpenBao policy that does not exist yet.
Create them in OpenBao, or reveals against these credentials will fail:
  netbox-production
```

## Afterwards

`netbox-secrets` is untouched. Verify the imported credentials resolve — a
`reveal` on a sample is the honest check — before retiring the originals.
Removing the source data is a separate, deliberate decision.
