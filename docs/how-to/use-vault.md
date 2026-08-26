# Use HashiCorp Vault

Set a `SecretEngine`'s **backend** to `HashiCorp Vault`. That is the whole
change.

```bash
curl -X PATCH https://netbox.example.net/api/plugins/openbao/engines/1/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"backend": "vault"}'
```

Same KV v2 mount, same AppRole setup, same environment variables, same policy
shape. OpenBao is a fork of Vault and their KV v2 and AppRole surfaces remain
compatible, so `hvac` drives both unmodified.

## Why you can believe that

The plugin's entire wire-protocol contract runs as **one shared test suite
against both servers**, and every case passes on both:

- check-and-set on create (`cas=0`) and against a stale version
- per-version reads
- version listing, newest first
- version-scoped deletes leaving the others intact
- whole-path destroy
- `custom_metadata` round-trips
- error scrubbing on forbidden, not-found, conflict, and unavailable

That is a test result, not an assumption. `_KVIntegrationTests` is subclassed
once per server, and each subclass skips cleanly when its address is unset.

## The differences that do exist

They are cosmetic, and handled:

- **Vault's `sys/health` returns a strict superset** of OpenBao's payload,
  adding `performance_standby`, `enterprise`, `clock_skew_ms`,
  `echo_duration_ms`, and `replication_primary_canary_age_ms`. Every field the
  plugin reads — `initialized`, `sealed`, `standby`, `version` — is present on
  both, so health parsing needs no override.
- **A performance standby** serves reads while reporting `standby: true`.
  Treating it as a standby is correct; the status message says which kind it is
  so an operator is not left guessing why a "standby" node is answering.
- **An enterprise build** is noted in the status message.

!!! warning "Version strings are not comparable between the two projects"

    Never infer capability from a version number. OpenBao 2.6 and Vault 1.x are
    not on the same scale and never will be.

## Running the suite against Vault yourself

```bash
docker run -d --name vault-dev -p 8300:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=devroot --cap-add=IPC_LOCK \
  hashicorp/vault:latest server -dev

export NETBOX_VAULT_TEST_ADDR=http://127.0.0.1:8300
export NETBOX_VAULT_TEST_TOKEN=devroot
python manage.py test netbox_openbao --noinput
```

Run it against your **actual** Vault version before relying on it in
production. Compatibility between two independently evolving projects is a
property of the versions you are running, not of the projects.

## Mixing them

Nothing stops one NetBox from having an OpenBao engine and a Vault engine at
the same time. `backend` is a per-engine field, the backend is resolved per
operation, and credentials carry their engine.

That is also the migration path in both directions: create the second engine,
create credentials on it, and retire the first when nothing points at it.
