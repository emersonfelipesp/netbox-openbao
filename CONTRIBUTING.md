# Contributing

Thanks for looking at this. It is a plugin whose job is to hold the most
sensitive data in a NetBox estate, so the contribution rules below are mostly
about keeping that defensible rather than about style.

## The one rule that outranks everything else

> **Secret material must never become a model field, a form field bound to an
> instance, a log line, an exception message, or a changelog entry.**

`Credential` has no column capable of holding material, and that absence is the
foundation of every other guarantee in [`docs/security.md`](docs/security.md).
`netbox_openbao/tests/test_security.py` enforces it by walking the model's
fields and failing on any secret-shaped name.

If you are about to add a field named `password`, `private_key`, `token`, or
similar to a model — stop. That is not a feature, it is the design being undone.

Everything that touches material goes through `netbox_openbao/services.py`.
Views, serializers, forms, and jobs never call a backend directly. One
chokepoint is what makes the plugin auditable, and it is also what stops an
authorization check from existing on one surface and not the others.

## Before you open a pull request

```bash
ruff check .
python manage.py makemigrations --check --dry-run   # needs DEVELOPER = True
python manage.py test netbox_openbao --noinput
```

Green is necessary but not sufficient — see the next section.

## Run the integration tests against a real server

The suite ships a `FakeBackend` so most tests need nothing running. **Do not
trust it on its own.** Three separate defects in this repository have hidden
behind a passing fake: a whole-path delete where a version-scoped one was
needed, tombstoned versions reported as alive, and an empty `custom_metadata`
value that *both* OpenBao and Vault reject — that last one broke credential
creation against every real server while 200+ tests stayed green.

A fake only fails in ways its author already thought of.

```bash
docker compose -f docker-compose.dev.yml up -d

export NETBOX_OPENBAO_TEST_ADDR=http://127.0.0.1:8200
export NETBOX_OPENBAO_TEST_TOKEN=devroot
python manage.py test netbox_openbao --noinput
```

The Vault and broker suites skip cleanly when their addresses are unset; see
[`docs/development.md`](docs/development.md) for both.

## What a change is expected to bring with it

| If you change… | …bring |
|---|---|
| the reveal, write, or backend path | a test that **fails** when the invariant it protects is broken. Re-read [`docs/security.md`](docs/security.md) first. |
| behaviour, setup, operations, the API, or architecture | the matching `docs/` update **in the same commit**, plus `CLAUDE.md`/`AGENTS.md` when an agent-facing fact changed |
| a model | a migration, and `makemigrations --check` clean |
| an authorization rule | the same rule on **every** surface — the REST actions, the full-page UI reveal, the HTMX reveal, the UI promote/discard, and the edit form. A gate implemented in one of them is a gate missing from the other four; that has already happened once. |

## Adding things

**A new credential type.** `CredentialTypeChoices` + `CREDENTIAL_SCHEMAS` + (if
it has extractable metadata) an extractor returning only `EXTRACTABLE_FIELDS`
keys + `SECRET_INPUT_FIELDS`/`SENSITIVE_INPUT_FIELDS` in `forms.py`. If the type
is specific to your estate rather than generally useful, define it as data with
a `CredentialTypeSchema` instead — see
[`docs/custom-credential-types.md`](docs/custom-credential-types.md).

**A new backend.** Subclass `SecretBackend`, register it in `backends/BACKENDS`
and `BackendChoices`, and add an integration subclass of `_KVIntegrationTests`.
Never raise a vendor exception, never log material. A backend tested only
against a *different* server proves nothing about it.

**A new extractor.** Add it to the `EXTRACTORS` registry. `CredentialTypeSchema.extractor`
must stay a *name from that registry* — if it ever becomes a dotted path
resolved with `import_string`, the model is remote code execution with a JSON
Schema attached.

## Scope

NetBox **4.7 only** (`min_version = "4.7.0"`, `max_version = "4.7.99"`).
Please do not send 4.6 compatibility shims: 4.7 changed `ipam.Service`, the
permission-action registration, and the detail-view framework, and supporting
both would mean branching on all three. The reasoning is in
[`docs/installation.md`](docs/installation.md#why-47-only).

`CLAUDE.md` carries a list of traps that each cost a debugging cycle. It is
worth ten minutes before your first change.

## Reporting a vulnerability

Not through a public issue. See [`SECURITY.md`](SECURITY.md).
