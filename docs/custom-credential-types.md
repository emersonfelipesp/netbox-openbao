# Operator-defined credential types

The built-in types — `password`, `ssh-keypair`, `x509-keypair`, and the rest —
are Python. Adding one meant a plugin release, so an estate with a vendor API
key, a RADIUS shared secret, or a database DSN could not model it without
forking.

**Credential types** (OpenBao → Configuration → Credential types) let you define
one as data.

## Defining a type

```json
{
  "type": "object",
  "properties": {
    "shared_secret": {"type": "string", "minLength": 8},
    "server":        {"type": "string"},
    "port":          {"type": "integer"}
  },
  "required": ["shared_secret", "server"]
}
```

with `secret_fields = ["shared_secret"]`.

The schema is a real JSON Schema and is enforced in full on every write — not
just required/unknown keys, but types, lengths, patterns, everything you put in
it.

## `secret_fields` is the security-critical part

It declares which properties hold secret material. **Anything not listed may be
mirrored into a NetBox column.** An omission here is a disclosure, not a
cosmetic slip, so the model refuses to save a `secret_fields` entry that is not
actually a property in the schema — a typo would otherwise mark nothing as
secret.

## `extractor` is a name, never a path

A type may name an extractor to derive non-secret metadata — `ssh` or `x509`
today. These are chosen from a **fixed registry of vetted functions**.

This is the constraint the whole model is shaped around. A JSONField that could
name any importable callable would be remote code execution wearing a schema,
so `extractor` is validated against the registry in the model's `clean()` —
which means the API enforces it too, not just the form. `os.system`,
`builtins.eval`, and a dotted path to a real extractor are all rejected, and
there are tests for each.

## What a stored type cannot do

- **It cannot shadow a built-in.** The plugin's own code paths assume the
  built-in definitions; a stored type quietly redefining `ssh-keypair` would
  change how existing credentials validate.
- **It cannot cause secret material to reach a NetBox column.** Whatever an
  extractor returns is filtered against a fixed allowlist of non-secret fields
  before anything is written, and the payload itself never touches a model
  field regardless of what its properties are called.

## Error messages

Validation failures report the failing **path**, never the value.
`jsonschema`'s own message embeds the failing instance, which for a secret
payload is the material itself — so it is deliberately not passed through.

## Using one

Once defined, the type appears in the credential form's type list and is
accepted by the REST API exactly like a built-in:

```bash
curl -X POST .../credentials/ -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "radius-01 shared secret",
        "credential_type": "radius",
        "policy": 3,
        "secret_data": {"shared_secret": "...", "server": "radius-01"}
      }'
```

## A note on `credential_type`

The `Credential.credential_type` field deliberately carries no Django
`choices`. Django validates a choices field in `clean_fields()`, which would
reject any operator-defined slug outright. Membership is validated in `clean()`
against the union of built-in and stored types instead — so a stored type is
accepted and a typo still is not.
