# Rotate without breaking consumers

Two ways to replace a credential's material. Pick by how many things depend on
it.

| | Use when |
|---|---|
| **`rotate`** | One consumer, and you control it. Writes and promotes in one step. |
| **`stage` → verify → `promote`** | Anything else. The old version keeps serving until you say otherwise. |

## The simple case

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/credentials/142/rotate/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"secret_data": {"password": "the-new-one"}}'
```

```json
{"id": 142, "kv_version": 4}
```

Needs `rotate_credential` and a write-enabled token. Check-and-set runs against
the recorded `kv_version`, so a rotation cannot clobber a concurrent write it
never saw — a `409` means someone else got there first, and you should re-read
before retrying.

## The safe case

### 1. Stage

```bash
curl -X POST https://netbox.example.net/api/plugins/openbao/credentials/142/stage/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"secret_data": {"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}}'
```

```json
{
  "id": 142,
  "status": "staged",
  "kv_version": 7,
  "live_kv_version": 6,
  "has_staged_version": true
}
```

**Every `reveal` still returns version 6.** Nothing that depends on this
credential has noticed anything.

In the UI: tick **Stage this change instead of applying it now** on the edit
form.

### 2. Deploy and verify

Push the new key to the devices. Confirm it works — actually log in, actually
run the automation. This step is the entire reason staging exists, and it is
the one the plugin cannot do for you.

Read the staged version explicitly if you need it:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  '.../credentials/142/reveal/?version=7&reason=CHG-1234'
```

### 3a. It worked — promote

```bash
curl -X POST .../credentials/142/promote/ \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"verified": true, "note": "confirmed on core-sw-01 and core-sw-02"}'
```

Nothing is written to OpenBao; the material is already there. Promotion just
moves the live pointer, which is why it cannot fail halfway.

It does confirm the staged version still exists first. Flipping the pointer to
a version destroyed out of band would break every consumer at once, silently,
because nothing reads material during promotion.

`verified` and `note` land in the access log. That is where *"was this rotation
actually checked?"* gets answered six months later.

### 3b. It did not — discard

```bash
curl -X POST .../credentials/142/discard/ -H "Authorization: Bearer $TOKEN"
```

Destroys **only** the staged version. The live one is never touched, the status
returns to `active`, and nothing that depends on the credential ever saw the
candidate.

Then stage again. There is no limit on attempts.

## Reading the version fields

```bash
curl -H "Authorization: Bearer $TOKEN" .../credentials/142/versions/
```

Metadata only, never values — so this needs `view_credential`, not
`reveal_credential`.

| Field | Meaning |
|---|---|
| `kv_version` | Highest version ever written. What check-and-set compares against. |
| `live_kv_version` | What consumers are served. Empty means "latest". |
| `staged_kv_version` | A candidate awaiting a decision. Empty when none. |

!!! warning "Do not infer 'staged' from `kv_version > live_kv_version`"

    That comparison is **true after every discard**, because OpenBao's version
    counter does not go backwards when a version is deleted. Read
    `has_staged_version` (or `staged_kv_version`) instead.

## Knowing when to rotate

Set `rotation_interval` on the credential, in days.
[`RotationDueJob`](../architecture/background-jobs.md#rotationduejob) then logs
whatever is overdue, measured from `last_rotated` or, failing that, `created`.

It reports; it does not rotate. Automatic rotation would mean the plugin
generating and deploying material without anyone deciding to, and deployment is
the half it does not own.

## Permissions

All four transitions need `rotate_credential`, not four separate permissions.
They are steps of one operation, and anyone trusted to replace material is
necessarily trusted to finish or abandon the replacement — splitting them would
create combinations with no coherent meaning, such as the right to promote
material you were not allowed to stage.

The tier's [group gate](../architecture/reveal-path.md#what-has-to-pass) applies
to all of them, on both the REST and UI surfaces.
