# Troubleshoot

Ordered by how often each one has actually happened, and written around the
failures whose symptom does not resemble their cause.

## The engine says `unauthorized`

Almost always the environment variables are missing from the unit that is
actually running — and almost always that unit is the **RQ worker**, not the
web service.

Both authenticate. The drop-in has to be applied to both:

```ini
# /etc/systemd/system/netbox.service.d/openbao.conf
# /etc/systemd/system/netbox-rq.service.d/openbao.conf
[Service]
EnvironmentFile=/etc/netbox/openbao.env
```

```bash
systemctl daemon-reload
systemctl restart netbox netbox-rq
systemctl show netbox-rq -p EnvironmentFiles
```

Check the prefix matches the engine's slug: `prod-core` →
`NETBOX_BAO_PROD_CORE_ROLE_ID`. Hyphens become underscores, and the whole thing
is upper-cased. The engine's detail page shows the resolved prefix with a copy
button, precisely because this is the most common failed deployment.

If a `CredentialPolicy` sets `approle_env_prefix`, **that** prefix must be
present too. A tier whose AppRole was never delivered fails at reveal time,
not at engine health — health uses the engine-wide credentials.

## Creating a credential fails, and the message says nothing useful

Check the OpenBao policy covers **both** `data/` and `metadata/`:

```hcl
path "secret/data/netbox/credentials/*"     { capabilities = ["create","read","update","delete"] }
path "secret/metadata/netbox/credentials/*" { capabilities = ["create","read","update","delete","list"] }
```

With `data/` alone the data write succeeds, the `custom_metadata` write is
refused, the transaction unwinds, and the
[compensator](../architecture/write-path.md) removes the orphaned path. What
you see is a failed create with no obvious cause.

→ [Scope an OpenBao policy](scope-openbao-policies.md)

## `A credential already occupies this path on this engine`

The `(engine, path)` unique constraint fired. Since the path is UUID-derived
this effectively cannot happen by collision — it means a `Credential` row was
created with a `path` copied from another, usually by a script that set `path`
directly.

`path` is `editable=False` and derived; do not set it.

## `409 Conflict` on a rotation

Check-and-set refused: someone wrote a new version between your read and your
write. That is the mechanism working.

Re-read the credential to pick up the current `kv_version`, decide whether the
other write was the one you wanted, and retry.

## A reveal returns 404 for a credential you can see in the list

An ObjectPermission **constraint** excludes it. A 404 rather than a 403 is
deliberate — a 403 would confirm the credential exists.

Check the constraints on the permission granting `reveal`, not just the one
granting `view`. They are separate actions and can carry different constraints.

## A reveal returns 403 and the message mentions groups

The [policy tier's group gate](policy-tiers.md#the-group-gate). The user holds
`reveal_credential` but belongs to none of the groups on the credential's
`CredentialPolicy`.

Either add them to a permitted group, or clear the tier's `groups` if you did
not intend to use that gate. The refusal is recorded in the access log, so
**OpenBao → Access log** filtered to `success=false` shows exactly who hit it.

## Every plugin URL 404s

`views.py` must be imported in `PluginConfig.ready()`. The
`@register_model_view` decorators live there, and `urls.py` resolves them
through `get_model_urls()` at URLconf load. Drop that import and every route
disappears.

## `TemplateDoesNotExist` on a detail page

NetBox 4.7's declarative layout does not remove the template lookup. Every
`ObjectView` still needs an `<app_label>/<model_name>.html` stub even when the
page is entirely panel-driven. All of the plugin's stubs live in
`templates/netbox_openbao/`.

## `NoReverseMatch` on `credentialaccesslog_changelog`

`NetBoxTable` injects an actions column linking to `<model>_changelog`. On a
plain (non-`NetBoxModel`) model that view does not exist. `CredentialAccessLogTable`
sets `actions = columns.ActionsColumn(actions=())` for exactly this.

## The reveal panel does not appear

It renders only for a user who holds `reveal_credential` **on that object**,
which is resolved in the view rather than guessed at in the template. If the
permission carries a constraint that excludes this credential, the panel is
correctly absent.

## Clicking Reveal does nothing at all

If the HTMX request returns a non-2xx status, HTMX does not swap by default.
The plugin catches `PermissionDenied` and backend errors and renders an error
fragment into the same slot, so a *silent* failure means something else — check
the browser console and NetBox's logs.

With JavaScript disabled the form falls back to its plain `action` attribute
and the full-page reveal view, which is why that view still exists.

## `UnsupportedAlgorithm: Need bcrypt module`

Loading a passphrase-protected OpenSSH private key. `cryptography` delegates
the OpenSSH bcrypt KDF to `bcrypt`, and NetBox does not ship it — it is a
declared dependency of this plugin, so this means the install did not bring
dependencies with it.

```bash
/opt/netbox/venv/bin/pip install 'bcrypt>=4.0.0'
```

## Background jobs never run

They are NetBox **system jobs**, scheduled by NetBox's RQ worker. Check
`netbox-rq.service` is running, then look under **Operations → Jobs**.

Intervals are read at **import time** by the `@system_job` decorators, so
changing one in `PLUGINS_CONFIG` needs a NetBox restart, not just a worker
restart.

## `CredentialVerifyJob` reports `missing`

NetBox has a credential row whose material does not exist at its path. Every
consumer of it will fail.

Either the material was deleted out of band, or a compensating delete removed
it after a failed write and the row survived (which should not happen, and is
worth reporting). Rotate new material onto it, or delete the row — deleting the
row is safe, since there is nothing left to orphan.

`unreachable` is different: a transport error, saying nothing about the data.

## `ORPHANED SECRET` in the logs

The write-path compensator could not remove material it had just written, so
there is a secret at a path NetBox has no row for.

**No job will find it.** `CredentialVerifyJob` iterates existing credential
rows, and this residue has none — it detects the opposite case, a row whose
material is missing. Alert on the `ORPHANED SECRET` string; it is the only
signal. Then find it by hand:

```bash
bao kv metadata list secret/netbox/credentials/
```

In [broker mode](broker-mode.md), an instance configured `may_delete = false`
produces this on **every** failed write, by design.

## Tests hang instead of failing

Two causes, and the second is invisible.

Stale PostgreSQL connections from a killed `--keepdb` run:

```sql
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname LIKE 'test_%' AND pid <> pg_backend_pid();
```

Or the test database is half-migrated and Django is asking whether to delete
it — on a **prompt you cannot see**, because stdout is block-buffered on any
non-tty. Pass `--noinput` and redirect stdin so a prompt fails loudly, and drop
the database rather than trusting `--keepdb` to sort it out:

```bash
python manage.py test netbox_openbao --noinput --keepdb < /dev/null
```

## Still stuck

Turn on plugin logging and reproduce:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {'console': {'class': 'logging.StreamHandler'}},
    'loggers': {
        'netbox.plugins.netbox_openbao': {'handlers': ['console'], 'level': 'DEBUG'},
    },
}
```

Nothing the plugin logs contains secret material — that is
[invariant](../architecture/invariants.md) rather than a hope — so these logs
are safe to attach to an issue. Backend errors are logged as a fixed string
plus the exception's *type*, never the server's response text, so if you need
to know what OpenBao actually said you will find it in **OpenBao's** audit
device, not here.
