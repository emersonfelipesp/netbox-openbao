# netbox-openbao — Agent Guide

A NetBox plugin that keeps **secret material in OpenBao** while **NetBox owns
credential inventory and relationships**.

Repository: <https://github.com/emersonfelipesp/netbox-openbao>.

## Hard constraints

**NetBox 4.6 and 4.7** (`min_version = "4.6.0"`,
`max_version = "4.7.99"`) and **OpenBao 2.6.x**.

This used to read "4.7 only — do not add 4.6 compatibility shims", on the
stated grounds that `ipam.Service` had changed in two ways. Only one of them
had. The parent GenericForeignKey was already present in 4.6; just the port
representation differs. Checked by importing every name the plugin uses under
both releases rather than by reading release notes: **61 of 64 NetBox imports
and 29 of 30 `netbox.ui` attributes are identical**, including the whole
declarative panel framework, `netbox.api.gfk_fields`, `netbox.jobs` and
`netbox.forms`, all of which the old note assumed were 4.7-only.

The floor matters operationally, which is why it was worth rechecking: the
estate still runs 4.6.5 while `netbox-nms` supports 4.5.8–4.7.99. Keeping the
4.6 floor preserves a common installable version today without preventing the
exact 4.7 beta source gate.

**Every 4.6/4.7 difference lives in `netbox_openbao/compat.py`** — read its
docstring before adding a version check anywhere else, and add it there if you
must add one. See [Verified 4.7 facts](#verified-47-facts).

**Python 3.12+, PostgreSQL 15+ with `ltree`, Redis 6+.**

## The rule that matters most

> **Secret material must never become a model field, a form field bound to an
> instance, a log line, an exception message, or a changelog entry.**

`Credential` has no column capable of holding material, and that absence is the
foundation of every other guarantee. `netbox_openbao/tests/test_security.py`
enforces it by walking the model's fields and failing on any secret-shaped
name. **If you are about to add a field named `password`, `private_key`,
`token`, or similar to a model, stop — you are undoing the design.**

Everything that touches material goes through `services.py`. Views,
serializers, forms, and jobs never call a backend directly. Keep it that way:
one chokepoint is what makes the plugin auditable.

## Verified 4.7 facts

These were reconfirmed against the exact `v4.7.0-beta2` source. Several contradict
what 4.5/4.6-era plugin documentation says — do not "correct" them back:

1. **`ipam.Service`** replaced `protocol` + `ports` with a single
   `port_mappings` `ArrayField` of `"tcp/22"` strings. Its parent is a
   **GenericForeignKey** (`parent_object_type`/`parent_object_id`) rather than
   direct Device/VM FKs — but that half is **also true on 4.6**, contrary to
   what this list said before. Only the ports differ, and `quickadd` handles
   both by checking whether the model has `port_mappings`.
2. **Custom permission actions** register via `Meta.permissions` on the model,
   which NetBox auto-registers through `register_model_actions(model, actions)`
   — note the plural, model-first signature. There is no
   `register_model_action('reveal', models=[...])`.
3. `'reveal'` is a legal action name: `RESERVED_ACTIONS = ('view', 'add',
   'change', 'delete')`.
4. **Background jobs** use the `@system_job(interval_minutes)` decorator from
   `netbox.jobs`.
5. **Detail views are declarative.** `netbox.ui` — `layout.SimpleLayout`
   plus `panels` and `attrs` — replaces hand-written detail templates. Use
   `ui/panels.py`, not new templates. Present in 4.6 too; the only attribute
   this plugin uses that 4.6 lacks is `ArrayAttr`, shimmed in `compat.py`.
6. The **version gate compares `RELEASE.version`**, which is `"4.7.0"` on
   `4.7.0-beta2` (the `beta2` designation is a separate field), so the current
   beta remains within the declared `4.6.0`–`4.7.99` range.
7. `GenericObjectChoiceField` / `GenericObjectFormMixin` handle generic-FK
   form fields. **4.7 only** — `CredentialAssignmentForm` falls back to a
   separate type + ID pair on 4.6, which loses the HTMX re-render but produces
   the same assignment. `FieldSet(html_id=…)` is 4.7-only for the same reason
   and is passed conditionally.
8. GFK idiom: `to='contenttypes.ContentType'`, `on_delete=models.PROTECT`,
   `related_name='+'`.

## Traps already paid for

Each of these cost a debugging cycle. They are load-bearing, not stylistic.

- **`get_client_ip()` returns a `netaddr.IPAddress`, not a string.**
  `GenericIPAddressField` cannot adapt it. Because the audit write is
  best-effort (it must never mask the operation's outcome), the failure was
  swallowed and **every HTTP-originated access went unrecorded**. Always
  `str()` it.
- **Django has no rollback hook.** `transaction.on_commit` fires only on
  commit. The write path compensates explicitly in an `except` block; do not
  "simplify" it into an `on_commit` callback.
- **A rolled-back credential still holds a primary key in memory.** FK-ing an
  audit entry to it raises a deferred FK violation at commit. `log_access`
  takes `link=False` for that case; `_row_exists()` decides.
- **`full_clean()` runs `clean_fields()` before `clean()`.** Defaults that
  need to satisfy a `null=False` field must be applied in `full_clean()`, not
  `clean()`, or the API rejects the request before the default can apply.
- **`ValidatedModelSerializer` builds `Model(**attrs)`** to run `full_clean()`.
  Any non-model serializer field (`secret_data`) must be popped before
  `super().validate()`.
- **`bcrypt` is a real dependency.** `cryptography` delegates the OpenSSH
  bcrypt KDF to it and NetBox does not ship it, so passphrase-protected
  OpenSSH keys fail with `UnsupportedAlgorithm` without it.
- **Filterset fields that traverse a relation need an explicit `field_name`.**
  NetBox derives extra lookups from it and raises `ValueError: Invalid field
  name/lookup` when the bare filter name does not resolve on the model.
- **`views.py` must be imported in `ready()`.** `@register_model_view`
  decorators live there and `urls.py` resolves them via `get_model_urls()`. Drop
  that import and every plugin URL 404s.
- **NetBox 4.7 needs `API_TOKEN_PEPPERS`** for v2 tokens. Without it every API
  test errors in `setUp` with `ValueError`, which does not look like a config
  problem.
- **`makemigrations` requires `DEVELOPER = True`.**
- **Every `ObjectView` still needs an `<app_label>/<model_name>.html` stub**,
  even when the page is entirely panel-driven. NetBox 4.7's declarative layout
  does not remove the template lookup — without the stub the detail page raises
  `TemplateDoesNotExist`. All five stubs live in `templates/netbox_openbao/`.
- **`NetBoxTable` injects an actions column** linking to `<model>_changelog`.
  On a plain (non-NetBoxModel) model that view does not exist and the list page
  dies with `NoReverseMatch`. Set `actions = columns.ActionsColumn(actions=())`.
- **Do not reimplement `ObjectEditView.post()`.** An earlier revision did, and
  silently dropped `restrict_form_fields()` (which limits related-object
  selectors to what the user may view), changelog snapshots, and
  `alter_object()`. Hook `form.save()` instead — the generic view already wraps
  it in a transaction — and raise `AbortRequest` for backend failures.
- **`super().clean()` can return `None`** in NetBox's form chain; fall back to
  `self.cleaned_data`.
- **`get_plugin_config()` returns `None`, not the default**, for a key absent
  from the merged config — which happens whenever `PLUGINS_CONFIG` is replaced
  after startup, including every `override_settings` in a test. `config.get_config`
  therefore treats `None` as "use the default". Before it did,
  `store_public_material` silently resolved to None and turned metadata
  extraction off, which looks exactly like the extractors failing.
- **An explicit `None` argument overrides a function default.** `generate_ssh_keypair(None)`
  raises rather than generating an Ed25519 key; callers must resolve the
  fallback themselves.
- **`TokenPermissions.perms_map` maps POST to `add_<model>`.** A custom POST
  `@action` therefore demands *create* rights unless you override it — which
  made `rotate` require `add_credential` and left `rotate_credential`
  decorative, and broke POST-`reveal` entirely. `api/permissions.py`
  remaps POST to `view_<model>` for both actions; the action's own permission
  is enforced through `restrict()`. The inherited write-token check still
  applies, so a read-only token cannot rotate.
- **Compensating a failed *rotation* must be version-scoped.** `backend.delete(path)`
  with no `versions` destroys the path and every version on it. On a create
  (`cas=0`) that is correct; on a rotation it would take the working secret
  with it — data loss strictly worse than the orphan the compensator exists to
  prevent. `store_credential` branches on `cas`.
- **Django's `ValidationError` is not translated by DRF** and escapes as a
  **500**. The service layer raises Django's (it also serves forms and
  management commands), so every API action calling it must convert —
  `api/views._as_drf_validation_error`. This bit the reveal endpoint's
  `require_reason` path before anyone noticed.
- **`kv_version` and `live_kv_version` legitimately diverge** after a discard,
  because OpenBao's version counter never goes backwards. Never infer "is
  something staged?" from comparing them; `staged_kv_version` is the answer.
- **Sharing a `requests.Session` across backends is safe only because hvac
  builds `X-Vault-Token` per request** and never assigns to `session.headers`.
  If that changes, two policy tiers on the same engine URL could send each
  other's tokens. Do not move auth onto the session.

- **A plain DRF viewset never applies object-permission constraints.** NetBox
  calls `queryset.restrict()` in `netbox.api.viewsets.BaseViewSet.initial()`, so
  a viewset built on `rest_framework.viewsets.ReadOnlyModelViewSet` is still
  gated on the model-level permission by `TokenPermissions` — which is exactly
  why it looks fine — while every **constraint** on the granting
  ObjectPermission is silently dropped. `CredentialAccessLogViewSet` was that
  viewset. Use `NetBoxReadOnlyModelViewSet` for a read-only NetBox endpoint;
  it composes only the retrieve and list mixins, so append-only survives, and
  its `CustomFieldsMixin`/`ExportTemplatesMixin`/`ETagMixin` all probe with
  `hasattr`/`getattr` and tolerate a plain Django model.
- **DRF runs `initial()` before it resolves the handler**, so a permission
  failure returns 403 and *masks* the 405 that would prove a route does not
  exist. A test asserting "the audit log rejects POST" therefore passes for the
  wrong reason if the user lacks the permission. Assert the absent handler on
  the viewset structurally, or grant the permission first and then assert 405 —
  `test_policy_gate` does both.
- **`rotate` is a permission, and `PATCH` is a rotation.** `PUT`, `PATCH`, and
  the bulk list endpoint all reach `perform_update()` under
  `change_credential`; a `secret_data` key there writes a new version. Gating
  only the dedicated `rotate` action leaves the same write reachable by a
  different verb. `_require_rotate` resolves it through `restrict()` so
  constraints apply.
- **Destroying a secret is irreversible; a transaction is not.** So the destroy
  goes *after* the commit — `post_delete` plus `transaction.on_commit`, never
  `pre_delete`. `perform_bulk_destroy()` puts N deletions in one transaction,
  so a `pre_delete` destroy meant one late failure wiped the material of every
  credential before it while restoring all their rows. The residue that remains
  in the other direction (row gone, secret present) is recoverable; that one is
  not.
- **`CredentialVerifyJob` cannot find an orphan.** It iterates existing
  credential rows, so it detects a row whose material is missing and is blind
  to material whose row is missing. Do not write that it reports orphans — the
  `ORPHANED SECRET` log line is the only signal until a mount-walking
  reconciler exists.
- **NetBox's `BaseViewSet` passes `fields`/`omit` to the serializer** for
  `?fields=`, `?omit=`, and `?brief=true`. A plain DRF `ModelSerializer` raises
  `TypeError: Field.__init__() got an unexpected keyword argument 'fields'` —
  a 500, not a 400. Use `netbox.api.serializers.BaseModelSerializer` even for a
  non-NetBoxModel.
- **Do not write that a per-tier AppRole stops a NetBox permission bug.** It
  does not. `get_backend()` picks the AppRole from the credential's own policy,
  so a bug that yields a `prod-core` credential reads it with the `prod-core`
  AppRole — the identity authorized for that path. Per-tier AppRoles bound
  blast radius: a leaked SecretID reaches only its tier, and a tier whose
  SecretID was never delivered to an instance is unreadable from it. Claim
  that, not more. This is the same mistake the broker-mode sentence was.
- **NetBox mutates the instance before your view code runs.**
  `ValidatedModelSerializer.validate()` `setattr()`s every validated attribute
  onto `self.instance` so it can `full_clean()` it, and Django's
  `ModelForm._post_clean()` calls `construct_instance()`. So by the time
  `perform_update()` or `form.save()` runs, `instance.<field>` is the
  **incoming** value, not the stored one. Any authorization decision that has
  to be made against the *current* state must re-read the committed row —
  `services.enforce_update_access` does. Getting this wrong is silent: the
  check runs, passes, and compares the caller against the value they chose.
- **An authorization check in a view is a check the other four surfaces do not
  have.** The `CredentialPolicy` group gate lived in
  `api/views.CredentialViewSet._authorize` and nowhere else, so the web UI
  served material the API refused. Anything of that shape belongs in
  `services.py`. Note also that `PATCH`/`PUT` are routed by DRF's own
  `update()` and never reach a custom action's authorization helper, so a gate
  applied only in that helper is bypassable by verb.
- **`netbox_openbao/secrets/` had no `__init__.py`** and worked only as an
  implicit namespace package. It now has one. A namespace portion inside a
  regular package merges with any same-named directory another distribution
  installs, and it is invisible to static tooling — which is how the
  documentation build found it.

## Testing

```bash
cd <netbox>/netbox
python manage.py test netbox_openbao

# Include the live-OpenBao tests — a fake proves nothing about whether hvac
# and OpenBao agree on check-and-set semantics.
export NETBOX_OPENBAO_TEST_ADDR=http://127.0.0.1:8200
export NETBOX_OPENBAO_TEST_TOKEN=devroot
python manage.py test netbox_openbao
```

`docker-compose.dev.yml` brings up PostgreSQL, Redis, and OpenBao 2.6 dev mode.
Full procedure in [`docs/development.md`](docs/development.md).

Broker-mode tests need a running
[`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker)
and skip cleanly without one:

```bash
export NETBOX_OPENBAO_BROKER_ADDR=https://localhost:8201
export NETBOX_OPENBAO_BROKER_CERT=/path/netbox-prod.pem
export NETBOX_OPENBAO_BROKER_KEY=/path/netbox-prod.key
export NETBOX_OPENBAO_BROKER_CA=/path/client-ca.pem
```

### Two things that will cost you an hour otherwise

- **A "hanging" test run has two causes, and the second one is invisible.**

  The obvious one is stale Postgres connections: killing a `--keepdb` run leaves
  backends holding the test database, and the next run blocks on them.

  ```sql
  SELECT pg_terminate_backend(pid) FROM pg_stat_activity
   WHERE datname LIKE 'test_%' AND pid <> pg_backend_pid();
  ```

  The other is the test database itself being unusable, which presents as a hang
  rather than as an error. A killed run can leave `test_openbao_test`
  half-migrated — the next run then dies on something like
  `column "status" of relation "dcim_module" already exists`, or, if Django
  decides to ask whether to delete it, blocks forever on a **prompt you cannot
  see**: with stdout block-buffered (any non-tty — a pipe, a CI log, an agent's
  captured output) the question never reaches you.

  In both cases `pg_stat_activity` shows `idle in transaction` waiting on
  `ClientRead`, which points at the database and tells you nothing. Look at what
  the process is blocked on instead:

  ```bash
  ls -l /proc/$PID/fd/0            # a tty or socket here -> it is waiting on input
  ```

  Two habits avoid the whole class. **Pass `--noinput` and redirect stdin** in
  any non-interactive run, so a prompt fails loudly instead of hanging — and
  when a run has been killed, **drop the test database** rather than trusting
  `--keepdb` to sort it out:

  ```sql
  DROP DATABASE IF EXISTS test_openbao_test;
  ```

  ```bash
  python manage.py test netbox_openbao --noinput --keepdb < /dev/null
  ```

  One more, on the diagnosis itself: `pgrep -f "manage.py test ..."` matches
  **the shell you typed it in**, so `until ! pgrep -f ...; do sleep 5; done`
  never exits and a "still running" reading can be entirely your own loop. Match
  on the interpreter instead:

  ```bash
  for p in $(pgrep -x python); do readlink /proc/$p/exe | grep -q nb47 && echo "$p"; done
  ```

- **Never `pkill -f "manage.py test"`.** The pattern matches the shell that ran
  it, so the kill takes your own session with it (exit 144). Match narrowly on
  the interpreter path, or find the process by its database connection.

### Why the live tests are not optional

Three separate defects have hidden behind a passing fake in this repository:
a whole-path delete where a version-scoped one was needed, tombstoned versions,
and an empty `custom_metadata` value that **both** OpenBao and Vault reject —
that last one broke credential creation against every real server while 200+
tests stayed green (#17). A fake only fails in ways its author already thought
of. Run against a real server before believing a green suite.

Current beta2 state: **308 tests** pass against exact NetBox 4.7.0-beta2 with a
live OpenBao 2.6 development server (`18` optional live-backend tests skip when
their endpoints are not configured). `ruff check` and
`makemigrations --check` are clean. The hosted compatibility matrix also keeps
NetBox 4.6.5 as the backward-regression target.

## When changing things

- **A new credential type** → `CredentialTypeChoices` + `CREDENTIAL_SCHEMAS` +
  (if needed) an extractor returning only `EXTRACTABLE_FIELDS` keys +
  `SECRET_INPUT_FIELDS`/`SENSITIVE_INPUT_FIELDS` in `forms.py`.
- **`Credential.credential_type` has no Django `choices` on purpose.** Django
  validates a choices field in `clean_fields()`, which would reject every
  operator-defined `CredentialTypeSchema` slug. Membership is checked in
  `clean()` instead, and the model supplies `get_credential_type_display()`
  because tables and panels call it.
- **`CredentialTypeSchema.extractor` must stay a registry name.** If it ever
  becomes a dotted path resolved with `import_string`, the model is remote code
  execution with a JSON Schema attached.
- **A new backend** → subclass `SecretBackend`, register it in
  `backends/BACKENDS` and `BackendChoices`, and add an integration subclass of
  `_KVIntegrationTests`. Never raise a vendor exception, never log material.
  A backend tested only against a different server proves nothing about it.
- **`BrokerBackend` is a transport swap, not a different store.** It speaks to
  [`netbox-openbao-broker`](https://github.com/emersonfelipesp/netbox-openbao-broker),
  which holds the AppRole so NetBox does not, and it must stay
  indistinguishable from direct mode above `SecretBackend` — same exception
  types for the same conditions. Three traps:
  - **Never send `kv_mount` or `namespace`.** They are the broker's own
    configuration. Sending them would let a compromised NetBox address mounts
    the operator never granted, which inverts the point of the mode.
  - **The client certificate is keyed on `env_prefix`**, exactly as the AppRole
    is. The broker identifies callers by certificate CN, so flattening this to
    one certificate would silently give every `CredentialPolicy` tier the same
    access.
  - **Never relay the broker's error text.** It is written not to leak policy,
    but this side cannot verify that, and forwarding a remote string gives up
    the guarantee `backends/exceptions.py` exists to provide.
- **Do not write that broker mode makes "a NetBox compromise not a secret
  compromise".** It does not, the README said so once, and it was wrong: an
  attacker with code execution in NetBox can still ask the broker and be
  answered. What it buys is that the database and configuration no longer carry
  vault credentials and that the audit log is out of reach. Claim that, not
  more.
- **Anything touching the reveal path** → re-read
  [`docs/security.md`](docs/security.md) first and make sure
  `tests/test_security.py` still fails when you break the invariant.
- **A behaviour change** → update `docs/` and this file in the same change,
  and rebuild the site: `pip install '.[docs]' && mkdocs build --strict`. The
  nav in `mkdocs.yml` is explicit, so a new page that is not listed there is
  built but unreachable — except under `docs/reference/`, which
  `scripts/gen_ref_pages.py` generates from the package at build time.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. In
short: every change that alters behaviour updates `docs/` and this file in the
same commit, `ruff check .` and `makemigrations --check` must be clean, and a
change to the reveal, write, or backend paths is expected to come with a test
that fails when the invariant it protects is broken.
