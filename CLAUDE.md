# netbox-openbao — Agent Guide

A NetBox plugin that keeps **secret material in OpenBao** while **NetBox owns
credential inventory and relationships**.

Repository: `https://git.nmulti.cloud/emersonfelipesp/netbox-openbao` (Gitea
only — this repo has no GitHub remote).

## Hard constraints

**NetBox 4.7 only** (`min_version = "4.7.0"`, `max_version = "4.7.99"`) and
**OpenBao 2.6.x**. Do not add 4.6 compatibility shims — 4.7 is a deliberate
floor, not an accident. See [Verified 4.7 facts](#verified-47-facts).

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

These were confirmed against the `v4.7.0-beta1` source. Several contradict
what 4.5/4.6-era plugin documentation says — do not "correct" them back:

1. **`ipam.Service`** replaced `protocol` + `ports` with a single
   `port_mappings` `ArrayField` of `"tcp/22"` strings, and its parent is a
   **GenericForeignKey** (`parent_object_type`/`parent_object_id`), not direct
   Device/VM FKs.
2. **Custom permission actions** register via `Meta.permissions` on the model,
   which NetBox auto-registers through `register_model_actions(model, actions)`
   — note the plural, model-first signature. There is no
   `register_model_action('reveal', models=[...])`.
3. `'reveal'` is a legal action name: `RESERVED_ACTIONS = ('view', 'add',
   'change', 'delete')`.
4. **Background jobs** use the `@system_job(interval_minutes)` decorator from
   `netbox.jobs`.
5. **Detail views are declarative.** NetBox 4.7 replaced hand-written detail
   templates with `netbox.ui` — `layout.SimpleLayout` plus `panels` and
   `attrs`. Use `ui/panels.py`, not new templates.
6. The **version gate compares `RELEASE.version`**, which is `"4.7.0"` on
   `4.7.0-beta1` (the `beta1` designation is a separate field), so
   `min_version = "4.7.0"` correctly loads on the current beta.
7. `GenericObjectChoiceField` / `GenericObjectFormMixin` handle generic-FK
   form fields.
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
- **Sharing a `requests.Session` across backends is safe only because hvac
  builds `X-Vault-Token` per request** and never assigns to `session.headers`.
  If that changes, two policy tiers on the same engine URL could send each
  other's tokens. Do not move auth onto the session.

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

Current state: **115 tests**, all passing against real NetBox 4.7.0-beta1 and a
live OpenBao 2.6.0. `ruff check` clean, `makemigrations --check` clean.

## When changing things

- **A new credential type** → `CredentialTypeChoices` + `CREDENTIAL_SCHEMAS` +
  (if needed) an extractor returning only `EXTRACTABLE_FIELDS` keys +
  `SECRET_INPUT_FIELDS`/`SENSITIVE_INPUT_FIELDS` in `forms.py`.
- **A new backend** → subclass `SecretBackend`; never raise a vendor exception,
  never log material.
- **Anything touching the reveal path** → re-read
  [`docs/security.md`](docs/security.md) first and make sure
  `tests/test_security.py` still fails when you break the invariant.
- **A behaviour change** → update `docs/` and this file in the same change.

## Workspace policy

This repo follows the `personal-context` workspace rules: Gitea-first issues
and PRs through `nms git`, a session journal for multi-window work, and the
capped adversarial-review gate before merge. See
[`/root/personal-context/CLAUDE.md`](/root/personal-context/CLAUDE.md).
