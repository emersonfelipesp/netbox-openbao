# Development

## Stack

```bash
docker compose -f docker-compose.dev.yml up -d
```

That gives PostgreSQL 16 (`127.0.0.1:15432`), Redis 7 (`127.0.0.1:16379`), and
OpenBao 2.6 in dev mode (`127.0.0.1:8200`, root token `devroot`).

PostgreSQL must be 15+ **with `ltree`** — NetBox 4.7 backs its hierarchical
models with it, and `migrate` fails without the extension:

```bash
psql -h 127.0.0.1 -p 15432 -U netbox -d netbox -c 'CREATE EXTENSION IF NOT EXISTS ltree;'
```

## NetBox checkout

```bash
git clone --depth 1 --branch v4.7.0-beta2 https://github.com/netbox-community/netbox.git
python3.12 -m venv .venv
.venv/bin/pip install -r netbox/requirements.txt
.venv/bin/pip install -e /path/to/netbox-openbao
```

`netbox/netbox/configuration.py`:

```python
DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'netbox', 'USER': 'netbox', 'PASSWORD': 'netbox',
    'HOST': '127.0.0.1', 'PORT': '15432',
}}
REDIS = {
    'tasks':   {'HOST': '127.0.0.1', 'PORT': 16379, 'DATABASE': 0, 'SSL': False},
    'caching': {'HOST': '127.0.0.1', 'PORT': 16379, 'DATABASE': 1, 'SSL': False},
}
ALLOWED_HOSTS = ['localhost', '127.0.0.1']
SECRET_KEY = 'development-only-key-that-is-at-least-fifty-characters-long'

# NetBox 4.7 requires both of these, and fails in non-obvious ways without them:
EMAIL = {'SERVER': 'localhost', 'PORT': 25, 'FROM_EMAIL': 'netbox@example.net'}
API_TOKEN_PEPPERS = {
    1: 'development-only-api-token-pepper-at-least-fifty-characters-long',
}   # v2 API tokens

DEVELOPER = True          # required for makemigrations
PLUGINS = ['netbox_openbao']
PLUGINS_CONFIG = {'netbox_openbao': {}}
```

The checkout above is the exact NetBox 4.7 beta certification target. The
hosted compatibility gate also runs this suite on NetBox 4.6.5 so work on the
beta cannot silently drop the supported floor.

NetBox validates `SECRET_KEY` and each `API_TOKEN_PEPPERS` value at startup;
both examples deliberately exceed the 50-character minimum. Without
`API_TOKEN_PEPPERS`, `Token.objects.create()` raises
`ValueError: API_TOKEN_PEPPERS is not defined` — which surfaces as every API
test erroring in `setUp`, not as a configuration message.

## Running the suite

```bash
cd netbox/netbox
../.venv/bin/python manage.py test netbox_openbao
```

To include the tests that exercise a real OpenBao — and you should, because a
fake proves nothing about whether `hvac` and OpenBao agree on check-and-set
semantics or custom metadata:

```bash
export NETBOX_OPENBAO_TEST_ADDR=http://127.0.0.1:8200
export NETBOX_OPENBAO_TEST_TOKEN=devroot
../.venv/bin/python manage.py test netbox_openbao
```

They are skipped when `NETBOX_OPENBAO_TEST_ADDR` is unset, so the suite still
runs anywhere. The same variables enable the administration
capability-discovery integration test, which performs a read-only request and
persists no OpenBao response body. Authentication administration integration
tests additionally require enabled `userpass`, `approle`, and `jwt` mounts and
exercise bounded test resources that they remove in `finally` blocks.

The authentication workspace also has an opt-in Playwright test. Install the
matching browser package and Chromium, then run the focused class:

```bash
python -m pip install playwright==1.60.0
python -m playwright install chromium
python manage.py test \
  netbox_openbao.tests.test_authentication_administration_browser
```

The class is skipped when Playwright is unavailable. It covers the rendered
workspace at desktop and 390 px widths, accessible label associations,
metadata reads, one-shot login clearing, direct OIDC state custody, MFA reads,
and exact destructive confirmation guidance.

## Migrations

```bash
python manage.py makemigrations netbox_openbao
python manage.py makemigrations netbox_openbao --check --dry-run   # CI gate
```

`makemigrations` requires `DEVELOPER = True`; NetBox refuses it otherwise.

## Lint

```bash
ruff check .
```

## Documentation

The site is Material for MkDocs. It builds from the checkout with **no package
install and no NetBox**: `mkdocstrings` reads the source through `griffe`,
which parses it statically and never imports it.

```bash
pip install '.[docs]'
mkdocs serve          # http://127.0.0.1:8000, live reload
mkdocs build --strict # what CI runs; warnings are errors
```

`--strict` is not decoration. It is what catches a broken cross-reference, a
nav entry pointing at a file that does not exist, and — because griffe warns on
a documented parameter with no type anywhere — a docstring that has drifted
from its signature.

Two things are generated rather than written:

- `docs/reference/**` — one page per module, produced by
  `scripts/gen_ref_pages.py` walking the package. A new module appears in the
  reference the moment it exists, and a deleted one disappears with it.
  `migrations/` and `tests/` are excluded.
- `docs/reference/SUMMARY.md` — the reference's own nav, consumed by
  `mkdocs-literate-nav`. Its links are relative to `reference/`, so they must
  **not** carry a `reference/` prefix.

Everything else is listed explicitly in `mkdocs.yml`'s `nav`. A new page that is
not listed there is built but unreachable.

## Layout

```
netbox_openbao/
├── __init__.py          PluginConfig
├── choices.py           ChoiceSets
├── config.py            cached settings-row and PLUGINS_CONFIG fallback
├── models/              settings, clusters, engines, policies, credentials, assignments, audit
├── administration/      capability discovery, transport boundary, audit, parity manifest
├── backends/            SecretBackend ABC, OpenBao/Vault/broker implementations, exceptions
├── secrets/             type registry, cryptography extractors, generators
├── services.py          the credential-material service boundary
├── api/                 serializers, viewsets, urls, throttling
├── ui/panels.py         declarative 4.7 detail panels
├── forms.py  tables.py  filtersets.py  views.py  urls.py
├── navigation.py  search.py  signals.py  jobs.py  template_content.py
└── tests/
```

`tests/test_policy_gate.py` is worth knowing about specifically: it asserts each
authorization gate on **every** surface separately — the REST actions, `PATCH`
of `secret_data`, the full-page UI reveal, the HTMX reveal, and the UI
promote/discard. Two real gaps hid in the difference between those surfaces, so
a test that covers one of them is not evidence about the others.

`services.py` is the stored credential-material chokepoint, so credential
views, serializers, and forms never call a credential backend directly. The
separate `administration/` boundary handles request-scoped cluster lifecycle
custody such as initialization shares, unseal shares, and snapshot streams.
Administration views may call that bounded transport directly, but neither
boundary may persist, cache, or log material.

## Adding a credential type

1. Add a value to `CredentialTypeChoices`.
2. Add a `CREDENTIAL_SCHEMAS` entry naming its payload fields and, optionally,
   an extractor.
3. If it needs new extraction, add a function to `secrets/extractors.py` and
   return only keys in `EXTRACTABLE_FIELDS` — anything else is dropped, which
   is what stops an extractor introducing a secret-bearing column.
4. Add the payload field names to `SECRET_INPUT_FIELDS` in `forms.py`, and to
   `SENSITIVE_INPUT_FIELDS` if they are secret.

No migration is needed unless you add a column.

## Adding a backend

Subclass `SecretBackend`, implement the six abstract methods, and register it
in `backends/BACKENDS`. Two rules are not optional:

1. Never raise a vendor exception — translate it to a
   `netbox_openbao.backends.exceptions` type carrying no server text.
2. Never log, format, or attach material to an exception, span, or metric.

HashiCorp Vault should be a near-empty subclass of `OpenBaoBackend`.
