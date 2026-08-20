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
git clone --depth 1 --branch v4.7.0 https://github.com/netbox-community/netbox.git
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
SECRET_KEY = 'development-only-key'

# NetBox 4.7 requires both of these, and fails in non-obvious ways without them:
EMAIL = {'SERVER': 'localhost', 'PORT': 25, 'FROM_EMAIL': 'netbox@example.net'}
API_TOKEN_PEPPERS = {1: 'ZGV2ZWxvcG1lbnQtcGVwcGVy'}   # v2 API tokens

DEVELOPER = True          # required for makemigrations
PLUGINS = ['netbox_openbao']
PLUGINS_CONFIG = {'netbox_openbao': {}}
```

Without `API_TOKEN_PEPPERS`, `Token.objects.create()` raises
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
runs anywhere.

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

## Layout

```
netbox_openbao/
├── __init__.py          PluginConfig
├── choices.py           ChoiceSets
├── config.py            typed PLUGINS_CONFIG access
├── models/              engines, policies, credentials, assignments, audit
├── backends/            SecretBackend ABC, OpenBao/Vault/broker implementations, exceptions
├── secrets/             type registry, cryptography extractors, generators
├── services.py          the only code that touches material
├── api/                 serializers, viewsets, urls, throttling
├── ui/panels.py         declarative 4.7 detail panels
├── forms.py  tables.py  filtersets.py  views.py  urls.py
├── navigation.py  search.py  signals.py  jobs.py  template_content.py
└── tests/
```

`services.py` is the chokepoint: everything that handles material goes through
it, so there is exactly one file to audit for leaks. Views, serializers, and
forms never call a backend directly.

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
