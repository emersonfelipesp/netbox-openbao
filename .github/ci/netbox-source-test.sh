#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETBOX_SHA="${NETBOX_SHA:-aa1d49d0f5021a28e6efc2d0364b84c5bcec7137}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ ! "$NETBOX_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "NETBOX_SHA must be a full 40-character commit SHA" >&2
  exit 1
fi

WORK_BASE="${RUNNER_TEMP:-/tmp}/netbox-openbao-source-${NETBOX_SHA:0:12}"
NETBOX_DIR="${NETBOX_SOURCE_DIR:-$WORK_BASE/netbox}"
VENV_DIR="${NETBOX_VENV_DIR:-$WORK_BASE/venv}"
CONFIG_FILE="$NETBOX_DIR/netbox/netbox/configuration.py"

mkdir -p "$WORK_BASE"

if [[ -z "${NETBOX_SOURCE_DIR:-}" ]]; then
  rm -rf "$NETBOX_DIR"
  git init -q "$NETBOX_DIR"
  git -C "$NETBOX_DIR" remote add origin https://github.com/netbox-community/netbox.git
  git -C "$NETBOX_DIR" fetch --depth=1 origin "$NETBOX_SHA"
  git -C "$NETBOX_DIR" checkout --detach FETCH_HEAD
fi

actual_sha="$(git -C "$NETBOX_DIR" rev-parse HEAD)"
if [[ "$actual_sha" != "$NETBOX_SHA" ]]; then
  echo "NetBox checkout drifted: expected $NETBOX_SHA, got $actual_sha" >&2
  exit 1
fi

rm -rf "$VENV_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"
PY="$VENV_DIR/bin/python"
"$PY" -m pip install --upgrade pip wheel setuptools
"$PY" -m pip install -r "$NETBOX_DIR/requirements.txt"
"$PY" -m pip install --no-build-isolation -e "$ROOT_DIR"

cat > "$CONFIG_FILE" <<'PY'
import os

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
DATABASES = {
    "default": {
        "NAME": os.environ.get("DB_NAME", "netbox_openbao_compat"),
        "USER": os.environ.get("DB_USER", "netbox_openbao_ci"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "netbox_openbao_ci"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "CONN_MAX_AGE": 0,
        "TEST": {
            "NAME": os.environ.get("DB_TEST_NAME", "test_netbox_openbao_compat"),
        },
    }
}
REDIS = {
    "tasks": {
        "HOST": os.environ.get("REDIS_HOST", "localhost"),
        "PORT": int(os.environ.get("REDIS_PORT", "6379")),
        "USERNAME": "",
        "PASSWORD": os.environ.get("REDIS_PASSWORD", ""),
        "DATABASE": int(os.environ.get("REDIS_DATABASE", "8")),
        "SSL": False,
    },
    "caching": {
        "HOST": os.environ.get("REDIS_HOST", "localhost"),
        "PORT": int(os.environ.get("REDIS_PORT", "6379")),
        "USERNAME": "",
        "PASSWORD": os.environ.get("REDIS_PASSWORD", ""),
        "DATABASE": int(os.environ.get("REDIS_CACHE_DATABASE", "9")),
        "SSL": False,
    },
}
SECRET_KEY = "netbox-openbao-source-ci-secret-key-not-for-production-000000"
API_TOKEN_PEPPERS = {
    1: "netbox-openbao-source-ci-pepper-not-for-production-0000000000",
}
EMAIL = {"SERVER": "localhost", "PORT": 25, "FROM_EMAIL": "netbox@example.net"}
DEFAULT_PERMISSIONS = {}
RQ = {"COMMIT_MODE": "auto"}
DEVELOPER = True
PLUGINS = ["netbox_openbao"]
PLUGINS_CONFIG = {"netbox_openbao": {}}
PY

export NETBOX_CONFIGURATION=netbox.configuration
export PYTHONPATH="$NETBOX_DIR/netbox:$ROOT_DIR:${PYTHONPATH:-}"

"$PY" "$NETBOX_DIR/netbox/manage.py" check
"$PY" "$NETBOX_DIR/netbox/manage.py" migrate --noinput
"$PY" "$NETBOX_DIR/netbox/manage.py" \
  makemigrations netbox_openbao --check --dry-run --noinput

TEST_OUTPUT="$WORK_BASE/django-test-output.log"
if ! "$PY" "$NETBOX_DIR/netbox/manage.py" test netbox_openbao \
  --noinput --keepdb --verbosity 1 2>&1 | tee "$TEST_OUTPUT"; then
  echo "Django compatibility suite failed" >&2
  exit 1
fi
if ! grep -Eq '^Found [1-9][0-9]* test\(s\)\.$' "$TEST_OUTPUT"; then
  echo "Django runner did not report any collected tests; failing closed" >&2
  exit 1
fi
