#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETBOX_SHA="${NETBOX_SHA:-aa1d49d0f5021a28e6efc2d0364b84c5bcec7137}"
NETBOX_RPC_SHA="${NETBOX_RPC_SHA:-e8d4ba3535e2b4f33125c16281a34da52b634df0}"
NETBOX_RPC_VERSION="0.1.8.post1"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ ! "$NETBOX_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "NETBOX_SHA must be a full 40-character commit SHA" >&2
  exit 1
fi
if [[ ! "$NETBOX_RPC_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "NETBOX_RPC_SHA must be a full 40-character commit SHA" >&2
  exit 1
fi

WORK_PARENT="$(realpath -e "${RUNNER_TEMP:-/tmp}")"
WORK_BASE="$(mktemp -d "$WORK_PARENT/netbox-openbao-source-${NETBOX_SHA:0:12}.XXXXXX")"

validated_cleanup_path() {
  if ! validated_real_path="$(realpath -e "$WORK_BASE")"; then
    echo "Unable to resolve the compatibility work root; refusing cleanup" >&2
    return 1
  fi
  case "$validated_real_path" in
    "$WORK_PARENT"/netbox-openbao-source-"${NETBOX_SHA:0:12}".??????)
      printf '%s\n' "$validated_real_path"
      ;;
    *)
      echo "The compatibility work root failed validation; refusing cleanup" >&2
      return 1
      ;;
  esac
}

cleanup_work_base() {
  cleanup_original_status=$?
  cleanup_result=0
  trap - EXIT

  if cleanup_real_path="$(validated_cleanup_path)"; then
    if find "$cleanup_real_path" -depth -delete; then
      echo "Removed compatibility work root $cleanup_real_path"
    else
      echo "Unable to remove the validated compatibility work root" >&2
      cleanup_result=1
    fi
  else
    cleanup_result=1
  fi

  if [[ "$cleanup_original_status" -ne 0 ]]; then
    exit "$cleanup_original_status"
  fi
  exit "$cleanup_result"
}
trap cleanup_work_base EXIT

NETBOX_INPUT_DIR="${NETBOX_SOURCE_DIR:-$WORK_BASE/netbox-source}"
NETBOX_DIR="$WORK_BASE/netbox"
VENV_DIR="$WORK_BASE/venv"
CONFIG_FILE="$NETBOX_DIR/netbox/netbox/configuration.py"
NETBOX_RPC_DIR="${NETBOX_RPC_SOURCE_DIR:-$ROOT_DIR/.deps/netbox-rpc}"
NETBOX_STATUS="$WORK_BASE/netbox-status.txt"
NETBOX_RPC_ARCHIVE="$WORK_BASE/netbox-rpc-${NETBOX_RPC_SHA}.tar.gz"
NETBOX_RPC_STATUS="$WORK_BASE/netbox-rpc-status.txt"

mkdir -p "$WORK_BASE"

if [[ -z "${NETBOX_SOURCE_DIR:-}" ]]; then
  git init -q "$NETBOX_INPUT_DIR"
  git -C "$NETBOX_INPUT_DIR" remote add origin https://github.com/netbox-community/netbox.git
  git -C "$NETBOX_INPUT_DIR" fetch --depth=1 origin "$NETBOX_SHA"
  git -C "$NETBOX_INPUT_DIR" checkout --detach FETCH_HEAD
fi

actual_sha="$(git -C "$NETBOX_INPUT_DIR" rev-parse HEAD)"
if [[ "$actual_sha" != "$NETBOX_SHA" ]]; then
  echo "NetBox checkout drifted: expected $NETBOX_SHA, got $actual_sha" >&2
  exit 1
fi
git -C "$NETBOX_INPUT_DIR" status --porcelain=v1 --untracked-files=all > "$NETBOX_STATUS"
if [[ -s "$NETBOX_STATUS" ]]; then
  echo "NetBox checkout is dirty; refusing to test unverified bytes" >&2
  exit 1
fi
mkdir -p "$NETBOX_DIR"
git -C "$NETBOX_INPUT_DIR" archive "$NETBOX_SHA" | tar -xf - -C "$NETBOX_DIR"

netbox_rpc_actual_sha="$(git -C "$NETBOX_RPC_DIR" rev-parse HEAD)"
if [[ "$netbox_rpc_actual_sha" != "$NETBOX_RPC_SHA" ]]; then
  echo "netbox-rpc checkout drifted: expected $NETBOX_RPC_SHA, got $netbox_rpc_actual_sha" >&2
  exit 1
fi
git -C "$NETBOX_RPC_DIR" status --porcelain=v1 --untracked-files=all > "$NETBOX_RPC_STATUS"
if [[ -s "$NETBOX_RPC_STATUS" ]]; then
  echo "netbox-rpc checkout is dirty; refusing to install unverified bytes" >&2
  exit 1
fi
git -C "$NETBOX_RPC_DIR" archive \
  --format=tar.gz \
  --prefix=netbox-rpc/ \
  --output="$NETBOX_RPC_ARCHIVE" \
  "$NETBOX_RPC_SHA"

"$PYTHON_BIN" -m venv "$VENV_DIR"
PY="$VENV_DIR/bin/python"
"$PY" -m pip install --upgrade pip wheel setuptools
"$PY" -m pip install -r "$NETBOX_DIR/requirements.txt"
"$PY" -m pip install --no-build-isolation "$NETBOX_RPC_ARCHIVE"
actual_rpc_version="$("$PY" -c 'from importlib.metadata import version; print(version("netbox-rpc"))')"
if [[ "$actual_rpc_version" != "$NETBOX_RPC_VERSION" ]]; then
  echo "netbox-rpc distribution drifted: expected $NETBOX_RPC_VERSION, got $actual_rpc_version" >&2
  exit 1
fi
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
PLUGINS = ["netbox_rpc", "netbox_openbao"]
PLUGINS_CONFIG = {"netbox_openbao": {}, "netbox_rpc": {}}
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
