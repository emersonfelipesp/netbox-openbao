#!/usr/bin/env bash
set -euo pipefail

# This script runs in the credentials-free ci-untrusted-python312 container.
# Never use a Docker executor or attach a host service to execute PR code.
[[ ! -e /var/run/docker.sock && ! -e /run/docker.sock && -z "${DOCKER_HOST:-}" ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]]
[[ -n "${GITHUB_WORKSPACE:-}" && -n "${RUNNER_TEMP:-}" ]]

VENV="$GITHUB_WORKSPACE/.venv"
REDIS_BIN="$VENV/lib/python3.12/site-packages/redislite/bin"
test -x "$REDIS_BIN/redis-server"

TEMP_PARENT="$(realpath -e "$RUNNER_TEMP")"
WORK_BASE="$(mktemp -d "$TEMP_PARENT/netbox-openbao-pr-db.XXXXXX")"
case "$WORK_BASE" in
  *[!a-zA-Z0-9_./-]*) echo 'Unsafe CI work path' >&2; exit 1 ;;
esac
PG_SOCKET="$WORK_BASE/socket"
PG_ROOT="$WORK_BASE/packages-root"
REDIS_PORT=$((30000 + GITHUB_RUN_ID % 20000))
mkdir "$PG_SOCKET"

stop_services() {
  if [[ -n "${redis_pid:-}" ]]; then
    kill "$redis_pid" 2>/dev/null || true
    wait "$redis_pid" 2>/dev/null || true
  fi
  if [[ -f "$WORK_BASE/pg/postmaster.pid" ]]; then
    "$PG_BIN/pg_ctl" -D "$WORK_BASE/pg" -m immediate stop
  fi
}

remove_workdir() {
  work_real="$(realpath -e "$WORK_BASE")" || return 1
  case "$work_real" in
    "$TEMP_PARENT"/netbox-openbao-pr-db.??????)
      find "$work_real" -depth -delete ;;
    *) echo 'Refusing to clean an unexpected CI work path' >&2; return 1 ;;
  esac
}

cleanup() {
  original_status=$?
  cleanup_status=0
  trap - EXIT
  stop_services || cleanup_status=1
  if [[ "$original_status" -ne 0 ]]; then
    cat "$WORK_BASE/postgres.log" "$WORK_BASE/redis.log" 2>/dev/null || true
  fi
  remove_workdir || cleanup_status=1
  if [[ "$original_status" -ne 0 ]]; then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

verify_redis_process() {
  local reported_pid
  if ! reported_pid="$(
    "$REDIS_BIN/redis-cli" --raw -h 127.0.0.1 -p "$REDIS_PORT" INFO server |
      tr -d '\r' | sed -n 's/^process_id:\([0-9][0-9]*\)$/\1/p'
  )"; then
    echo 'Could not read the CI Redis process ID' >&2
    return 1
  fi
  if [[ ! "$reported_pid" =~ ^[0-9]+$ || "$reported_pid" != "$redis_pid" ]]; then
    echo 'CI Redis process ID does not match the child started by this job' >&2
    return 1
  fi
}

# PostgreSQL appends ".s.PGSQL.5432" to the socket directory; Linux limits
# the resulting Unix-domain socket path to 107 bytes plus a NUL terminator.
if (( ${#PG_SOCKET} + 14 >= 108 )); then
  echo 'The CI PostgreSQL socket path exceeds the Linux limit' >&2
  exit 1
fi

# apt verifies Debian's signed Release metadata and package checksums. Extract
# packages without installation scripts or privilege; all apt state is job-local.
mkdir -p "$WORK_BASE/apt/lists/partial" "$WORK_BASE/apt/archives/partial" \
  "$WORK_BASE/downloads" "$PG_ROOT"
APT_OPTIONS=(
  -o "Dir::State::lists=$WORK_BASE/apt/lists"
  -o "Dir::Cache::archives=$WORK_BASE/apt/archives"
  -o APT::Get::AllowUnauthenticated=false
)
apt-get "${APT_OPTIONS[@]}" update
(
  cd "$WORK_BASE/downloads"
  apt-get "${APT_OPTIONS[@]}" download \
    postgresql-15 postgresql-client-15 libicu72 libpq5 libxml2 \
    libldap-2.5-0 libsasl2-2
)
for package in "$WORK_BASE"/downloads/*.deb; do
  dpkg-deb -x "$package" "$PG_ROOT"
done
export LD_LIBRARY_PATH="$PG_ROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
PG_BIN="$PG_ROOT/usr/lib/postgresql/15/bin"
test -x "$PG_BIN/initdb"
test -f "$PG_ROOT/usr/share/postgresql/15/extension/ltree.control"
[[ "$("$PG_BIN/postgres" --version)" == 'postgres (PostgreSQL) 15.'* ]]

"$PG_BIN/initdb" -D "$WORK_BASE/pg" -A trust --no-instructions
"$PG_BIN/pg_ctl" -D "$WORK_BASE/pg" \
  -o "-c listen_addresses='' -c unix_socket_directories=$PG_SOCKET" \
  -l "$WORK_BASE/postgres.log" start
"$PG_BIN/createuser" -h "$PG_SOCKET" -p 5432 \
  --superuser --createdb --login netbox_openbao_ci
"$PG_BIN/createdb" -h "$PG_SOCKET" -p 5432 \
  -O netbox_openbao_ci netbox_openbao_ci
"$PG_BIN/psql" -h "$PG_SOCKET" -p 5432 -d netbox_openbao_ci \
  -c 'CREATE EXTENSION IF NOT EXISTS ltree;'
"$PG_BIN/psql" -h "$PG_SOCKET" -p 5432 -d netbox_openbao_ci \
  -c "CREATE COLLATION ci_icu_probe (locale='und-u-kn-true', provider=icu);"

"$REDIS_BIN/redis-server" --bind 127.0.0.1 --port "$REDIS_PORT" \
  --daemonize no --save '' --appendonly no > "$WORK_BASE/redis.log" 2>&1 &
redis_pid=$!
for _ in $(seq 1 30); do
  if "$REDIS_BIN/redis-cli" -h 127.0.0.1 -p "$REDIS_PORT" ping | grep -qx PONG; then
    break
  fi
  kill -0 "$redis_pid"
  sleep 1
done
kill -0 "$redis_pid"
test "$("$REDIS_BIN/redis-cli" -h 127.0.0.1 -p "$REDIS_PORT" ping)" = PONG
# A run-ID port alias must not let this job use another job's Redis process.
verify_redis_process

export DB_HOST="$PG_SOCKET"
export DB_PORT=5432
export DB_NAME=netbox_openbao_ci
export DB_TEST_NAME=test_netbox_openbao_ci
export DB_USER=netbox_openbao_ci
export DB_PASSWORD=netbox_openbao_ci
export REDIS_HOST=127.0.0.1
export REDIS_PORT
PYTHON_BIN="$(command -v python3.12)"
export PYTHON_BIN
export NETBOX_RPC_SOURCE_DIR="$GITHUB_WORKSPACE/.deps/netbox-rpc"
export NETBOX_CI_BINARY_PSYCOPG=1

"$PYTHON_BIN" -c 'import sys; assert sys.version_info[:2] == (3, 12)'
if bash "$GITHUB_WORKSPACE/.github/ci/netbox-source-test.sh"; then
  verify_redis_process
else
  suite_status=$?
  verify_redis_process || true
  exit "$suite_status"
fi
