#!/usr/bin/env python3
"""Fail closed when the declared NetBox compatibility evidence drifts."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BETA2_SHA = "aa1d49d0f5021a28e6efc2d0364b84c5bcec7137"
NETBOX_46_SHA = "ebee3578b90901ba69ea646815f9b0662f627726"
NETBOX_RPC_SHA = "e8d4ba3535e2b4f33125c16281a34da52b634df0"
NETBOX_RPC_REQUIREMENT = "netbox-rpc>=0.1.8"
NETBOX_RPC_VERSION = "0.1.8.post1"
RPC_INSTALL = '"$PY" -m pip install --no-build-isolation "$NETBOX_RPC_ARCHIVE"'
PLUGIN_INSTALL = '"$PY" -m pip install --no-build-isolation -e "$ROOT_DIR"'
NETBOX_SHA_GUARD = '[[ "$actual_sha" != "$NETBOX_SHA" ]]'
NETBOX_STATUS_COMMAND = 'git -C "$NETBOX_INPUT_DIR" status --porcelain=v1 --untracked-files=all > "$NETBOX_STATUS"'
NETBOX_DIRTY_GUARD = '[[ -s "$NETBOX_STATUS" ]]'
NETBOX_ARCHIVE_COMMAND = 'git -C "$NETBOX_INPUT_DIR" archive "$NETBOX_SHA" | tar -xf - -C "$NETBOX_DIR"'
FIXED_VENV_DIR = 'VENV_DIR="$WORK_BASE/venv"'
RPC_SOURCE_BINDING = "NETBOX_RPC_SOURCE_DIR: ${{ github.workspace }}/.deps/netbox-rpc"
RPC_SHA_GUARD = '[[ "$netbox_rpc_actual_sha" != "$NETBOX_RPC_SHA" ]]'
RPC_STATUS_COMMAND = 'git -C "$NETBOX_RPC_DIR" status --porcelain=v1 --untracked-files=all > "$NETBOX_RPC_STATUS"'
RPC_DIRTY_GUARD = '[[ -s "$NETBOX_RPC_STATUS" ]]'
RPC_ARCHIVE_COMMAND = (
    'git -C "$NETBOX_RPC_DIR" archive \\\n'
    '  --format=tar.gz \\\n'
    '  --prefix=netbox-rpc/ \\\n'
    '  --output="$NETBOX_RPC_ARCHIVE" \\\n'
    '  "$NETBOX_RPC_SHA"'
)
RPC_VERSION_READ = (
    'actual_rpc_version="$("$PY" -c '
    "'from importlib.metadata import version; print(version(\"netbox-rpc\"))')\""
)
RPC_VERSION_GUARD = '[[ "$actual_rpc_version" != "$NETBOX_RPC_VERSION" ]]'
WORK_PARENT = 'WORK_PARENT="$(realpath -e "${RUNNER_TEMP:-/tmp}")"'
UNIQUE_WORK_BASE = 'WORK_BASE="$(mktemp -d "$WORK_PARENT/netbox-openbao-source-${NETBOX_SHA:0:12}.XXXXXX")"'
WORK_CLEANUP_VALIDATOR = "validated_cleanup_path()"
WORK_CLEANUP_TRAP = "trap cleanup_work_base EXIT"
WORK_CLEANUP_PATTERN = '"$WORK_PARENT"/netbox-openbao-source-"${NETBOX_SHA:0:12}".??????)'
WORK_CLEANUP_DELETE = 'find "$cleanup_real_path" -depth -delete'
WORK_CLEANUP_STATUS = 'if [[ "$cleanup_original_status" -ne 0 ]]'
CHECKOUT_ACTION = "https://git.nmulti.cloud/actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def validate_contract(
    *,
    plugin: str,
    workflow: str,
    harness: str,
    readme: str,
    development: str,
    pyproject: str,
) -> None:
    """Validate every binding that makes the exact-source gate executable."""
    dependencies = tomllib.loads(pyproject)["project"]["dependencies"]
    checkout_pattern = re.compile(
        r"- name: Checkout RPC dependency\s+"
        rf"uses: {re.escape(CHECKOUT_ACTION)}[^\n]*\n\s*"
        r"with:\s+"
        r"repository: N-MultiCloud/netbox-rpc\s+"
        rf"ref: {NETBOX_RPC_SHA}\s+"
        r"path: \.deps/netbox-rpc\s+"
        r"persist-credentials: false"
    )
    suite_binding_pattern = re.compile(
        r"- name: Run exact-source compatibility suite\s+"
        r"shell: bash\s+"
        r"env:\s+"
        r"PYTHON_BIN: .*?\s+"
        + re.escape(RPC_SOURCE_BINDING)
        + r".*?run: bash \.github/ci/netbox-source-test\.sh",
        flags=re.DOTALL,
    )
    concurrency_pattern = re.compile(
        r"concurrency:\s+"
        r"(?:#[^\n]*\n\s*)*"
        r"group: netbox-openbao-compatibility\s+"
        r"cancel-in-progress: false"
    )

    require("min_version = '4.6.0'" in plugin, "NetBox 4.6 floor drifted")
    require("max_version = '4.7.99'" in plugin, "NetBox 4.7 ceiling drifted")
    require(BETA2_SHA in workflow, "exact NetBox beta2 commit is not gated")
    require(NETBOX_46_SHA in workflow, "NetBox 4.6 regression commit is not gated")
    require(workflow.count(f"NETBOX_RPC_SHA: {NETBOX_RPC_SHA}") == 1, "workflow netbox-rpc SHA binding drifted")
    require(len(checkout_pattern.findall(workflow)) == 1, "netbox-rpc dependency checkout contract drifted")
    require(workflow.count("persist-credentials: false") == 2, "checkout credential persistence contract drifted")
    require("persist-credentials: true" not in workflow, "checkout credentials must never persist")
    require(workflow.count(RPC_SOURCE_BINDING) == 1, "workflow netbox-rpc source binding drifted")
    require(
        suite_binding_pattern.search(workflow) is not None,
        "exact suite does not receive the checked-out dependency",
    )
    require('netbox_version: "4.7.0-beta2"' in workflow, "beta2 matrix label missing")
    require('netbox_version: "4.6.5"' in workflow, "4.6 matrix label missing")
    require(concurrency_pattern.search(workflow) is not None, "compatibility runs are not serialized across refs")
    require(
        re.search(r"^\s+pull_request:", workflow, flags=re.MULTILINE) is None,
        "privileged compatibility workflow must not run pull-request code",
    )

    require(NETBOX_RPC_SHA in harness, "exact netbox-rpc dependency commit is not verified")
    require(f'NETBOX_RPC_VERSION="{NETBOX_RPC_VERSION}"' in harness, "netbox-rpc version check drifted")
    require(harness.count(WORK_PARENT) == 1, "compatibility work parent is not canonicalized")
    require(harness.count(UNIQUE_WORK_BASE) == 1, "compatibility work root is not collision-free")
    require(harness.count(WORK_CLEANUP_VALIDATOR) == 1, "compatibility work cleanup validator drifted")
    require(harness.count(WORK_CLEANUP_TRAP) == 1, "compatibility work cleanup trap drifted")
    require(
        WORK_CLEANUP_PATTERN in harness
        and WORK_CLEANUP_DELETE in harness
        and WORK_CLEANUP_STATUS in harness,
        "compatibility work cleanup is not bounded or status-preserving",
    )
    require(
        'actual_sha="$(git -C "$NETBOX_INPUT_DIR" rev-parse HEAD)"' in harness,
        "source harness no longer resolves the checkout commit",
    )
    require(
        NETBOX_SHA_GUARD in harness,
        "source harness no longer fails closed on checkout drift",
    )
    require(
        NETBOX_STATUS_COMMAND in harness and NETBOX_DIRTY_GUARD in harness,
        "source harness no longer rejects dirty NetBox bytes",
    )
    require(
        harness.count(NETBOX_ARCHIVE_COMMAND) == 1,
        "source harness no longer tests an archive of the verified NetBox commit",
    )
    require(harness.count(FIXED_VENV_DIR) == 1, "compatibility venv is not bounded by the unique work root")
    require("NETBOX_VENV_DIR" not in harness, "compatibility venv must not accept an external deletion target")
    require('rm -rf "$VENV_DIR"' not in harness, "compatibility harness must not recursively delete a venv override")
    require(
        RPC_SHA_GUARD in harness,
        "source harness no longer fails closed on netbox-rpc checkout drift",
    )
    require(
        RPC_STATUS_COMMAND in harness and RPC_DIRTY_GUARD in harness,
        "source harness no longer rejects dirty netbox-rpc bytes",
    )
    require(
        harness.count(RPC_ARCHIVE_COMMAND) == 1,
        "source harness no longer archives the verified netbox-rpc commit",
    )
    require(harness.count(RPC_INSTALL) == 1, "netbox-rpc archive install contract drifted")
    require(harness.count(PLUGIN_INSTALL) == 1, "netbox-openbao editable install contract drifted")
    require(harness.index(RPC_INSTALL) < harness.index(PLUGIN_INSTALL), "netbox-rpc must install before netbox-openbao")
    require(
        RPC_VERSION_GUARD in harness,
        "source harness no longer fails closed on netbox-rpc distribution drift",
    )
    ordered_contract = (
        RPC_SHA_GUARD,
        RPC_STATUS_COMMAND,
        RPC_DIRTY_GUARD,
        RPC_ARCHIVE_COMMAND,
        RPC_INSTALL,
        RPC_VERSION_READ,
        RPC_VERSION_GUARD,
        PLUGIN_INSTALL,
    )
    positions = [harness.index(item) for item in ordered_contract]
    require(positions == sorted(positions), "netbox-rpc verification and installation order drifted")
    require("Found [1-9][0-9]* test" in harness, "zero-test fail-closed guard missing")

    require(NETBOX_RPC_REQUIREMENT in dependencies, "project netbox-rpc requirement drifted")
    require("4.6.0–4.7.99" in readme, "README support range drifted")
    require("--branch v4.7.0-beta2" in development, "development checkout is not beta2")
    require(NETBOX_RPC_SHA in development, "documented netbox-rpc SHA drifted")
    require(f"distribution version `{NETBOX_RPC_VERSION}`" in development, "documented netbox-rpc version drifted")
    require(
        "https://github.com/N-MultiCloud/netbox-rpc.git" in development,
        "development guide must use the approved public mirror",
    )
    require("git.nmulti.cloud" not in development, "development guide exposes the internal Gitea endpoint")


def require_rejected(name: str, **sources: str) -> None:
    """Prove a representative contract mutation fails validation."""
    try:
        validate_contract(**sources)
    except (KeyError, SystemExit, ValueError, tomllib.TOMLDecodeError):
        return
    raise SystemExit(f"contract mutation was accepted: {name}")


def main() -> None:
    sources = {
        "plugin": read("netbox_openbao/__init__.py"),
        "workflow": read(".gitea/workflows/compatibility.yml"),
        "harness": read(".github/ci/netbox-source-test.sh"),
        "readme": read("README.md"),
        "development": read("docs/development.md"),
        "pyproject": read("pyproject.toml"),
    }
    validate_contract(**sources)

    mutations = {
        "missing dependency install": {"harness": sources["harness"].replace(RPC_INSTALL, "")},
        "reordered dependency install": {
            "harness": sources["harness"]
            .replace(RPC_INSTALL, "")
            .replace(PLUGIN_INSTALL, f"{PLUGIN_INSTALL}\n{RPC_INSTALL}")
        },
        "mismatched source path": {
            "workflow": sources["workflow"].replace(RPC_SOURCE_BINDING, "NETBOX_RPC_SOURCE_DIR: /tmp/rpc")
        },
        "persisted checkout credentials": {
            "workflow": sources["workflow"].replace("persist-credentials: false", "persist-credentials: true", 1)
        },
        "dependency checkout action removed": {
            "workflow": sources["workflow"].replace(
                f"- name: Checkout RPC dependency\n        uses: {CHECKOUT_ACTION}",
                "- name: Checkout RPC dependency\n        uses: removed/action",
            )
        },
        "project requirement drift": {
            "pyproject": sources["pyproject"].replace(NETBOX_RPC_REQUIREMENT, "netbox-rpc>=9")
        },
        "dependency SHA drift": {"workflow": sources["workflow"].replace(NETBOX_RPC_SHA, "0" * 40)},
        "dirty NetBox guard removed": {
            "harness": sources["harness"].replace(NETBOX_DIRTY_GUARD, '[[ ! -s "$NETBOX_STATUS" ]]')
        },
        "NetBox archive revision rebound": {
            "harness": sources["harness"].replace(
                NETBOX_ARCHIVE_COMMAND,
                NETBOX_ARCHIVE_COMMAND.replace('"$NETBOX_SHA"', "HEAD"),
            )
        },
        "external venv deletion target restored": {
            "harness": sources["harness"].replace(FIXED_VENV_DIR, 'VENV_DIR="${NETBOX_VENV_DIR:-$WORK_BASE/venv}"')
        },
        "distribution version drift": {
            "harness": sources["harness"].replace(
                f'NETBOX_RPC_VERSION="{NETBOX_RPC_VERSION}"', 'NETBOX_RPC_VERSION="9"'
            )
        },
        "dirty-source guard removed": {
            "harness": sources["harness"].replace(
                RPC_DIRTY_GUARD, '[[ ! -s "$NETBOX_RPC_STATUS" ]]'
            )
        },
        "dirty check rebound to project": {
            "harness": sources["harness"].replace(
                RPC_STATUS_COMMAND,
                RPC_STATUS_COMMAND.replace("$NETBOX_RPC_DIR", "$ROOT_DIR"),
            )
        },
        "archive rebound to project": {
            "harness": sources["harness"].replace(
                RPC_ARCHIVE_COMMAND, RPC_ARCHIVE_COMMAND.replace("$NETBOX_RPC_DIR", "$ROOT_DIR")
            )
        },
        "archive revision rebound": {
            "harness": sources["harness"].replace(
                RPC_ARCHIVE_COMMAND, RPC_ARCHIVE_COMMAND.replace('"$NETBOX_RPC_SHA"', "HEAD~1")
            )
        },
        "version oracle replaced by constant": {
            "harness": sources["harness"].replace(
                RPC_VERSION_READ, 'actual_rpc_version="$NETBOX_RPC_VERSION"'
            )
        },
        "deterministic work root": {
            "harness": sources["harness"].replace(
                UNIQUE_WORK_BASE, 'WORK_BASE="${RUNNER_TEMP:-/tmp}/netbox-openbao-source-${NETBOX_SHA:0:12}"'
            )
        },
        "per-ref concurrency restored": {
            "workflow": sources["workflow"].replace(
                "group: netbox-openbao-compatibility", "group: netbox-openbao-compatibility-${{ github.ref }}"
            )
        },
        "concurrent run cancellation enabled": {
            "workflow": sources["workflow"].replace("cancel-in-progress: false", "cancel-in-progress: true")
        },
        "work cleanup trap removed": {
            "harness": sources["harness"].replace(WORK_CLEANUP_TRAP, "")
        },
        "work cleanup path widened": {
            "harness": sources["harness"].replace(WORK_CLEANUP_PATTERN, '"$WORK_PARENT"/*)')
        },
        "verified archive removed": {
            "harness": sources["harness"].replace(
                RPC_INSTALL, '"$PY" -m pip install --no-build-isolation "$NETBOX_RPC_DIR"'
            )
        },
        "documented SHA drift": {
            "development": sources["development"].replace(NETBOX_RPC_SHA, "0" * 40)
        },
    }
    for name, mutation in mutations.items():
        require(
            mutation and all(value != sources[key] for key, value in mutation.items()),
            f"contract mutation is a no-op: {name}",
        )
        require_rejected(name, **(sources | mutation))

    print("NetBox compatibility contract is pinned, executable, and mutation-checked")


if __name__ == "__main__":
    main()
