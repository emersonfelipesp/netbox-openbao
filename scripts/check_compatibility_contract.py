#!/usr/bin/env python3
"""Fail closed when the declared NetBox compatibility evidence drifts."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BETA2_SHA = "aa1d49d0f5021a28e6efc2d0364b84c5bcec7137"
NETBOX_46_SHA = "ebee3578b90901ba69ea646815f9b0662f627726"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


plugin = read("netbox_openbao/__init__.py")
workflow = read(".gitea/workflows/compatibility.yml")
harness = read(".github/ci/netbox-source-test.sh")
readme = read("README.md")
development = read("docs/development.md")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


require("min_version = '4.6.0'" in plugin, "NetBox 4.6 floor drifted")
require("max_version = '4.7.99'" in plugin, "NetBox 4.7 ceiling drifted")
require(BETA2_SHA in workflow, "exact NetBox beta2 commit is not gated")
require(NETBOX_46_SHA in workflow, "NetBox 4.6 regression commit is not gated")
require('netbox_version: "4.7.0-beta2"' in workflow, "beta2 matrix label missing")
require('netbox_version: "4.6.5"' in workflow, "4.6 matrix label missing")
require(
    re.search(r"^\s+pull_request:", workflow, flags=re.MULTILINE) is None,
    "privileged compatibility workflow must not run pull-request code",
)
require(
    'actual_sha="$(git -C "$NETBOX_DIR" rev-parse HEAD)"' in harness,
    "source harness no longer resolves the checkout commit",
)
require(
    '[[ "$actual_sha" != "$NETBOX_SHA" ]]' in harness,
    "source harness no longer fails closed on checkout drift",
)
require("Found [1-9][0-9]* test" in harness, "zero-test fail-closed guard missing")
require("4.6.0–4.7.99" in readme, "README support range drifted")
require("--branch v4.7.0-beta2" in development, "development checkout is not beta2")

print("NetBox compatibility contract is pinned and internally consistent")
