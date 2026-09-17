"""Load and validate the pinned OpenBao UI parity ownership manifest."""

import json
from pathlib import Path
from typing import Any

BASELINE_VERSION = "2.6.2"
REQUIRED_FIELDS = frozenset({"id", "upstream_routes", "capability", "owner_issue", "status"})
COMPLETE_FIELDS = REQUIRED_FIELDS | {"equivalence", "evidence"}
EVIDENCE_FIELDS = frozenset({"implementation", "ui", "tests"})
TRANSPORTS = frozenset({"direct", "broker"})
ALLOWED_STATUSES = frozenset({"foundation", "planned", "complete", "capability-gated"})


def _validate_family_id(family_id: Any, seen: set[str]) -> None:
    if not isinstance(family_id, str) or not family_id or family_id in seen:
        raise ValueError("The OpenBao UI parity manifest has a missing or duplicate family ID.")
    seen.add(family_id)


def _validate_routes(routes: Any) -> None:
    if not isinstance(routes, list) or not routes:
        raise ValueError("The OpenBao UI parity manifest has invalid upstream routes.")
    if not all(isinstance(route, str) and route for route in routes):
        raise ValueError("The OpenBao UI parity manifest has invalid upstream routes.")
    if len(routes) != len(set(routes)):
        raise ValueError("The OpenBao UI parity manifest has duplicate upstream routes.")


def _validate_evidence_path(repository: Path, raw_path: Any) -> None:
    if not isinstance(raw_path, str) or not raw_path or Path(raw_path).is_absolute():
        raise ValueError("A complete OpenBao UI parity family has invalid evidence paths.")
    candidate = (repository / raw_path).resolve()
    if repository not in candidate.parents or not candidate.is_file():
        raise ValueError("A complete OpenBao UI parity family has invalid evidence paths.")


def _validate_evidence_group(repository: Path, paths: Any) -> None:
    if not isinstance(paths, list) or not paths:
        raise ValueError("A complete OpenBao UI parity family has missing evidence.")
    for raw_path in paths:
        _validate_evidence_path(repository, raw_path)


def _route_mapping(family: dict[str, Any], field: str) -> dict[str, Any]:
    routes = set(family["upstream_routes"])
    mapping = family[field]
    if not isinstance(mapping, dict) or set(mapping) != routes:
        raise ValueError(f"A complete OpenBao UI parity family has invalid route {field} mappings.")
    return mapping


def _validate_evidence(family: dict[str, Any]) -> None:
    equivalence = _route_mapping(family, "equivalence")
    if not all(isinstance(statement, str) and statement.strip() for statement in equivalence.values()):
        raise ValueError("A complete OpenBao UI parity family needs route equivalence statements.")
    evidence = _route_mapping(family, "evidence")
    repository = Path(__file__).resolve().parents[2]
    for groups in evidence.values():
        if not isinstance(groups, dict) or set(groups) != EVIDENCE_FIELDS:
            raise ValueError("A complete OpenBao UI parity family has invalid evidence groups.")
        for paths in groups.values():
            _validate_evidence_group(repository, paths)


def _validate_family(family: Any, seen: set[str]) -> None:
    if not isinstance(family, dict):
        raise ValueError("The OpenBao UI parity manifest has an invalid family entry.")
    required = COMPLETE_FIELDS if family.get("status") == "complete" else REQUIRED_FIELDS
    if set(family) != required:
        raise ValueError("The OpenBao UI parity manifest has an invalid family entry.")
    _validate_family_id(family["id"], seen)
    _validate_routes(family["upstream_routes"])
    if family["status"] not in ALLOWED_STATUSES:
        raise ValueError("The OpenBao UI parity manifest has an invalid status.")
    if not isinstance(family["owner_issue"], int) or family["owner_issue"] < 63:
        raise ValueError("The OpenBao UI parity manifest has an invalid owner issue.")
    if family["status"] == "complete":
        _validate_evidence(family)


def _validate_transport_evidence(manifest: dict[str, Any], complete_families: set[str]) -> None:
    evidence = manifest.get("transport_evidence")
    if not isinstance(evidence, dict) or set(evidence) != complete_families:
        raise ValueError("Complete OpenBao UI parity families need transport evidence.")
    repository = Path(__file__).resolve().parents[2]
    for family_id, transports in evidence.items():
        if not isinstance(transports, dict) or set(transports) != TRANSPORTS:
            raise ValueError(f"OpenBao UI parity family {family_id} has invalid transport evidence.")
        for paths in transports.values():
            _validate_evidence_group(repository, paths)


def load_parity_manifest() -> dict[str, Any]:
    path = Path(__file__).with_name("openbao-ui-v2.6.2.json")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("baseline") != BASELINE_VERSION:
        raise ValueError("The OpenBao UI parity manifest has an invalid baseline.")
    families = manifest.get("families")
    if not isinstance(families, list) or not families:
        raise ValueError("The OpenBao UI parity manifest has no capability families.")
    seen: set[str] = set()
    for family in families:
        _validate_family(family, seen)
    complete_families = {family["id"] for family in families if family["status"] == "complete"}
    _validate_transport_evidence(manifest, complete_families)
    return manifest
