"""Load and validate the pinned OpenBao UI parity ownership manifest."""

import json
from pathlib import Path
from typing import Any

BASELINE_VERSION = '2.6.2'
REQUIRED_FIELDS = frozenset({'id', 'upstream_routes', 'capability', 'owner_issue', 'status'})
ALLOWED_STATUSES = frozenset({'foundation', 'planned', 'complete', 'capability-gated'})


def _validate_family_id(family_id: Any, seen: set[str]) -> None:
    if not isinstance(family_id, str) or not family_id or family_id in seen:
        raise ValueError('The OpenBao UI parity manifest has a missing or duplicate family ID.')
    seen.add(family_id)


def _validate_routes(routes: Any) -> None:
    if not isinstance(routes, list) or not routes:
        raise ValueError('The OpenBao UI parity manifest has invalid upstream routes.')
    if not all(isinstance(route, str) and route for route in routes):
        raise ValueError('The OpenBao UI parity manifest has invalid upstream routes.')


def _validate_family(family: Any, seen: set[str]) -> None:
    if not isinstance(family, dict) or set(family) != REQUIRED_FIELDS:
        raise ValueError('The OpenBao UI parity manifest has an invalid family entry.')
    _validate_family_id(family['id'], seen)
    _validate_routes(family['upstream_routes'])
    if family['status'] not in ALLOWED_STATUSES:
        raise ValueError('The OpenBao UI parity manifest has an invalid status.')
    if not isinstance(family['owner_issue'], int) or family['owner_issue'] < 63:
        raise ValueError('The OpenBao UI parity manifest has an invalid owner issue.')


def load_parity_manifest() -> dict[str, Any]:
    path = Path(__file__).with_name('openbao-ui-v2.6.2.json')
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or manifest.get('baseline') != BASELINE_VERSION:
        raise ValueError('The OpenBao UI parity manifest has an invalid baseline.')
    families = manifest.get('families')
    if not isinstance(families, list) or not families:
        raise ValueError('The OpenBao UI parity manifest has no capability families.')
    seen: set[str] = set()
    for family in families:
        _validate_family(family, seen)
    return manifest
