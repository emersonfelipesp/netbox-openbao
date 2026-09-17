"""Reviewed OpenBao 2.6.2 lease, tool, and UI configuration contracts."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final
from urllib.parse import quote

from .access import FieldRule, operation_shape, validate_access_payload
from .schema import CapabilityDocument, CapabilitySchemaError

_LEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,499}$")
_HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,126}$")
_ALGORITHM_RE = re.compile(r"^(sha2-(224|256|384|512)|sha3-(224|256|384|512))$")
_SOURCE_RE = re.compile(r"^(platform|all)$")
_DURATION_RE = re.compile(r"^(?:[1-9][0-9]*(?:ns|us|µs|ms|s|m|h))+$")

TEXT = FieldRule("text", maximum=20_000)
MATERIAL_TEXT = FieldRule("text", maximum=100_000, material=True)
BOOL = FieldRule("boolean", maximum=1)
POSITIVE_INTEGER = FieldRule("positive-integer", maximum=1_048_576)
STRING_LIST = FieldRule("string-list", maximum=256)
JSON_MAP = FieldRule("json-map", maximum=256)
MAX_WRAPPING_JSON_BYTES = 256_000
MAX_WRAPPING_JSON_DEPTH = 12
MAX_WRAPPING_JSON_MEMBERS = 2_000
MAX_WRAPPING_JSON_STRING = 100_000


@dataclass(frozen=True, slots=True)
class FinalOperation:
    method: str
    path_template: str
    permission: str
    risk: str
    fields: dict[str, FieldRule] = field(default_factory=dict)
    response_kind: str = "metadata"
    confirmation: str = ""
    identifier_kind: str = ""

    def public(self) -> dict:
        return {
            "method": self.method,
            "risk": self.risk,
            "required_permission": f"netbox_openbao.{self.permission}",
            "response_kind": self.response_kind,
            "destructive": bool(self.confirmation),
            "confirmation": self.confirmation,
            "identifier_required": "{identifier}" in self.path_template,
            "identifier_kind": self.identifier_kind,
            "fields": {
                name: {
                    "kind": rule.kind,
                    "required": rule.required,
                    "maximum": rule.maximum,
                    "choices": sorted(rule.choices),
                    "material": rule.material,
                }
                for name, rule in self.fields.items()
            },
        }


@dataclass(frozen=True, slots=True)
class FinalResource:
    key: str
    label: str
    family: str
    operations: dict[str, FinalOperation]

    def path(self, operation: str, identifier: str = "") -> str:
        contract = self.operations[operation]
        safe = "/" if contract.identifier_kind == "lease-prefix" else ""
        if contract.identifier_kind == "lease-prefix":
            identifier = identifier.rstrip("/")
        return contract.path_template.replace("{identifier}", quote(identifier, safe=safe))

    def public(self) -> dict:
        operations = {name: operation.public() for name, operation in self.operations.items()}
        if self.key == "leases" and "list" in operations:
            operations["list"]["identifier_allow_blank"] = True
        return {
            "key": self.key,
            "label": self.label,
            "family": self.family,
            "operations": operations,
        }


def _op(method, path, permission, risk, *, fields=None, response="metadata", confirmation="", kind=""):
    return FinalOperation(method, path, permission, risk, fields or {}, response, confirmation, kind)


FINAL_RESOURCES: Final = {
    "leases": FinalResource(
        "leases",
        "Leases",
        "leases",
        {
            "list": _op(
                "LIST", "/sys/leases/lookup/{identifier}", "view_leases_openbaocluster", "read", kind="lease-prefix"
            ),
            "lookup": _op(
                "POST",
                "/sys/leases/lookup",
                "view_leases_openbaocluster",
                "read",
                fields={"lease_id": FieldRule("text", required=True, maximum=500)},
            ),
            "renew": _op(
                "POST",
                "/sys/leases/renew",
                "manage_leases_openbaocluster",
                "write",
                fields={"lease_id": FieldRule("text", required=True, maximum=500), "increment": POSITIVE_INTEGER},
            ),
            "revoke": _op(
                "POST",
                "/sys/leases/revoke",
                "revoke_leases_openbaocluster",
                "destructive",
                fields={"lease_id": FieldRule("text", required=True, maximum=500), "sync": BOOL},
                confirmation="REVOKE lease {target} ON {cluster}",
            ),
            "revoke-prefix": _op(
                "POST",
                "/sys/leases/revoke-prefix/{identifier}",
                "revoke_leases_openbaocluster",
                "destructive",
                fields={"sync": BOOL},
                confirmation="REVOKE lease prefix {target} ON {cluster}",
                kind="lease-prefix",
            ),
            "force-revoke": _op(
                "POST",
                "/sys/leases/revoke-force/{identifier}",
                "force_revoke_leases_openbaocluster",
                "destructive",
                confirmation="FORCE REVOKE lease prefix {target} ON {cluster}",
                kind="lease-prefix",
            ),
        },
    ),
    "wrapping": FinalResource(
        "wrapping",
        "Response wrapping",
        "tools",
        {
            "wrap": _op(
                "POST",
                "/sys/wrapping/wrap",
                "use_wrapping_openbaocluster",
                "write",
                fields={
                    "data": FieldRule(
                        "bounded-json-map", required=True, maximum=MAX_WRAPPING_JSON_MEMBERS, material=True
                    ),
                    "ttl": FieldRule("duration", maximum=100),
                },
                response="material",
            ),
            "lookup": _op(
                "POST",
                "/sys/wrapping/lookup",
                "use_wrapping_openbaocluster",
                "read",
                fields={"token": FieldRule("text", required=True, maximum=20_000, material=True)},
            ),
            "rewrap": _op(
                "POST",
                "/sys/wrapping/rewrap",
                "use_wrapping_openbaocluster",
                "write",
                fields={"token": FieldRule("text", required=True, maximum=20_000, material=True)},
                response="material",
            ),
            "unwrap": _op(
                "POST",
                "/sys/wrapping/unwrap",
                "unwrap_material_openbaocluster",
                "write",
                fields={"token": FieldRule("text", required=True, maximum=20_000, material=True)},
                response="material",
            ),
        },
    ),
    "hash": FinalResource(
        "hash",
        "Hash tool",
        "tools",
        {
            "run": _op(
                "POST",
                "/sys/tools/hash/{identifier}",
                "use_tools_openbaocluster",
                "write",
                fields={
                    "input": FieldRule("base64-text", required=True, maximum=1_000_000, material=True),
                    "format": FieldRule("choice", maximum=20, choices=frozenset({"hex", "base64"})),
                },
                response="material",
                kind="algorithm",
            )
        },
    ),
    "random": FinalResource(
        "random",
        "Random data tool",
        "tools",
        {
            "generate": _op(
                "POST",
                "/sys/tools/random/{identifier}",
                "use_tools_openbaocluster",
                "write",
                fields={
                    "bytes": FieldRule("strict-positive-integer", required=True, maximum=4096),
                    "format": FieldRule("choice", maximum=20, choices=frozenset({"hex", "base64"})),
                },
                response="material",
                kind="source",
            )
        },
    ),
    "token-tools": FinalResource(
        "token-tools",
        "Token lookup tool",
        "tools",
        {
            "lookup": _op(
                "POST",
                "/auth/token/lookup",
                "manage_tokens_openbaocluster",
                "read",
                fields={"token": FieldRule("text", required=True, maximum=20_000, material=True)},
            )
        },
    ),
    "ui-headers": FinalResource(
        "ui-headers",
        "UI response headers",
        "ui-configuration",
        {
            "list": _op("LIST", "/sys/config/ui/headers", "view_ui_configuration_openbaocluster", "read"),
            "read": _op(
                "GET",
                "/sys/config/ui/headers/{identifier}",
                "view_ui_configuration_openbaocluster",
                "read",
                kind="header",
            ),
            "write": _op(
                "POST",
                "/sys/config/ui/headers/{identifier}",
                "manage_ui_configuration_openbaocluster",
                "write",
                fields={"values": FieldRule("header-values", required=True, maximum=64)},
                confirmation="REPLACE UI header {target} ON {cluster}",
                kind="header",
            ),
            "delete": _op(
                "DELETE",
                "/sys/config/ui/headers/{identifier}",
                "manage_ui_configuration_openbaocluster",
                "destructive",
                confirmation="DELETE UI header {target} ON {cluster}",
                kind="header",
            ),
        },
    ),
}


def normalize_final_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise CapabilitySchemaError("The operation identifier is invalid.")
    matcher = {"lease-prefix": _LEASE_RE, "header": _HEADER_RE, "algorithm": _ALGORITHM_RE, "source": _SOURCE_RE}.get(
        kind
    )
    if matcher is None or not matcher.fullmatch(value) or ".." in value or "//" in value:
        raise CapabilitySchemaError("The operation identifier is invalid.")
    return value


def operation_contract(resource_key: str, operation_name: str) -> tuple[FinalResource, FinalOperation]:
    try:
        resource = FINAL_RESOURCES[resource_key]
        return resource, resource.operations[operation_name]
    except (KeyError, TypeError):
        raise CapabilitySchemaError("The finalization operation is unsupported.") from None


def _validate_json_text(value: str, *, key: bool = False) -> None:
    if len(value) > MAX_WRAPPING_JSON_STRING or any(ord(character) < 32 for character in value):
        label = "object key" if key else "string"
        raise CapabilitySchemaError(f"The wrapping data contains an invalid {label}.")


def _wrapping_children(item):
    if isinstance(item, dict):
        for key, child in item.items():
            if not isinstance(key, str):
                raise CapabilitySchemaError("The wrapping data contains an invalid object key.")
            _validate_json_text(key, key=True)
            yield child
    elif isinstance(item, list):
        yield from item


def _validate_wrapping_scalar(item) -> None:
    if isinstance(item, str):
        _validate_json_text(item)
    elif isinstance(item, float) and not math.isfinite(item):
        raise CapabilitySchemaError("The wrapping data contains a non-finite number.")
    elif item is not None and not isinstance(item, (dict, list, bool, int, float)):
        raise CapabilitySchemaError("The wrapping data contains an unsupported value.")


def _validate_wrapping_json(value) -> dict:
    if not isinstance(value, dict):
        raise CapabilitySchemaError("The wrapping data must be a JSON object.")
    members = 0
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_WRAPPING_JSON_DEPTH:
            raise CapabilitySchemaError("The wrapping data is nested too deeply.")
        children = list(_wrapping_children(item))
        members += len(children)
        if members > MAX_WRAPPING_JSON_MEMBERS:
            raise CapabilitySchemaError("The wrapping data contains too many members.")
        _validate_wrapping_scalar(item)
        pending.extend((child, depth + 1) for child in children)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_WRAPPING_JSON_BYTES:
        raise CapabilitySchemaError("The wrapping data exceeds its reviewed size bound.")
    return value


def _ordinary_validation_fields(operation: FinalOperation) -> dict[str, FieldRule]:
    return {
        name: FieldRule("text", rule.required, rule.maximum, rule.choices, rule.material)
        if rule.kind == "duration" else
        FieldRule("string-list", rule.required, rule.maximum, rule.choices, rule.material)
        if rule.kind == "header-values" else rule
        for name, rule in operation.fields.items()
        if rule.kind != "bounded-json-map"
    }


def _add_bounded_fields(normalized: dict, payload: dict, operation: FinalOperation) -> None:
    for name, rule in operation.fields.items():
        if rule.kind != "bounded-json-map":
            continue
        if name not in payload:
            if rule.required:
                raise CapabilitySchemaError("The operation payload is missing a required field.")
            continue
        normalized[name] = _validate_wrapping_json(payload[name])


def _validate_normalized_value(value, rule: FieldRule) -> None:
    if isinstance(value, int) and not isinstance(value, bool) and value > rule.maximum:
        raise CapabilitySchemaError("The operation payload exceeds its reviewed bound.")
    if isinstance(value, dict) and len(value) > rule.maximum:
        raise CapabilitySchemaError("The operation payload exceeds its reviewed bound.")
    if rule.kind == "duration" and (not isinstance(value, str) or not _DURATION_RE.fullmatch(value)):
        raise CapabilitySchemaError("The operation payload contains an invalid duration.")
    if rule.kind == "header-values" and any(
        any(ord(character) < 32 or ord(character) == 127 for character in item) for item in value
    ):
        raise CapabilitySchemaError("UI header values must not contain control characters.")


def validate_payload(payload, operation: FinalOperation) -> dict:
    if not isinstance(payload, dict):
        raise CapabilitySchemaError("The operation payload must be an object.")
    fields = _ordinary_validation_fields(operation)
    ordinary = {name: value for name, value in payload.items() if name in fields}
    if set(payload) - set(operation.fields):
        raise CapabilitySchemaError("The operation payload contains unsupported fields.")
    normalized = validate_access_payload(ordinary, fields)
    _add_bounded_fields(normalized, payload, operation)
    for name, value in normalized.items():
        _validate_normalized_value(value, operation.fields[name])
    return normalized


def advertised(document: CapabilityDocument, operation: FinalOperation) -> bool:
    expected = 2 if operation.path_template == "/sys/leases/lookup/{identifier}" else 1
    return len(_runtime_matches(document, operation)) == expected


def _valid_fixture_entry(entry) -> bool:
    expected_keys = {"resource", "operation", "method", "path", "operation_ids", "query", "body"}
    if not isinstance(entry, dict) or set(entry) != expected_keys:
        return False
    if not isinstance(entry["operation_ids"], list) or not entry["operation_ids"]:
        return False
    if not all(isinstance(value, str) and value for value in entry["operation_ids"]):
        return False
    for mapping in (entry["query"], entry["body"]):
        typed_strings = isinstance(mapping, dict) and all(
            isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()
        )
        if not typed_strings:
            return False
    return True


def load_final_route_fixture() -> dict:
    fixture = json.loads(Path(__file__).with_name("openbao-final-v2.6.2.json").read_text(encoding="utf-8"))
    expected = {
        (resource.key, name, operation.method, operation.path_template)
        for resource in FINAL_RESOURCES.values()
        for name, operation in resource.operations.items()
    }
    actual = {
        (entry.get("resource"), entry.get("operation"), entry.get("method"), entry.get("path"))
        for entry in fixture.get("operations", [])
        if _valid_fixture_entry(entry)
    }
    entries = fixture.get("operations", [])
    if fixture.get("baseline") != "2.6.2" or len(actual) != len(entries) or actual != expected:
        raise CapabilitySchemaError("The pinned final-operation route fixture is stale or invalid.")
    return fixture


def _runtime_matches(document: CapabilityDocument, operation: FinalOperation) -> list:
    fixture = load_final_route_fixture()
    contract = next(
        entry for entry in fixture["operations"]
        if entry["method"] == operation.method and entry["path"] == operation.path_template
    )
    expected_shapes = {operation_shape(operation.path_template.replace("{identifier}", "{name}"))}
    if operation.path_template == "/sys/leases/lookup/{identifier}":
        expected_shapes.add(operation_shape("/sys/leases/lookup/"))

    def method_matches(candidate) -> bool:
        if candidate.method == operation.method:
            return True
        return operation.method == "LIST" and candidate.method == "GET"

    def identifier_matches(candidate) -> bool:
        if operation.identifier_kind != "source":
            return True
        parameter = candidate.path_template.rsplit("/", 1)[-1].strip("{}").lower()
        return parameter in {"source", "name"}

    def metadata_matches(candidate) -> bool:
        query_types = dict(candidate.query_parameter_types)
        expected_query = {name: kind.removesuffix("!") for name, kind in contract["query"].items()}
        required_query = {name for name, kind in contract["query"].items() if kind.endswith("!")}
        body_types = dict(candidate.body_field_types)
        expected_path_count = (
            0 if candidate.operation_id == "leases-look-up" else operation.path_template.count("{identifier}")
        )
        return (
            candidate.operation_id in contract["operation_ids"]
            and query_types == expected_query
            and set(candidate.required_query_parameters) == required_query
            and body_types == contract["body"]
            and not candidate.required_body_fields
            and len(candidate.path_parameters) == expected_path_count
            and set(candidate.required_path_parameters) == set(candidate.path_parameters)
            and all(kind == "string" for _, kind in candidate.path_parameter_types)
        )

    return [
        candidate
        for candidate in document.operations
        if method_matches(candidate)
        and operation_shape(candidate.path_template) in expected_shapes
        and identifier_matches(candidate)
        and metadata_matches(candidate)
    ]


def conformance_report(document: CapabilityDocument) -> dict:
    load_final_route_fixture()
    entries = []
    for resource in FINAL_RESOURCES.values():
        for name, operation in resource.operations.items():
            matches = _runtime_matches(document, operation)
            expected_count = 2 if resource.key == "leases" and name == "list" else 1
            entries.append(
                {
                    "resource": resource.key,
                    "operation": name,
                    "advertised": len(matches) >= expected_count,
                    "duplicates": max(0, len(matches) - expected_count),
                    "unclassified": sum(not candidate.classified for candidate in matches),
                }
            )
    missing = [entry for entry in entries if not entry["advertised"]]
    duplicates = [entry for entry in entries if entry["duplicates"]]
    unclassified = [entry for entry in entries if entry["unclassified"]]
    stale = document.product_version != "2.6.2"
    return {
        "product_version": document.product_version,
        "operations": entries,
        "missing": missing,
        "duplicates": duplicates,
        "unclassified": unclassified,
        "stale": stale,
        "conformant": not missing and not duplicates and not unclassified and not stale,
    }
