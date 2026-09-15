"""Reviewed OpenBao 2.6.2 secret-engine and mounted-operation contracts.

Runtime OpenAPI proves that an operation exists. It never chooses a URL,
method, permission, response class, or caller identity. Those decisions remain
fixed here and are intersected with the live document at request time.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Final
from urllib.parse import quote

from .schema import CapabilityDocument, CapabilitySchemaError, DiscoveredOperation

MAX_ENGINE_MOUNTS: Final = 512
MAX_ENGINE_PATH: Final = 128
MAX_QUERY_BYTES: Final = 65_536
MAX_RESOURCE_PATH: Final = 1_024
MAX_REQUEST_BYTES: Final = 1_000_000
MAX_RESPONSE_BYTES: Final = 2_000_000
MAX_VALUE_DEPTH: Final = 20
MAX_VALUE_FIELDS: Final = 2_000
MAX_VALUE_ITEMS: Final = 2_000
MAX_VALUE_STRING: Final = 100_000

MOUNT_TYPES: Final = frozenset(
    {
        "ad",
        "alicloud",
        "aws",
        "azure",
        "consul",
        "database",
        "gcp",
        "generic",
        "kv",
        "kubernetes",
        "ldap",
        "mongodb",
        "nomad",
        "openldap",
        "pki",
        "rabbitmq",
        "ssh",
        "terraform",
        "totp",
        "transit",
    }
)
RESERVED_MOUNT_PATHS: Final = frozenset({"cubbyhole", "identity", "sys"})
GENERIC_METHODS: Final = frozenset({"GET", "LIST", "POST", "PUT", "PATCH", "DELETE"})
DESTRUCTIVE_PATH_SEGMENTS: Final = frozenset({"delete", "destroy", "revoke"})

_MOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_RESOURCE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+~-]{0,199}$")
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,499}$")
_MIGRATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_DURATION_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})(?:ns|us|µs|ms|s|m|h|d)?$")
_MOUNTED_TEMPLATE_RE = re.compile(r"^/\{secret_mount_path\}(?:/[A-Za-z0-9_.:@+~-]+|/\{[A-Za-z][A-Za-z0-9_]{0,63}\})*$")


@dataclass(frozen=True, slots=True)
class SecretEngineMount:
    path: str
    engine_type: str
    accessor: str = ""
    description: str = ""
    local: bool = False
    seal_wrap: bool = False
    default_lease_ttl: int = 0
    max_lease_ttl: int = 0
    plugin_version: str = ""
    kv_version: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExplorerOperation:
    operation_key: str
    operation_id: str
    method: str
    path_template: str
    mount_parameter: str
    summary: str
    risk_level: str
    response_class: str
    required_permission: str
    executable: bool
    query_parameters: tuple[str, ...]
    required_query_parameters: tuple[str, ...]
    path_parameters: tuple[str, ...]
    required_path_parameters: tuple[str, ...]
    path_parameter_types: tuple[tuple[str, str], ...]
    body_fields: tuple[str, ...]
    required_body_fields: tuple[str, ...]
    query_parameter_types: tuple[tuple[str, str], ...]
    body_field_types: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_mount_path(value: Any) -> str:
    if not isinstance(value, str):
        raise CapabilitySchemaError("The secret-engine mount path is invalid.")
    normalized = value.strip().strip("/")
    if not _MOUNT_RE.fullmatch(normalized):
        raise CapabilitySchemaError("The secret-engine mount path is invalid.")
    return normalized


def normalize_resource_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RESOURCE_PATH:
        raise CapabilitySchemaError("The mounted resource path is invalid.")
    if value != value.strip() or value.startswith("/") or value.endswith("/") or "//" in value:
        raise CapabilitySchemaError("The mounted resource path is invalid.")
    segments = value.split("/")
    if any(not _RESOURCE_SEGMENT_RE.fullmatch(segment) or segment in {".", ".."} for segment in segments):
        raise CapabilitySchemaError("The mounted resource path is invalid.")
    return "/".join(segments)


def normalize_migration_id(value: Any) -> str:
    if not isinstance(value, str) or not _MIGRATION_ID_RE.fullmatch(value):
        raise CapabilitySchemaError("The remount migration identifier is invalid.")
    return value


def _public_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise CapabilitySchemaError(f"OpenBao returned invalid {field} metadata.")
    return value


def _public_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CapabilitySchemaError(f"OpenBao returned invalid {field} metadata.")
    return value


def normalize_secret_engine_mounts(payload: Any) -> tuple[SecretEngineMount, ...]:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or len(data) > MAX_ENGINE_MOUNTS:
        raise CapabilitySchemaError("OpenBao returned invalid secret-engine metadata.")
    mounts: list[SecretEngineMount] = []
    for raw_path, raw_mount in data.items():
        if not isinstance(raw_mount, dict):
            raise CapabilitySchemaError("OpenBao returned invalid secret-engine metadata.")
        path = normalize_mount_path(raw_path)
        config = raw_mount.get("config") or {}
        options = raw_mount.get("options") or {}
        if not isinstance(config, dict):
            raise CapabilitySchemaError("OpenBao returned invalid secret-engine metadata.")
        if not isinstance(options, dict):
            raise CapabilitySchemaError("OpenBao returned invalid secret-engine metadata.")
        raw_kv_version = options.get("version", "") if raw_mount.get("type") == "kv" else ""
        if not isinstance(raw_kv_version, str) or raw_kv_version not in {"", "1", "2"}:
            raise CapabilitySchemaError("OpenBao returned invalid KV engine metadata.")
        mounts.append(
            SecretEngineMount(
                path=path,
                engine_type=_public_text(raw_mount.get("type", ""), "engine type", 100),
                accessor=_public_text(raw_mount.get("accessor", ""), "engine accessor", 200),
                description=_public_text(raw_mount.get("description", ""), "engine description", 500),
                local=raw_mount.get("local", False) is True,
                seal_wrap=raw_mount.get("seal_wrap", False) is True,
                default_lease_ttl=_public_integer(config.get("default_lease_ttl", 0), "default lease TTL"),
                max_lease_ttl=_public_integer(config.get("max_lease_ttl", 0), "maximum lease TTL"),
                plugin_version=_public_text(raw_mount.get("plugin_version", ""), "plugin version", 100),
                kv_version=int(raw_kv_version) if raw_kv_version else 0,
            )
        )
    return tuple(sorted(mounts, key=lambda mount: mount.path))


def validate_enable_payload(payload: Any) -> dict[str, Any]:
    allowed = {
        "type",
        "description",
        "local",
        "seal_wrap",
        "external_entropy_access",
        "options",
        "config",
        "plugin_name",
        "plugin_version",
    }
    result = validate_bounded_json(payload, allowed_top_level=allowed)
    engine_type = result.get("type")
    if not isinstance(engine_type, str) or engine_type not in MOUNT_TYPES:
        raise CapabilitySchemaError("The secret-engine type is not in the reviewed registry.")
    for field in ("description", "plugin_name", "plugin_version"):
        if field in result and (not isinstance(result[field], str) or len(result[field]) > 500):
            raise CapabilitySchemaError(f"The secret-engine {field.replace('_', ' ')} is invalid.")
    for field in ("local", "seal_wrap", "external_entropy_access"):
        if field in result and not isinstance(result[field], bool):
            raise CapabilitySchemaError(f"The secret-engine {field.replace('_', ' ')} is invalid.")
    if "options" in result:
        _validate_string_mapping(result["options"], "options")
    if "config" in result:
        _validate_mount_config(result["config"])
    return result


def validate_tune_payload(payload: Any) -> dict[str, Any]:
    allowed = {
        "default_lease_ttl",
        "max_lease_ttl",
        "description",
        "audit_non_hmac_request_keys",
        "audit_non_hmac_response_keys",
        "listing_visibility",
        "passthrough_request_headers",
        "allowed_response_headers",
        "token_type",
        "plugin_version",
        "user_lockout_config",
        "options",
    }
    result = validate_bounded_json(payload, allowed_top_level=allowed)
    if not result:
        raise CapabilitySchemaError("At least one reviewed tune field is required.")
    _validate_tune_fields(result)
    return result


def _validate_string_mapping(value: Any, field: str) -> None:
    if not isinstance(value, dict) or len(value) > 100:
        raise CapabilitySchemaError(f"The secret-engine {field} are invalid.")
    for key, child in value.items():
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError(f"The secret-engine {field} are invalid.")
        if not isinstance(child, str) or len(child) > 2_000 or "\x00" in child:
            raise CapabilitySchemaError(f"The secret-engine {field} are invalid.")


def _validate_mount_config(value: Any) -> None:
    allowed = {
        "default_lease_ttl",
        "max_lease_ttl",
        "force_no_cache",
        "audit_non_hmac_request_keys",
        "audit_non_hmac_response_keys",
        "listing_visibility",
        "passthrough_request_headers",
        "allowed_response_headers",
        "allowed_managed_keys",
        "token_type",
        "user_lockout_config",
        "plugin_version",
        "plugin_name",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        raise CapabilitySchemaError("The secret-engine config is invalid.")
    for name in ("default_lease_ttl", "max_lease_ttl"):
        if name in value:
            _validate_duration(value[name], allow_integer=True)
    if "force_no_cache" in value and not isinstance(value["force_no_cache"], bool):
        raise CapabilitySchemaError("The secret-engine config is invalid.")
    nested = {name: child for name, child in value.items() if name not in {"default_lease_ttl", "max_lease_ttl"}}
    _validate_tune_fields(nested)


def _validate_tune_fields(value: dict[str, Any]) -> None:
    string_fields = {"description", "listing_visibility", "token_type", "plugin_version", "plugin_name"}
    list_fields = {
        "audit_non_hmac_request_keys",
        "audit_non_hmac_response_keys",
        "passthrough_request_headers",
        "allowed_response_headers",
        "allowed_managed_keys",
    }
    for name in string_fields & value.keys():
        if not isinstance(value[name], str) or len(value[name]) > 2_000 or "\x00" in value[name]:
            raise CapabilitySchemaError("The secret-engine tune configuration is invalid.")
    for name in {"default_lease_ttl", "max_lease_ttl"} & value.keys():
        _validate_duration(value[name], allow_integer=False)
    if value.get("listing_visibility") not in {None, "", "hidden", "unauth"}:
        raise CapabilitySchemaError("The secret-engine tune configuration is invalid.")
    if value.get("token_type") not in {None, "", "default-service", "default-batch", "service", "batch"}:
        raise CapabilitySchemaError("The secret-engine tune configuration is invalid.")
    for name in list_fields & value.keys():
        _validate_string_list(value[name])
    if "options" in value:
        _validate_string_mapping(value["options"], "options")
    if "user_lockout_config" in value:
        _validate_user_lockout_config(value["user_lockout_config"])


def _validate_string_list(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 100:
        raise CapabilitySchemaError("The secret-engine tune configuration is invalid.")
    if any(not isinstance(item, str) or len(item) > 500 or "\x00" in item for item in value):
        raise CapabilitySchemaError("The secret-engine tune configuration is invalid.")


def _validate_user_lockout_config(value: Any) -> None:
    allowed = {
        "lockout_counter_reset_duration",
        "lockout_threshold",
        "lockout_duration",
        "lockout_disable",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        raise CapabilitySchemaError("The secret-engine user lockout configuration is invalid.")
    if "lockout_threshold" in value and (
        isinstance(value["lockout_threshold"], bool)
        or not isinstance(value["lockout_threshold"], int)
        or not 0 <= value["lockout_threshold"] <= 18_446_744_073_709_551_615
    ):
        raise CapabilitySchemaError("The secret-engine user lockout configuration is invalid.")
    for name in {"lockout_counter_reset_duration", "lockout_duration"} & value.keys():
        _validate_duration(value[name], allow_integer=False)
    if "lockout_disable" in value and not isinstance(value["lockout_disable"], bool):
        raise CapabilitySchemaError("The secret-engine user lockout configuration is invalid.")


def validate_bounded_json(value: Any, *, allowed_top_level: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CapabilitySchemaError("The OpenBao request body must be an object.")
    if allowed_top_level is not None and set(value) - allowed_top_level:
        raise CapabilitySchemaError("The OpenBao request body contains an undeclared field.")
    try:
        encoded_size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode())
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise CapabilitySchemaError("The OpenBao request body contains an unsupported value.") from None
    if encoded_size > MAX_REQUEST_BYTES:
        raise CapabilitySchemaError("The OpenBao request body is too large.")
    counters = {"fields": 0, "items": 0, "bytes": 0}
    _validate_json_value(value, counters, depth=0)
    if counters["bytes"] > MAX_REQUEST_BYTES:
        raise CapabilitySchemaError("The OpenBao request body is too large.")
    return value


def _validate_json_value(value: Any, counters: dict[str, int], *, depth: int) -> None:
    if depth > MAX_VALUE_DEPTH:
        raise CapabilitySchemaError("The OpenBao request body is nested too deeply.")
    if isinstance(value, dict):
        _validate_json_mapping(value, counters, depth)
        return
    if isinstance(value, list):
        _validate_json_list(value, counters, depth)
        return
    _validate_json_scalar(value, counters)


def _validate_json_mapping(value: dict, counters: dict[str, int], depth: int) -> None:
    counters["fields"] += len(value)
    if counters["fields"] > MAX_VALUE_FIELDS:
        raise CapabilitySchemaError("The OpenBao request body has too many fields.")
    for key, child in value.items():
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("The OpenBao request body contains an invalid field name.")
        counters["bytes"] += len(key.encode())
        _validate_json_value(child, counters, depth=depth + 1)


def _validate_json_list(value: list, counters: dict[str, int], depth: int) -> None:
    counters["items"] += len(value)
    if counters["items"] > MAX_VALUE_ITEMS:
        raise CapabilitySchemaError("The OpenBao request body has too many list items.")
    for child in value:
        _validate_json_value(child, counters, depth=depth + 1)


def _validate_json_scalar(value: Any, counters: dict[str, int]) -> None:
    if isinstance(value, str):
        if len(value) > MAX_VALUE_STRING or "\x00" in value:
            raise CapabilitySchemaError("The OpenBao request body contains an invalid string.")
        counters["bytes"] += len(value.encode())
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise CapabilitySchemaError("The OpenBao request body contains an unsupported value.")
    if value is not None and not isinstance(value, (bool, int, float)):
        raise CapabilitySchemaError("The OpenBao request body contains an unsupported value.")


def _generic_template(operation: DiscoveredOperation) -> bool:
    if operation.family != "mounted-secrets" or not _MOUNTED_TEMPLATE_RE.fullmatch(operation.path_template):
        return False
    placeholders = set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]{0,63})\}", operation.path_template))
    return set(operation.path_parameters) == placeholders and set(operation.required_path_parameters) == placeholders


def classify_explorer_operations(document: CapabilityDocument) -> tuple[ExplorerOperation, ...]:
    result = []
    for operation in document.operations:
        executable = operation.method in GENERIC_METHODS and _generic_template(operation)
        risk = _mounted_operation_risk(operation)
        permission = (
            "netbox_openbao.reveal_secret_operations_openbaocluster"
            if risk == "read"
            else "netbox_openbao.delete_secret_operations_openbaocluster"
            if risk == "destructive"
            else "netbox_openbao.execute_secret_operations_openbaocluster"
        )
        result.append(
            ExplorerOperation(
                operation_key=operation.operation_key,
                operation_id=operation.operation_id,
                method=operation.method,
                path_template=operation.path_template,
                mount_parameter=operation.mount_parameter,
                summary=operation.summary,
                risk_level=risk,
                response_class="sensitive-material",
                required_permission=permission,
                executable=executable,
                query_parameters=operation.query_parameters,
                required_query_parameters=operation.required_query_parameters,
                path_parameters=operation.path_parameters,
                required_path_parameters=operation.required_path_parameters,
                path_parameter_types=operation.path_parameter_types,
                body_fields=operation.body_fields,
                required_body_fields=operation.required_body_fields,
                query_parameter_types=operation.query_parameter_types,
                body_field_types=operation.body_field_types,
            )
        )
    return tuple(sorted(result, key=lambda item: (not item.executable, item.operation_key)))


def _mounted_operation_risk(operation: DiscoveredOperation) -> str:
    if operation.method == "DELETE":
        return "destructive"
    segments = {segment.lower() for segment in operation.path_template.split("/")}
    if operation.method in {"POST", "PUT", "PATCH"} and segments & DESTRUCTIVE_PATH_SEGMENTS:
        return "destructive"
    if operation.method in {"GET", "LIST"}:
        return "read"
    return "write"


def resolve_explorer_operation(document: CapabilityDocument, operation_key: str) -> ExplorerOperation:
    matches = [item for item in classify_explorer_operations(document) if item.operation_key == operation_key]
    if len(matches) != 1 or not matches[0].executable:
        raise CapabilitySchemaError("The selected operation is not in the reviewed executable registry.")
    return matches[0]


def compile_mounted_path(mount_path: Any, resource_path: Any) -> str:
    mount = normalize_mount_path(mount_path)
    resource = normalize_resource_path(resource_path)
    encoded = "/".join(quote(segment, safe="-._~:@+") for segment in resource.split("/"))
    return f"/{quote(mount, safe='-._~')}/{encoded}"


def mount_parameter_for_path(mount_path: Any) -> str:
    mount = normalize_mount_path(mount_path)
    return f"{re.sub(r'[^A-Za-z0-9]', '_', mount)}_mount_path"


def compile_operation_path(
    template: str,
    mount_path: Any,
    resource_path: Any,
    path_parameters: Any,
) -> str:
    """Compile one admitted mount-scoped template without accepting a raw path."""
    if not isinstance(template, str) or not _MOUNTED_TEMPLATE_RE.fullmatch(template):
        raise CapabilitySchemaError("The mounted operation template is outside the reviewed registry.")
    if not isinstance(path_parameters, dict) or len(path_parameters) > 16:
        raise CapabilitySchemaError("The mounted operation path parameters are invalid.")
    placeholders = set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]{0,63})\}", template))
    replacements = _operation_replacements(placeholders, mount_path, resource_path, path_parameters)
    compiled = template
    for name, value in replacements.items():
        compiled = compiled.replace(f"{{{name}}}", value)
    if "{" in compiled or "}" in compiled:
        raise CapabilitySchemaError("The mounted operation template has unresolved parameters.")
    return compiled


def _operation_replacements(
    placeholders: set[str],
    mount_path: Any,
    resource_path: Any,
    path_parameters: dict,
) -> dict[str, str]:
    mount = normalize_mount_path(mount_path)
    resource = normalize_resource_path(resource_path) if resource_path else ""
    expected = placeholders - {"secret_mount_path", "path"}
    if set(path_parameters) != expected or ("path" in placeholders) != bool(resource):
        raise CapabilitySchemaError("The mounted operation path parameters do not match the reviewed template.")
    replacements = {"secret_mount_path": quote(mount, safe="-._~")}
    if "path" in placeholders:
        replacements["path"] = "/".join(quote(part, safe="-._~:@+") for part in resource.split("/"))
    for name, value in path_parameters.items():
        if isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, int):
            value = str(value)
        elif isinstance(value, float) and math.isfinite(value):
            value = str(value)
        if not isinstance(value, str) or not _RESOURCE_SEGMENT_RE.fullmatch(value) or value in {".", ".."}:
            raise CapabilitySchemaError("The mounted operation path parameters are invalid.")
        replacements[name] = quote(value, safe="-._~:@+")
    return replacements


def validate_query(value: Any) -> dict[str, Any]:
    if value in (None, {}):
        return {}
    if not isinstance(value, dict) or len(value) > 32:
        raise CapabilitySchemaError("The OpenBao query parameters are invalid.")
    try:
        encoded_size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode())
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise CapabilitySchemaError("The OpenBao query parameters are invalid.") from None
    if encoded_size > MAX_QUERY_BYTES:
        raise CapabilitySchemaError("The OpenBao query parameters are invalid.")
    result: dict[str, Any] = {}
    for key, child in value.items():
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("The OpenBao query parameters are invalid.")
        _validate_query_value(child)
        result[key] = child
    return result


def _validate_query_value(value: Any) -> None:
    if isinstance(value, str):
        if len(value) <= 2_000 and "\x00" not in value:
            return
    elif isinstance(value, (bool, int)):
        return
    elif isinstance(value, float):
        if math.isfinite(value):
            return
    elif isinstance(value, list) and len(value) <= 100:
        if all(not isinstance(item, (dict, list)) for item in value):
            for item in value:
                _validate_query_value(item)
            return
    raise CapabilitySchemaError("The OpenBao query parameters are invalid.")


def validate_declared_field_types(value: dict[str, Any], declared_types: tuple[tuple[str, str], ...]) -> None:
    expected = dict(declared_types)
    for name, child in value.items():
        if not _matches_declared_type(child, expected.get(name, "json")):
            raise CapabilitySchemaError("The OpenBao request field has an invalid JSON type.")


def _matches_declared_type(value: Any, declared: str) -> bool:
    validators = {
        "array": lambda child: isinstance(child, list),
        "boolean": lambda child: isinstance(child, bool),
        "integer": lambda child: isinstance(child, int) and not isinstance(child, bool),
        "number": lambda child: isinstance(child, (int, float)) and not isinstance(child, bool),
        "object": lambda child: isinstance(child, dict),
        "string": lambda child: isinstance(child, str),
    }
    return declared == "json" or validators.get(declared, lambda _child: False)(value)


def _validate_duration(value: Any, *, allow_integer: bool) -> None:
    if allow_integer and isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value <= 9_223_372_036_854_775_807:
            return
    if isinstance(value, str) and _DURATION_RE.fullmatch(value):
        return
    raise CapabilitySchemaError("The secret-engine duration is invalid.")
