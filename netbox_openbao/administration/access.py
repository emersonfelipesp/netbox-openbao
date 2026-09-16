"""Static OpenBao 2.6.2 policy, identity, OIDC, and namespace contracts.

Runtime OpenAPI proves that a reviewed endpoint exists. It never supplies an
executable path, field, permission, confirmation, response classification, or
namespace. Those decisions live only in this module.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import quote

from .authentication import (
    BOOL,
    MATERIAL_KEYS,
    POSITIVE_INTEGER,
    STRING_LIST,
    STRING_MAP,
    FieldRule,
    validate_reviewed_payload,
)
from .schema import CapabilitySchemaError

MAX_ACCESS_NAME: Final = 200
MAX_POLICY_DOCUMENT: Final = 256_000
MAX_TEMPLATE_DOCUMENT: Final = 64_000
ACCESS_OPERATIONS: Final = frozenset({"list", "read", "write", "delete", "rotate", "merge", "generate"})
ACCESS_MATERIAL_KEYS: Final = MATERIAL_KEYS | frozenset({"client_secret", "key_shares"})

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,199}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ACCESSOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_NAMESPACE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z][A-Za-z0-9_]*\}")


def _text(*, required: bool = False, maximum: int = 20_000, material: bool = False) -> FieldRule:
    return FieldRule("text", required=required, maximum=maximum, material=material)


def _choice(*values: str, required: bool = False) -> FieldRule:
    return FieldRule("choice", required=required, maximum=100, choices=frozenset(values))


UUID_LIST = FieldRule("uuid-list", maximum=256)
UUID_TEXT = FieldRule("uuid", maximum=36)
URL_LIST = FieldRule("url-list", maximum=64)
POLICY_TEXT = _text(required=True, maximum=MAX_POLICY_DOCUMENT)
TEMPLATE_TEXT = _text(required=True, maximum=MAX_TEMPLATE_DOCUMENT)


@dataclass(frozen=True, slots=True)
class AccessOperationSpec:
    """One reviewed operation on an OpenBao access-control resource."""

    method: str
    path_template: str
    permission: str
    risk: str
    fields: dict[str, FieldRule] = field(default_factory=dict)
    response_kind: str = "metadata"
    confirmation: str = ""


@dataclass(frozen=True, slots=True)
class AccessResourceSpec:
    """One fixed policy, identity, OIDC, or namespace resource family."""

    key: str
    label: str
    family: str
    identifier_kind: str
    operations: dict[str, AccessOperationSpec]

    def path(self, operation: str, identifier: str = "") -> str:
        contract = self.operations[operation]
        if "{identifier}" not in contract.path_template:
            return contract.path_template
        return contract.path_template.replace("{identifier}", quote(identifier, safe=""))

    def as_public_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "family": self.family,
            "identifier_kind": self.identifier_kind,
            "operations": {
                name: {
                    "method": operation.method,
                    "fields": {
                        field_name: {
                            "kind": rule.kind,
                            "required": rule.required,
                            "choices": sorted(rule.choices),
                            "material": rule.material,
                        }
                        for field_name, rule in operation.fields.items()
                    },
                    "risk": operation.risk,
                    "response_kind": operation.response_kind,
                    "required_permission": operation.permission,
                    "destructive": bool(operation.confirmation),
                    "identifier_required": "{identifier}" in operation.path_template,
                }
                for name, operation in self.operations.items()
            },
        }


def _crud(
    *,
    collection: str,
    item: str,
    view_permission: str,
    manage_permission: str,
    delete_permission: str,
    fields: dict[str, FieldRule],
    response_kind: str = "metadata",
    write_path: str = "",
    list_method: str = "LIST",
) -> dict[str, AccessOperationSpec]:
    return {
        "list": AccessOperationSpec(list_method, collection, view_permission, "read"),
        "read": AccessOperationSpec("GET", item, view_permission, "read", response_kind=response_kind),
        "write": AccessOperationSpec(
            "POST", write_path or item, manage_permission, "write", fields=fields, response_kind=response_kind
        ),
        "delete": AccessOperationSpec(
            "DELETE",
            item,
            delete_permission,
            "destructive",
            confirmation="DELETE {resource} {identifier} ON {cluster}",
        ),
    }


POLICY_FIELDS: Final = {"policy": POLICY_TEXT}
ENTITY_FIELDS: Final = {
    "id": UUID_TEXT,
    "name": _text(maximum=MAX_ACCESS_NAME),
    "metadata": STRING_MAP,
    "policies": STRING_LIST,
    "disabled": BOOL,
}
ENTITY_ALIAS_FIELDS: Final = {
    "id": UUID_TEXT,
    "name": _text(required=True, maximum=MAX_ACCESS_NAME),
    "canonical_id": UUID_TEXT,
    "mount_accessor": _text(required=True, maximum=256),
}
GROUP_FIELDS: Final = {
    "id": UUID_TEXT,
    "name": _text(maximum=MAX_ACCESS_NAME),
    "type": _choice("internal", "external"),
    "metadata": STRING_MAP,
    "policies": STRING_LIST,
    "member_entity_ids": UUID_LIST,
    "member_group_ids": UUID_LIST,
}
GROUP_ALIAS_FIELDS: Final = {
    "id": UUID_TEXT,
    "name": _text(required=True, maximum=MAX_ACCESS_NAME),
    "canonical_id": UUID_TEXT,
    "mount_accessor": _text(required=True, maximum=256),
}
OIDC_CLIENT_FIELDS: Final = {
    "key": _text(maximum=MAX_ACCESS_NAME),
    "redirect_uris": URL_LIST,
    "assignments": STRING_LIST,
    "client_type": _choice("confidential", "public"),
    "id_token_ttl": POSITIVE_INTEGER,
    "access_token_ttl": POSITIVE_INTEGER,
    "authorization_code": BOOL,
    "client_credentials": BOOL,
}
OIDC_KEY_FIELDS: Final = {
    "algorithm": _choice("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"),
    "allowed_client_ids": STRING_LIST,
    "rotation_period": POSITIVE_INTEGER,
    "verification_ttl": POSITIVE_INTEGER,
}
OIDC_ASSIGNMENT_FIELDS: Final = {"entity_ids": UUID_LIST, "group_ids": UUID_LIST}
OIDC_PROVIDER_FIELDS: Final = {
    "issuer": _text(maximum=4_096),
    "allowed_client_ids": STRING_LIST,
    "scopes_supported": STRING_LIST,
}
OIDC_SCOPE_FIELDS: Final = {
    "description": _text(maximum=2_000),
    "template": TEMPLATE_TEXT,
}
NAMESPACE_FIELDS: Final = {
    "custom_metadata": FieldRule("string-map", required=True, maximum=128),
}


ACCESS_RESOURCES: Final = {
    "acl-policies": AccessResourceSpec(
        "acl-policies",
        "ACL policies",
        "policies",
        "name",
        _crud(
            collection="/sys/policies/acl",
            item="/sys/policies/acl/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_policies_openbaocluster",
            delete_permission="delete_policies_openbaocluster",
            fields=POLICY_FIELDS,
        ),
    ),
    "password-policies": AccessResourceSpec(
        "password-policies",
        "Password policies",
        "policies",
        "name",
        {
            **_crud(
                collection="/sys/policies/password",
                item="/sys/policies/password/{identifier}",
                view_permission="view_access_openbaocluster",
                manage_permission="manage_policies_openbaocluster",
                delete_permission="delete_policies_openbaocluster",
                fields=POLICY_FIELDS,
            ),
            "generate": AccessOperationSpec(
                "GET",
                "/sys/policies/password/{identifier}/generate",
                "generate_passwords_openbaocluster",
                "material",
                response_kind="material",
            ),
        },
    ),
    "entities": AccessResourceSpec(
        "entities",
        "Identity entities",
        "identity",
        "uuid",
        {
            **_crud(
                collection="/identity/entity/id",
                item="/identity/entity/id/{identifier}",
                view_permission="view_access_openbaocluster",
                manage_permission="manage_identity_openbaocluster",
                delete_permission="delete_identity_openbaocluster",
                fields=ENTITY_FIELDS,
                write_path="/identity/entity",
            ),
            "merge": AccessOperationSpec(
                "POST",
                "/identity/entity/merge",
                "merge_identity_openbaocluster",
                "destructive",
                fields={
                    "from_entity_ids": FieldRule("uuid-list", required=True, maximum=32),
                    "to_entity_id": FieldRule("uuid", required=True, maximum=36),
                    "force": BOOL,
                    "conflicting_alias_ids_to_keep": FieldRule("uuid-list", maximum=32),
                },
                confirmation="MERGE identities ON {cluster}",
            ),
        },
    ),
    "entity-aliases": AccessResourceSpec(
        "entity-aliases",
        "Entity aliases",
        "identity",
        "uuid",
        _crud(
            collection="/identity/entity-alias/id",
            item="/identity/entity-alias/id/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_identity_openbaocluster",
            delete_permission="delete_identity_openbaocluster",
            fields=ENTITY_ALIAS_FIELDS,
            write_path="/identity/entity-alias",
        ),
    ),
    "groups": AccessResourceSpec(
        "groups",
        "Identity groups",
        "identity",
        "uuid",
        _crud(
            collection="/identity/group/id",
            item="/identity/group/id/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_identity_openbaocluster",
            delete_permission="delete_identity_openbaocluster",
            fields=GROUP_FIELDS,
            write_path="/identity/group",
        ),
    ),
    "group-aliases": AccessResourceSpec(
        "group-aliases",
        "Group aliases",
        "identity",
        "uuid",
        _crud(
            collection="/identity/group-alias/id",
            item="/identity/group-alias/id/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_identity_openbaocluster",
            delete_permission="delete_identity_openbaocluster",
            fields=GROUP_ALIAS_FIELDS,
            write_path="/identity/group-alias",
        ),
    ),
    "oidc-clients": AccessResourceSpec(
        "oidc-clients",
        "OIDC clients",
        "oidc",
        "name",
        {
            **_crud(
                collection="/identity/oidc/client",
                item="/identity/oidc/client/{identifier}",
                view_permission="view_access_openbaocluster",
                manage_permission="manage_oidc_openbaocluster",
                delete_permission="delete_oidc_openbaocluster",
                fields=OIDC_CLIENT_FIELDS,
                response_kind="material",
            ),
            "read": AccessOperationSpec(
                "GET",
                "/identity/oidc/client/{identifier}",
                "reveal_oidc_client_secrets_openbaocluster",
                "read",
                response_kind="material",
            ),
        },
    ),
    "oidc-keys": AccessResourceSpec(
        "oidc-keys",
        "OIDC keys",
        "oidc",
        "name",
        {
            **_crud(
                collection="/identity/oidc/key",
                item="/identity/oidc/key/{identifier}",
                view_permission="view_access_openbaocluster",
                manage_permission="manage_oidc_openbaocluster",
                delete_permission="delete_oidc_openbaocluster",
                fields=OIDC_KEY_FIELDS,
            ),
            "rotate": AccessOperationSpec(
                "POST",
                "/identity/oidc/key/{identifier}/rotate",
                "rotate_oidc_keys_openbaocluster",
                "destructive",
                confirmation="ROTATE oidc-keys {identifier} ON {cluster}",
            ),
        },
    ),
    "oidc-assignments": AccessResourceSpec(
        "oidc-assignments",
        "OIDC assignments",
        "oidc",
        "name",
        _crud(
            collection="/identity/oidc/assignment",
            item="/identity/oidc/assignment/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_oidc_openbaocluster",
            delete_permission="delete_oidc_openbaocluster",
            fields=OIDC_ASSIGNMENT_FIELDS,
        ),
    ),
    "oidc-providers": AccessResourceSpec(
        "oidc-providers",
        "OIDC providers",
        "oidc",
        "name",
        _crud(
            collection="/identity/oidc/provider",
            item="/identity/oidc/provider/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_oidc_openbaocluster",
            delete_permission="delete_oidc_openbaocluster",
            fields=OIDC_PROVIDER_FIELDS,
        ),
    ),
    "oidc-scopes": AccessResourceSpec(
        "oidc-scopes",
        "OIDC scopes",
        "oidc",
        "name",
        _crud(
            collection="/identity/oidc/scope",
            item="/identity/oidc/scope/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_oidc_openbaocluster",
            delete_permission="delete_oidc_openbaocluster",
            fields=OIDC_SCOPE_FIELDS,
        ),
    ),
    "namespaces": AccessResourceSpec(
        "namespaces",
        "Namespaces",
        "namespaces",
        "namespace",
        _crud(
            collection="/sys/namespaces",
            item="/sys/namespaces/{identifier}",
            view_permission="view_access_openbaocluster",
            manage_permission="manage_namespaces_openbaocluster",
            delete_permission="delete_namespaces_openbaocluster",
            fields=NAMESPACE_FIELDS,
        ),
    ),
}


def resource_spec(key: str) -> AccessResourceSpec:
    try:
        return ACCESS_RESOURCES[key]
    except (KeyError, TypeError):
        raise CapabilitySchemaError("The access-control resource is unsupported.") from None


def normalize_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise CapabilitySchemaError("The resource identifier is invalid.")
    if kind == "uuid" and _UUID_RE.fullmatch(value):
        return value
    if kind == "name" and _NAME_RE.fullmatch(value):
        return value
    if kind == "accessor" and _ACCESSOR_RE.fullmatch(value):
        return value
    if kind == "namespace":
        if _NAMESPACE_SEGMENT_RE.fullmatch(value):
            return value
    raise CapabilitySchemaError("The resource identifier is invalid.")


def operation_shape(path: str) -> str:
    """Ignore upstream placeholder names while retaining every literal segment."""
    return _PLACEHOLDER_RE.sub("{}", path)


def runtime_advertises(document, operation: AccessOperationSpec) -> bool:
    expected_shape = operation_shape(operation.path_template.replace("{identifier}", "{name}"))

    def method_matches(candidate) -> bool:
        if candidate.method == operation.method.upper():
            return True
        return (
            operation.method == "LIST"
            and candidate.method == "GET"
            and (
                candidate.required_query_parameters == ("list",)
                or candidate.path_template == "/sys/namespaces"
            )
        )

    return any(
        method_matches(candidate) and operation_shape(candidate.path_template) == expected_shape
        for candidate in document.operations
    )


def operation_contract(resource_key: str, operation_name: str) -> tuple[AccessResourceSpec, AccessOperationSpec]:
    resource = resource_spec(resource_key)
    try:
        operation = resource.operations[operation_name]
    except (KeyError, TypeError):
        raise CapabilitySchemaError("The access-control operation is unsupported.") from None
    return resource, operation


def _normalize_url_list(value, rule: FieldRule) -> list[str]:
    if not isinstance(value, list) or len(value) > rule.maximum:
        raise CapabilitySchemaError("The access-control payload contains an invalid list.")
    normalized = []
    for item in value:
        if (
            not isinstance(item, str)
            or len(item) > 4_096
            or not item.startswith(("https://", "http://"))
            or any(ord(character) < 32 for character in item)
        ):
            raise CapabilitySchemaError("The access-control payload contains an invalid URL.")
        normalized.append(item)
    return normalized


def _normalize_extended_field(value, rule: FieldRule):
    if rule.kind == "uuid":
        return normalize_identifier(value, "uuid")
    if rule.kind == "url-list":
        return _normalize_url_list(value, rule)
    if not isinstance(value, list) or len(value) > rule.maximum:
        raise CapabilitySchemaError("The access-control payload contains an invalid list.")
    return [normalize_identifier(item, "uuid") for item in value]


def validate_access_payload(payload, fields: dict[str, FieldRule]) -> dict:
    """Validate access-control fields, including UUID and URL list extensions."""
    if not isinstance(payload, dict) or len(payload) > len(fields):
        raise CapabilitySchemaError("The access-control payload is invalid.")
    unknown = set(payload) - set(fields)
    missing = {name for name, rule in fields.items() if rule.required and name not in payload}
    if unknown or missing:
        raise CapabilitySchemaError("The access-control payload contains unsupported fields.")
    ordinary = {name: rule for name, rule in fields.items() if rule.kind not in {"uuid", "uuid-list", "url-list"}}
    result = validate_reviewed_payload({name: payload[name] for name in payload if name in ordinary}, ordinary)
    extended_kinds = {"uuid", "uuid-list", "url-list"}
    for name, rule in fields.items():
        if name in payload and rule.kind in extended_kinds:
            result[name] = _normalize_extended_field(payload[name], rule)
    return result


def _invalid_access_response():
    raise CapabilitySchemaError("OpenBao returned an invalid access-control response.")


def _normalize_response_dict(value: dict, *, material: bool, depth: int) -> dict:
    if len(value) > 1_000:
        _invalid_access_response()
    result = {}
    for key, child in value.items():
        if not isinstance(key, str) or len(key) > 500 or any(ord(character) < 32 for character in key):
            _invalid_access_response()
        if material or key.lower() not in ACCESS_MATERIAL_KEYS:
            result[key] = _normalize_response_value(child, material=material, depth=depth + 1)
    return result


def _normalize_response_value(value, *, material: bool, depth: int):
    if depth > 10:
        _invalid_access_response()
    if isinstance(value, dict):
        return _normalize_response_dict(value, material=material, depth=depth)
    if isinstance(value, list):
        if len(value) > 1_000:
            _invalid_access_response()
        return [_normalize_response_value(item, material=material, depth=depth + 1) for item in value]
    if isinstance(value, str):
        if len(value) > MAX_POLICY_DOCUMENT or "\x00" in value:
            _invalid_access_response()
        return value
    if isinstance(value, float) and not math.isfinite(value):
        _invalid_access_response()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    _invalid_access_response()


def normalize_access_response(payload, *, material: bool = False):
    """Bound a JSON response and remove undeclared material from metadata views."""
    if not isinstance(payload, dict):
        _invalid_access_response()
    return _normalize_response_dict(payload, material=material, depth=0)
