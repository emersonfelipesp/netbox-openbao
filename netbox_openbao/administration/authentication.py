"""Typed, bounded contracts for OpenBao authentication administration.

Runtime OpenAPI and help documents prove that a reviewed operation exists. They
never create executable paths or fields. Every request admitted here is mapped
through the static OpenBao 2.6.2 registry below.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Final
from urllib.parse import parse_qs, urlsplit

from .schema import CapabilitySchemaError

MAX_AUTH_MOUNTS: Final = 256
MAX_AUTH_RESPONSE_DEPTH: Final = 8
MAX_AUTH_RESPONSE_FIELDS: Final = 1_000
MAX_AUTH_STRING: Final = 20_000
MAX_AUTH_LIST: Final = 256
MAX_AUTH_NAME: Final = 200
MAX_AUTH_URL: Final = 4_096

AUTH_METHOD_TYPES: Final = frozenset(
    {"token", "userpass", "approle", "kubernetes", "jwt", "oidc", "ldap", "cert", "radius"}
)
MFA_METHOD_TYPES: Final = frozenset({"totp", "duo", "okta", "pingid"})
AUTH_RESOURCE_OPERATIONS: Final = frozenset({"list", "read", "write", "delete", "issue", "lookup", "destroy"})

_MOUNT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,199}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SAFE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,199}$")
_SAFE_RESPONSE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,499}$")
_ROLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,999}$")

MATERIAL_KEYS: Final = frozenset(
    {
        "access_token",
        "api_token",
        "barcode",
        "bindpass",
        "client_token",
        "client_tls_key",
        "code",
        "id_token",
        "jwt",
        "oidc_client_secret",
        "password",
        "password_hash",
        "private_key",
        "refresh_token",
        "secret",
        "secret_id",
        "secret_key",
        "settings_file_base64",
        "token",
        "token_reviewer_jwt",
    }
)
OAUTH2_MATERIAL_KEYS: Final = frozenset({"access_token", "id_token", "refresh_token"})


@dataclass(frozen=True, slots=True)
class FieldRule:
    """One reviewed request field and its bounded structural type."""

    kind: str
    required: bool = False
    maximum: int = MAX_AUTH_STRING
    choices: frozenset[str] = field(default_factory=frozenset)
    material: bool = False


def _text(*, required: bool = False, maximum: int = MAX_AUTH_STRING, material: bool = False) -> FieldRule:
    return FieldRule("text", required=required, maximum=maximum, material=material)


def _choice(*values: str, required: bool = False) -> FieldRule:
    return FieldRule("choice", required=required, maximum=100, choices=frozenset(values))


BOOL = FieldRule("boolean")
INTEGER = FieldRule("integer")
POSITIVE_INTEGER = FieldRule("positive-integer")
STRICT_POSITIVE_INTEGER = FieldRule("strict-positive-integer")
TOTP_DIGITS = FieldRule("totp-digits")
TOTP_SKEW = FieldRule("totp-skew")
STRING_LIST = FieldRule("string-list", maximum=1_000)
STRING_MAP = FieldRule("string-map", maximum=2_000)
JSON_MAP = FieldRule("json-map", maximum=5_000)
SECRET_TEXT = _text(material=True)
BASE64_SECRET = FieldRule("base64-text", required=True, material=True)

TOKEN_FIELDS: Final = {
    "token_bound_cidrs": STRING_LIST,
    "token_explicit_max_ttl": POSITIVE_INTEGER,
    "token_max_ttl": POSITIVE_INTEGER,
    "token_no_default_policy": BOOL,
    "token_num_uses": POSITIVE_INTEGER,
    "token_period": POSITIVE_INTEGER,
    "token_policies": STRING_LIST,
    "token_strictly_bind_ip": BOOL,
    "token_ttl": POSITIVE_INTEGER,
    "token_type": _choice("default-service", "service", "batch", "default-batch"),
}


@dataclass(frozen=True, slots=True)
class AuthResourceSpec:
    """A fixed mounted-auth resource contract."""

    key: str
    method_types: frozenset[str]
    collection_suffix: str
    item_suffix: str = ""
    operations: frozenset[str] = field(default_factory=frozenset)
    fields: dict[str, FieldRule] = field(default_factory=dict)
    response_kind: str = "metadata"
    risk: str = "write"

    def path(self, mount_path: str, *, name: str = "") -> str:
        suffix = self.item_suffix if name else self.collection_suffix
        return f"/auth/{mount_path}/{suffix.format(name=name)}".rstrip("/")


AUTH_CONFIG_FIELDS: Final = {
    "cert": {
        "disable_binding": BOOL,
        "enable_identity_alias_metadata": BOOL,
        "ocsp_cache_size": POSITIVE_INTEGER,
    },
    "jwt": {
        "bound_issuer": _text(maximum=1_000),
        "default_role": _text(maximum=MAX_AUTH_NAME),
        "jwks_ca_pem": _text(),
        "jwks_url": _text(maximum=MAX_AUTH_URL),
        "jwt_supported_algs": STRING_LIST,
        "jwt_validation_pubkeys": STRING_LIST,
        "namespace_in_state": BOOL,
        "oidc_client_id": _text(maximum=1_000),
        "oidc_client_secret": SECRET_TEXT,
        "oidc_discovery_ca_pem": _text(),
        "oidc_discovery_url": _text(maximum=MAX_AUTH_URL),
        "oidc_response_mode": _choice("", "query", "form_post"),
        "oidc_response_types": STRING_LIST,
        "override_allowed_server_names": STRING_LIST,
        "provider_config": JSON_MAP,
        "skip_jwks_validation": BOOL,
    },
    "oidc": {},
    "kubernetes": {
        "disable_iss_validation": BOOL,
        "disable_local_ca_jwt": BOOL,
        "issuer": _text(maximum=2_000),
        "kubernetes_ca_cert": _text(),
        "kubernetes_host": _text(maximum=MAX_AUTH_URL),
        "pem_keys": STRING_LIST,
        "token_reviewer_jwt": SECRET_TEXT,
    },
    "ldap": {
        "anonymous_group_search": BOOL,
        "binddn": _text(maximum=2_000),
        "bindpass": SECRET_TEXT,
        "case_sensitive_names": BOOL,
        "certificate": _text(),
        "client_tls_cert": _text(),
        "client_tls_key": SECRET_TEXT,
        "connection_timeout": POSITIVE_INTEGER,
        "deny_null_bind": BOOL,
        "dereference_aliases": _choice("never", "finding", "searching", "always"),
        "discoverdn": BOOL,
        "groupattr": _text(maximum=500),
        "groupdn": _text(maximum=2_000),
        "groupfilter": _text(maximum=4_000),
        "insecure_tls": BOOL,
        "max_page_size": POSITIVE_INTEGER,
        "request_timeout": POSITIVE_INTEGER,
        "starttls": BOOL,
        "tls_max_version": _choice("tls10", "tls11", "tls12", "tls13"),
        "tls_min_version": _choice("tls10", "tls11", "tls12", "tls13"),
        "upndomain": _text(maximum=1_000),
        "url": _text(maximum=MAX_AUTH_URL),
        "use_pre111_group_cn_behavior": BOOL,
        "use_token_groups": BOOL,
        "userattr": _text(maximum=500),
        "userdn": _text(maximum=2_000),
        "userfilter": _text(maximum=4_000),
        "username_as_alias": BOOL,
        **TOKEN_FIELDS,
    },
    "radius": {
        "host": _text(required=True, maximum=1_000),
        "port": POSITIVE_INTEGER,
        "secret": FieldRule("text", required=True, material=True),
        "unregistered_user_policies": _text(maximum=2_000),
        "dial_timeout": POSITIVE_INTEGER,
        "read_timeout": POSITIVE_INTEGER,
        "nas_port": POSITIVE_INTEGER,
        "nas_identifier": _text(maximum=1_000),
        **TOKEN_FIELDS,
    },
}
AUTH_CONFIG_FIELDS["oidc"] = AUTH_CONFIG_FIELDS["jwt"]

USERPASS_FIELDS: Final = {
    "password": SECRET_TEXT,
    "password_hash": SECRET_TEXT,
    "policies": STRING_LIST,
    "bound_cidrs": STRING_LIST,
    "max_ttl": POSITIVE_INTEGER,
    "ttl": POSITIVE_INTEGER,
    **TOKEN_FIELDS,
}
APPROLE_FIELDS: Final = {
    "bind_secret_id": BOOL,
    "bound_cidr_list": STRING_LIST,
    "local_secret_ids": BOOL,
    "period": POSITIVE_INTEGER,
    "policies": STRING_LIST,
    "secret_id_bound_cidrs": STRING_LIST,
    "secret_id_num_uses": POSITIVE_INTEGER,
    "secret_id_ttl": POSITIVE_INTEGER,
    **TOKEN_FIELDS,
}
KUBERNETES_ROLE_FIELDS: Final = {
    "alias_name_source": _choice("serviceaccount_uid", "serviceaccount_name"),
    "audience": _text(maximum=1_000),
    "bound_service_account_names": STRING_LIST,
    "bound_service_account_namespace_selector": _text(maximum=5_000),
    "bound_service_account_namespaces": STRING_LIST,
    "bound_cidrs": STRING_LIST,
    "max_ttl": POSITIVE_INTEGER,
    "num_uses": POSITIVE_INTEGER,
    "period": POSITIVE_INTEGER,
    "policies": STRING_LIST,
    "ttl": POSITIVE_INTEGER,
    **TOKEN_FIELDS,
}
JWT_ROLE_FIELDS: Final = {
    "allowed_redirect_uris": STRING_LIST,
    "bound_audiences": STRING_LIST,
    "bound_claims": JSON_MAP,
    "bound_claims_type": _choice("string", "glob"),
    "bound_subject": _text(maximum=2_000),
    "callback_mode": _choice("client", "direct", "device"),
    "claim_mappings": STRING_MAP,
    "clock_skew_leeway": INTEGER,
    "expiration_leeway": INTEGER,
    "groups_claim": _text(maximum=1_000),
    "max_age": POSITIVE_INTEGER,
    "not_before_leeway": INTEGER,
    "oauth2_metadata": STRING_LIST,
    "oidc_scopes": STRING_LIST,
    "poll_interval": POSITIVE_INTEGER,
    "role_type": _choice("jwt", "oidc", required=True),
    "token_policies_template_claims": BOOL,
    "user_claim": _text(required=True, maximum=1_000),
    "user_claim_json_pointer": BOOL,
    "bound_cidrs": STRING_LIST,
    "max_ttl": POSITIVE_INTEGER,
    "num_uses": POSITIVE_INTEGER,
    "period": POSITIVE_INTEGER,
    "policies": STRING_LIST,
    "ttl": POSITIVE_INTEGER,
    **TOKEN_FIELDS,
}
TOKEN_ROLE_FIELDS: Final = {
    "allowed_entity_aliases": STRING_LIST,
    "allowed_policies": STRING_LIST,
    "allowed_policies_glob": STRING_LIST,
    "bound_cidrs": STRING_LIST,
    "disallowed_policies": STRING_LIST,
    "disallowed_policies_glob": STRING_LIST,
    "explicit_max_ttl": POSITIVE_INTEGER,
    "orphan": BOOL,
    "path_suffix": _text(maximum=1_000),
    "period": POSITIVE_INTEGER,
    "renewable": BOOL,
    **TOKEN_FIELDS,
}
CERT_FIELDS: Final = {
    "allowed_common_names": STRING_LIST,
    "allowed_dns_sans": STRING_LIST,
    "allowed_email_sans": STRING_LIST,
    "allowed_metadata_extensions": STRING_LIST,
    "allowed_names": STRING_LIST,
    "allowed_organizational_units": STRING_LIST,
    "allowed_uri_sans": STRING_LIST,
    "bound_cidrs": STRING_LIST,
    "certificate": _text(),
    "display_name": _text(maximum=500),
    "lease": POSITIVE_INTEGER,
    "max_ttl": POSITIVE_INTEGER,
    "ocsp_ca_certificates": _text(),
    "ocsp_enabled": BOOL,
    "ocsp_fail_open": BOOL,
    "ocsp_query_all_servers": BOOL,
    "ocsp_servers_override": STRING_LIST,
    "period": POSITIVE_INTEGER,
    "policies": STRING_LIST,
    "required_extensions": STRING_LIST,
    "ttl": POSITIVE_INTEGER,
    **TOKEN_FIELDS,
}

AUTH_RESOURCE_REGISTRY: Final = {
    "token-roles": AuthResourceSpec(
        key="token-roles",
        method_types=frozenset({"token"}),
        collection_suffix="roles",
        item_suffix="roles/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=TOKEN_ROLE_FIELDS,
    ),
    "userpass-users": AuthResourceSpec(
        key="userpass-users",
        method_types=frozenset({"userpass"}),
        collection_suffix="users",
        item_suffix="users/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=USERPASS_FIELDS,
        risk="sensitive",
    ),
    "approle-roles": AuthResourceSpec(
        key="approle-roles",
        method_types=frozenset({"approle"}),
        collection_suffix="role",
        item_suffix="role/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=APPROLE_FIELDS,
    ),
    "kubernetes-roles": AuthResourceSpec(
        key="kubernetes-roles",
        method_types=frozenset({"kubernetes"}),
        collection_suffix="role",
        item_suffix="role/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=KUBERNETES_ROLE_FIELDS,
    ),
    "jwt-roles": AuthResourceSpec(
        key="jwt-roles",
        method_types=frozenset({"jwt", "oidc"}),
        collection_suffix="role",
        item_suffix="role/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=JWT_ROLE_FIELDS,
        risk="sensitive",
    ),
    "ldap-groups": AuthResourceSpec(
        key="ldap-groups",
        method_types=frozenset({"ldap"}),
        collection_suffix="groups",
        item_suffix="groups/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields={"policies": STRING_LIST},
    ),
    "ldap-users": AuthResourceSpec(
        key="ldap-users",
        method_types=frozenset({"ldap"}),
        collection_suffix="users",
        item_suffix="users/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields={"groups": STRING_LIST, "policies": STRING_LIST},
    ),
    "radius-users": AuthResourceSpec(
        key="radius-users",
        method_types=frozenset({"radius"}),
        collection_suffix="users",
        item_suffix="users/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields={"policies": STRING_LIST},
        risk="sensitive",
    ),
    "certificates": AuthResourceSpec(
        key="certificates",
        method_types=frozenset({"cert"}),
        collection_suffix="certs",
        item_suffix="certs/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields=CERT_FIELDS,
        risk="sensitive",
    ),
    "certificate-crls": AuthResourceSpec(
        key="certificate-crls",
        method_types=frozenset({"cert"}),
        collection_suffix="crls",
        item_suffix="crls/{name}",
        operations=frozenset({"list", "read", "write", "delete"}),
        fields={"crl": _text(), "url": _text(maximum=MAX_AUTH_URL)},
        risk="sensitive",
    ),
}

MFA_METHOD_FIELDS: Final = {
    "totp": {
        "algorithm": _choice("SHA1", "SHA256", "SHA512"),
        "digits": TOTP_DIGITS,
        "issuer": _text(required=True, maximum=1_000),
        "key_size": STRICT_POSITIVE_INTEGER,
        "max_validation_attempts": POSITIVE_INTEGER,
        "method_name": _text(maximum=MAX_AUTH_NAME),
        "period": STRICT_POSITIVE_INTEGER,
        "qr_size": POSITIVE_INTEGER,
        "skew": TOTP_SKEW,
    },
    "duo": {
        "api_hostname": _text(required=True, maximum=MAX_AUTH_URL),
        "integration_key": _text(required=True, maximum=1_000),
        "method_name": _text(maximum=MAX_AUTH_NAME),
        "push_info": _text(maximum=2_000),
        "secret_key": FieldRule("text", required=True, material=True),
        "use_passcode": BOOL,
        "username_format": _text(maximum=2_000),
    },
    "okta": {
        "api_token": FieldRule("text", required=True, material=True),
        "base_url": _text(maximum=MAX_AUTH_URL),
        "method_name": _text(maximum=MAX_AUTH_NAME),
        "org_name": _text(required=True, maximum=1_000),
        "primary_email": BOOL,
        "production": BOOL,
        "username_format": _text(maximum=2_000),
    },
    "pingid": {
        "method_name": _text(maximum=MAX_AUTH_NAME),
        "settings_file_base64": BASE64_SECRET,
        "username_format": _text(maximum=2_000),
    },
}

MFA_ENFORCEMENT_FIELDS: Final = {
    "auth_method_accessors": STRING_LIST,
    "auth_method_types": STRING_LIST,
    "identity_entity_ids": STRING_LIST,
    "identity_group_ids": STRING_LIST,
    "mfa_method_ids": FieldRule("string-list", required=True, maximum=1_000),
}


@dataclass(frozen=True, slots=True)
class AuthMount:
    path: str
    method_type: str
    accessor: str
    description: str
    local: bool
    seal_wrap: bool
    default_lease_ttl: int
    max_lease_ttl: int
    token_type: str
    plugin_version: str
    running_plugin_version: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class MFAMethodChoice:
    method_id: str
    method_type: str
    uses_passcode: bool


@dataclass(frozen=True, slots=True, repr=False)
class MFARequirement:
    """A short-lived login challenge. Never persist, log, cache, or enqueue."""

    request_id: str = field(repr=False)
    constraints: dict[str, tuple[MFAMethodChoice, ...]] = field(repr=False)

    def __repr__(self) -> str:
        return "<MFARequirement redacted>"

    def as_dict(self) -> dict[str, Any]:
        return {
            "mfa_request_id": self.request_id,
            "mfa_constraints": {
                name: {"any": [asdict(method) for method in methods]} for name, methods in self.constraints.items()
            },
        }


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationResult:
    """One-shot authentication material and bounded identity metadata."""

    client_token: str = field(default="", repr=False)
    accessor: str = ""
    policies: tuple[str, ...] = ()
    identity_policies: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    material_metadata: dict[str, str] = field(default_factory=dict, repr=False)
    lease_duration: int = 0
    renewable: bool = False
    entity_id: str = ""
    token_type: str = ""
    mfa_requirement: MFARequirement | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "<AuthenticationResult redacted>"

    def as_dict(self) -> dict[str, Any]:
        result = {
            "client_token": self.client_token,
            "accessor": self.accessor,
            "policies": list(self.policies),
            "identity_policies": list(self.identity_policies),
            "metadata": {**self.metadata, **self.material_metadata},
            "lease_duration": self.lease_duration,
            "renewable": self.renewable,
            "entity_id": self.entity_id,
            "token_type": self.token_type,
        }
        if self.mfa_requirement is not None:
            result["mfa_requirement"] = self.mfa_requirement.as_dict()
        return result


@dataclass(frozen=True, slots=True, repr=False)
class OIDCStartResult:
    auth_url: str = field(repr=False)
    state: str = field(repr=False)
    poll_interval: int

    def __repr__(self) -> str:
        return "<OIDCStartResult redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class SecretIDResult:
    secret_id: str = field(repr=False)
    accessor: str
    ttl: int
    num_uses: int

    def __repr__(self) -> str:
        return "<SecretIDResult redacted>"

    def as_dict(self) -> dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "secret_id_accessor": self.accessor,
            "secret_id_ttl": self.ttl,
            "secret_id_num_uses": self.num_uses,
        }


@dataclass(frozen=True, slots=True, repr=False)
class TOTPSetupResult:
    url: str = field(repr=False)
    barcode: str = field(repr=False)

    def __repr__(self) -> str:
        return "<TOTPSetupResult redacted>"

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "barcode": self.barcode}


def normalize_mount_path(value: Any) -> str:
    if not isinstance(value, str):
        raise CapabilitySchemaError("OpenBao auth mount path is invalid.")
    path = value.strip().removesuffix("/")
    if path.startswith("auth/") or not _MOUNT_PATH_RE.fullmatch(path):
        raise CapabilitySchemaError("OpenBao auth mount path is invalid.")
    return path


def normalize_resource_name(value: Any, *, uuid_only: bool = False) -> str:
    if not isinstance(value, str):
        raise CapabilitySchemaError("OpenBao auth resource name is invalid.")
    pattern = _UUID_RE if uuid_only else _RESOURCE_NAME_RE
    if not pattern.fullmatch(value):
        raise CapabilitySchemaError("OpenBao auth resource name is invalid.")
    return value


def normalize_role_id(value: Any) -> str:
    if not isinstance(value, str) or not _ROLE_ID_RE.fullmatch(value):
        raise CapabilitySchemaError("OpenBao AppRole RoleID is invalid.")
    return value


def _bounded_text(value: Any, *, maximum: int, blank: bool = True) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(ord(character) < 32 and character not in "\n\r\t" for character in value)
        or "\x00" in value
        or (not blank and not value)
    ):
        raise CapabilitySchemaError("OpenBao authentication value is invalid.")
    return value


def _validate_string_list(value: Any, rule: FieldRule) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return [_bounded_text(item, maximum=rule.maximum) for item in value]


def _validate_string_map(value: Any, rule: FieldRule) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("OpenBao authentication field is invalid.")
        result[key] = _bounded_text(item, maximum=rule.maximum)
    return result


def _validate_json_mapping(value: dict, depth: int) -> dict:
    if len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("OpenBao authentication field is invalid.")
        result[key] = _validate_json_value(item, depth=depth + 1)
    return result


def _validate_json_sequence(value: list, depth: int) -> list:
    if len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return [_validate_json_value(item, depth=depth + 1) for item in value]


def _validate_json_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return _bounded_text(value, maximum=5_000)
    if value is None or isinstance(value, bool) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise CapabilitySchemaError("OpenBao authentication field is invalid.")


def _validate_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        raise CapabilitySchemaError("OpenBao authentication field is nested too deeply.")
    if isinstance(value, dict):
        return _validate_json_mapping(value, depth)
    if isinstance(value, list):
        return _validate_json_sequence(value, depth)
    return _validate_json_scalar(value)


def _validate_text_field(value: Any, rule: FieldRule) -> str:
    result = _bounded_text(value, maximum=rule.maximum, blank=not rule.required)
    if rule.choices and result not in rule.choices:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return result


def _validate_boolean_field(value: Any, rule: FieldRule) -> bool:
    del rule
    if not isinstance(value, bool):
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return value


def _validate_base64_text_field(value: Any, rule: FieldRule) -> str:
    result = _validate_text_field(value, rule)
    try:
        base64.b64decode(result, validate=True)
    except (binascii.Error, ValueError):
        raise CapabilitySchemaError("OpenBao authentication field is invalid.") from None
    return result


def _validate_integer_field(value: Any, rule: FieldRule) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    minimum = 1 if rule.kind == "strict-positive-integer" else 0 if rule.kind == "positive-integer" else -(2**31)
    if value < minimum or value > 2**31 - 1:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    if rule.kind == "totp-digits" and value not in {6, 8}:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    if rule.kind == "totp-skew" and value not in {0, 1}:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return value


def _validate_json_map_field(value: Any, rule: FieldRule) -> dict:
    del rule
    if not isinstance(value, dict):
        raise CapabilitySchemaError("OpenBao authentication field is invalid.")
    return _validate_json_value(value)


_FIELD_VALIDATORS = {
    "text": _validate_text_field,
    "choice": _validate_text_field,
    "boolean": _validate_boolean_field,
    "base64-text": _validate_base64_text_field,
    "integer": _validate_integer_field,
    "positive-integer": _validate_integer_field,
    "strict-positive-integer": _validate_integer_field,
    "totp-digits": _validate_integer_field,
    "totp-skew": _validate_integer_field,
    "string-list": _validate_string_list,
    "string-map": _validate_string_map,
    "json-map": _validate_json_map_field,
}


def _validate_field(value: Any, rule: FieldRule) -> Any:
    try:
        validator = _FIELD_VALIDATORS[rule.kind]
    except KeyError:
        raise CapabilitySchemaError("OpenBao authentication field is invalid.") from None
    return validator(value, rule)


def validate_reviewed_payload(payload: Any, fields: dict[str, FieldRule]) -> dict[str, Any]:
    """Validate only named reviewed fields and return an independent payload."""
    if not isinstance(payload, dict) or len(payload) > len(fields):
        raise CapabilitySchemaError("OpenBao authentication payload is invalid.")
    unknown = set(payload) - set(fields)
    missing = {name for name, rule in fields.items() if rule.required and name not in payload}
    if unknown or missing:
        raise CapabilitySchemaError("OpenBao authentication payload contains unsupported fields.")
    result = {}
    for name, value in payload.items():
        result[name] = _validate_field(value, fields[name])
    return result


def validate_auth_resource_payload(
    resource_key: str,
    method_type: str,
    operation: str,
    payload: Any,
) -> dict[str, Any]:
    """Validate a mounted resource and enforce NetBox-safe OIDC roles."""
    spec = resource_spec(resource_key, method_type, operation)
    result = validate_reviewed_payload(payload, spec.fields)
    if resource_key != "jwt-roles" or operation != "write":
        return result
    callback_mode = result.get("callback_mode")
    if callback_mode in {"client", "device"}:
        raise CapabilitySchemaError("NetBox supports only direct OIDC callback mode.")
    if result.get("role_type") == "oidc" and callback_mode != "direct":
        raise CapabilitySchemaError("OIDC roles managed through NetBox must use direct callback mode.")
    result["oidc_disable_confirmation"] = False
    result["verbose_oidc_logging"] = False
    return result


def validate_direct_oidc_role(payload: Any) -> dict[str, Any]:
    """Require an existing OIDC role to use the direct callback contract."""
    data = _response_data(payload)
    if data.get("role_type") != "oidc" or data.get("callback_mode") != "direct":
        raise CapabilitySchemaError("The selected role is not configured for direct OIDC callback mode.")
    if data.get("oidc_disable_confirmation") is True or data.get("verbose_oidc_logging") is True:
        raise CapabilitySchemaError("The selected OIDC role enables a setting forbidden by NetBox.")
    return normalize_public_auth_data(payload)


def resource_spec(key: Any, method_type: str, operation: str) -> AuthResourceSpec:
    if not isinstance(key, str) or key not in AUTH_RESOURCE_REGISTRY:
        raise CapabilitySchemaError("OpenBao auth resource is unsupported.")
    spec = AUTH_RESOURCE_REGISTRY[key]
    if method_type not in spec.method_types or operation not in spec.operations:
        raise CapabilitySchemaError("OpenBao auth resource operation is unsupported.")
    return spec


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise CapabilitySchemaError(f"OpenBao returned invalid {field_name}.")
    return value


def _integer(value: Any, field_name: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CapabilitySchemaError(f"OpenBao returned invalid {field_name}.")
    return value


def _response_data(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CapabilitySchemaError("OpenBao returned an invalid authentication response.")
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise CapabilitySchemaError("OpenBao returned an invalid authentication response.")
    return data


def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError(f"OpenBao returned invalid {field_name}.")
    return tuple(_bounded_text(item, maximum=1_000) for item in value)


def normalize_auth_mounts(payload: Any) -> tuple[AuthMount, ...]:
    data = _response_data(payload)
    if len(data) > MAX_AUTH_MOUNTS:
        raise CapabilitySchemaError("OpenBao returned too many auth mounts.")
    mounts = []
    for raw_path, raw_mount in data.items():
        path = normalize_mount_path(raw_path)
        if not isinstance(raw_mount, dict):
            raise CapabilitySchemaError("OpenBao returned an invalid auth mount.")
        method_type = _bounded_text(raw_mount.get("type"), maximum=100, blank=False).removeprefix("ns_")
        if method_type not in AUTH_METHOD_TYPES:
            continue
        config = raw_mount.get("config") or {}
        if not isinstance(config, dict):
            raise CapabilitySchemaError("OpenBao returned an invalid auth mount.")
        mounts.append(
            AuthMount(
                path=path,
                method_type=method_type,
                accessor=_bounded_text(raw_mount.get("accessor", ""), maximum=200),
                description=_bounded_text(raw_mount.get("description", ""), maximum=1_000),
                local=_boolean(raw_mount.get("local", False), "auth mount local state"),
                seal_wrap=_boolean(raw_mount.get("seal_wrap", False), "auth mount seal-wrap state"),
                default_lease_ttl=_integer(config.get("default_lease_ttl", 0), "auth mount default TTL"),
                max_lease_ttl=_integer(config.get("max_lease_ttl", 0), "auth mount maximum TTL"),
                token_type=_bounded_text(config.get("token_type", ""), maximum=100),
                plugin_version=_bounded_text(raw_mount.get("plugin_version", ""), maximum=100),
                running_plugin_version=_bounded_text(raw_mount.get("running_plugin_version", ""), maximum=100),
            )
        )
    mounts.sort(key=lambda item: item.path)
    return tuple(mounts)


def auth_mount(mounts: tuple[AuthMount, ...], path: str) -> AuthMount:
    normalized = normalize_mount_path(path)
    try:
        return next(mount for mount in mounts if mount.path == normalized)
    except StopIteration:
        raise CapabilitySchemaError("OpenBao auth mount does not exist.") from None


def _normalize_metadata(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao returned invalid authentication metadata.")
    result = {}
    for key, item in value.items():
        if key in MATERIAL_KEYS:
            continue
        if not isinstance(key, str) or not _SAFE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("OpenBao returned invalid authentication metadata.")
        result[key] = _bounded_text(item, maximum=2_000)
    return result


def _normalize_material_metadata(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao returned invalid authentication metadata.")
    return {key: _bounded_text(value[key], maximum=MAX_AUTH_STRING) for key in OAUTH2_MATERIAL_KEYS if key in value}


def _normalize_mfa_requirement(value: Any) -> MFARequirement:
    if not isinstance(value, dict):
        raise CapabilitySchemaError("OpenBao returned an invalid MFA requirement.")
    request_id = _bounded_text(value.get("mfa_request_id"), maximum=1_000, blank=False)
    raw_constraints = value.get("mfa_constraints")
    if not isinstance(raw_constraints, dict) or not raw_constraints or len(raw_constraints) > 32:
        raise CapabilitySchemaError("OpenBao returned invalid MFA constraints.")
    constraints = {}
    for name, raw_constraint in raw_constraints.items():
        constraint_name = _bounded_text(name, maximum=MAX_AUTH_NAME, blank=False)
        if not isinstance(raw_constraint, dict):
            raise CapabilitySchemaError("OpenBao returned invalid MFA constraints.")
        raw_methods = raw_constraint.get("any")
        if not isinstance(raw_methods, list) or not raw_methods or len(raw_methods) > 16:
            raise CapabilitySchemaError("OpenBao returned invalid MFA constraints.")
        methods = []
        for raw_method in raw_methods:
            if not isinstance(raw_method, dict):
                raise CapabilitySchemaError("OpenBao returned invalid MFA constraints.")
            method_type = _bounded_text(raw_method.get("type"), maximum=32, blank=False)
            if method_type not in MFA_METHOD_TYPES:
                raise CapabilitySchemaError("OpenBao returned an unsupported MFA method.")
            methods.append(
                MFAMethodChoice(
                    method_id=normalize_resource_name(raw_method.get("id"), uuid_only=True),
                    method_type=method_type,
                    uses_passcode=_boolean(raw_method.get("uses_passcode"), "MFA passcode state"),
                )
            )
        constraints[constraint_name] = tuple(methods)
    return MFARequirement(request_id=request_id, constraints=constraints)


def normalize_authentication_result(payload: Any) -> AuthenticationResult:
    if not isinstance(payload, dict) or not isinstance(payload.get("auth"), dict):
        raise CapabilitySchemaError("OpenBao returned an invalid authentication response.")
    auth = payload["auth"]
    raw_requirement = auth.get("mfa_requirement")
    requirement = _normalize_mfa_requirement(raw_requirement) if raw_requirement is not None else None
    client_token = _bounded_text(auth.get("client_token", ""), maximum=MAX_AUTH_STRING)
    if not client_token and requirement is None:
        raise CapabilitySchemaError("OpenBao authentication returned neither a token nor an MFA challenge.")
    return AuthenticationResult(
        client_token=client_token,
        accessor=_bounded_text(auth.get("accessor", ""), maximum=1_000),
        policies=_string_tuple(auth.get("policies"), "token policies"),
        identity_policies=_string_tuple(auth.get("identity_policies"), "identity policies"),
        metadata=_normalize_metadata(auth.get("metadata")),
        material_metadata=_normalize_material_metadata(auth.get("metadata")),
        lease_duration=_integer(auth.get("lease_duration", 0), "token lease duration"),
        renewable=_boolean(auth.get("renewable", False), "token renewable state"),
        entity_id=_bounded_text(auth.get("entity_id", ""), maximum=1_000),
        token_type=_bounded_text(auth.get("token_type", ""), maximum=100),
        mfa_requirement=requirement,
    )


def _safe_response_mapping(value: dict, depth: int) -> dict:
    if len(value) > MAX_AUTH_RESPONSE_FIELDS:
        raise CapabilitySchemaError("OpenBao authentication response has too many fields.")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _SAFE_RESPONSE_KEY_RE.fullmatch(key):
            raise CapabilitySchemaError("OpenBao authentication response has an invalid field.")
        if key.lower() not in MATERIAL_KEYS:
            result[key] = _safe_response_value(item, depth=depth + 1)
    return result


def _safe_response_sequence(value: list, depth: int) -> list:
    if len(value) > MAX_AUTH_LIST:
        raise CapabilitySchemaError("OpenBao authentication response has too many items.")
    return [_safe_response_value(item, depth=depth + 1) for item in value]


def _safe_response_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return _bounded_text(value, maximum=MAX_AUTH_STRING)
    if value is None or isinstance(value, bool) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise CapabilitySchemaError("OpenBao authentication response contains an unsupported value.")


def _safe_response_value(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_AUTH_RESPONSE_DEPTH:
        raise CapabilitySchemaError("OpenBao authentication response is nested too deeply.")
    if isinstance(value, dict):
        return _safe_response_mapping(value, depth)
    if isinstance(value, list):
        return _safe_response_sequence(value, depth)
    return _safe_response_scalar(value)


def normalize_public_auth_data(payload: Any) -> dict[str, Any]:
    """Return bounded public metadata and drop all material-shaped fields."""
    return _safe_response_value(_response_data(payload))


def normalize_oidc_start(payload: Any) -> OIDCStartResult:
    data = _response_data(payload)
    auth_url = _bounded_text(data.get("auth_url"), maximum=MAX_AUTH_URL, blank=False)
    state = _bounded_text(data.get("state"), maximum=1_000, blank=False)
    raw_interval = data.get("poll_interval", 5)
    try:
        poll_interval = int(raw_interval)
    except (TypeError, ValueError):
        raise CapabilitySchemaError("OpenBao returned an invalid OIDC poll interval.") from None
    if not 1 <= poll_interval <= 60:
        raise CapabilitySchemaError("OpenBao returned an invalid OIDC poll interval.")
    validate_authorization_url(auth_url, state)
    return OIDCStartResult(auth_url=auth_url, state=state, poll_interval=poll_interval)


def validate_authorization_url(value: str, expected_state: str) -> None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise CapabilitySchemaError("OpenBao returned an invalid OIDC authorization URL.") from None
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        raise CapabilitySchemaError("OpenBao returned an invalid OIDC authorization URL.")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise CapabilitySchemaError("OpenBao returned an insecure OIDC authorization URL.")
    elif parsed.scheme != "https":
        raise CapabilitySchemaError("OpenBao returned an insecure OIDC authorization URL.")
    states = parse_qs(parsed.query, strict_parsing=False).get("state", [])
    if len(states) != 1 or states[0].split(",ns=", 1)[0] != expected_state:
        raise CapabilitySchemaError("OpenBao returned a mismatched OIDC state.")


def normalize_secret_id_result(payload: Any) -> SecretIDResult:
    data = _response_data(payload)
    return SecretIDResult(
        secret_id=_bounded_text(data.get("secret_id"), maximum=MAX_AUTH_STRING, blank=False),
        accessor=_bounded_text(data.get("secret_id_accessor"), maximum=1_000, blank=False),
        ttl=_integer(data.get("secret_id_ttl", 0), "SecretID TTL"),
        num_uses=_integer(data.get("secret_id_num_uses", 0), "SecretID use count"),
    )


def normalize_totp_setup_result(payload: Any) -> TOTPSetupResult:
    data = _response_data(payload)
    barcode = _bounded_text(data.get("barcode"), maximum=2_000_000, blank=False)
    try:
        decoded = base64.b64decode(barcode, validate=True)
    except (binascii.Error, ValueError):
        raise CapabilitySchemaError("OpenBao returned an invalid TOTP barcode.") from None
    if not decoded.startswith(b"\x89PNG\r\n\x1a\n"):
        raise CapabilitySchemaError("OpenBao returned an invalid TOTP barcode.")
    return TOTPSetupResult(
        url=_bounded_text(data.get("url"), maximum=MAX_AUTH_STRING, blank=False),
        barcode=barcode,
    )
