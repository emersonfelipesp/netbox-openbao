"""Fail-closed request contracts for authentication and MFA administration."""

from __future__ import annotations

import json
import re

from rest_framework import serializers

from netbox_openbao.administration.authentication import (
    AUTH_CONFIG_FIELDS,
    AUTH_METHOD_TYPES,
    MFA_ENFORCEMENT_FIELDS,
    MFA_METHOD_FIELDS,
    FieldRule,
    normalize_mount_path,
    normalize_resource_name,
    validate_auth_resource_payload,
    validate_reviewed_payload,
)
from netbox_openbao.administration.schema import CapabilitySchemaError

NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,200}$")
SAFE_OPTION_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,199}$")


def _validate_small_string_map(value):
    if len(value) > 64 or any(not SAFE_OPTION_KEY_RE.fullmatch(key) for key in value):
        raise serializers.ValidationError("The configuration map is invalid.")
    return value


class MountTuningFields(serializers.Serializer):
    description = serializers.CharField(max_length=1_000, allow_blank=True, required=False)
    default_lease_ttl = serializers.IntegerField(min_value=0, max_value=2**31 - 1, required=False)
    max_lease_ttl = serializers.IntegerField(min_value=0, max_value=2**31 - 1, required=False)
    token_type = serializers.ChoiceField(
        choices=("default-service", "service", "batch", "default-batch"), required=False
    )
    listing_visibility = serializers.ChoiceField(choices=("", "hidden", "unauth"), required=False)
    passthrough_request_headers = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=64, required=False
    )
    allowed_response_headers = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=64, required=False
    )
    audit_non_hmac_request_keys = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=64, required=False
    )
    audit_non_hmac_response_keys = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=64, required=False
    )
    options = serializers.DictField(child=serializers.CharField(max_length=2_000), required=False)
    user_lockout_config = serializers.DictField(child=serializers.CharField(max_length=2_000), required=False)
    plugin_version = serializers.RegexField(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,99}$", required=False)

    def validate_options(self, value):
        return _validate_small_string_map(value)

    def validate_user_lockout_config(self, value):
        return _validate_small_string_map(value)


def _safe_contract(callable_, *args):
    try:
        return callable_(*args)
    except (CapabilitySchemaError, KeyError, TypeError, ValueError):
        raise serializers.ValidationError("The request does not match a reviewed OpenBao 2.6.2 contract.") from None


class StrictSerializer(serializers.Serializer):
    """Reject request keys that are outside the reviewed contract."""

    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["The request contains unsupported fields."]})
        return super().to_internal_value(data)


class ReasonSerializer(StrictSerializer):
    reason = serializers.CharField(min_length=3, max_length=1_000, trim_whitespace=True)


class ConfirmAuthenticationActionSerializer(ReasonSerializer):
    confirmation = serializers.CharField(max_length=400, trim_whitespace=True)

    def validate_confirmation(self, value):
        expected = self.context["expected_confirmation"]
        if value != expected:
            raise serializers.ValidationError(f"Type exactly: {expected}")
        return value


class EnableAuthMethodSerializer(ReasonSerializer, MountTuningFields):
    mount_path = serializers.CharField(max_length=128)
    method_type = serializers.ChoiceField(choices=sorted(AUTH_METHOD_TYPES - {"token"}))
    description = serializers.CharField(max_length=1_000, allow_blank=True, required=False)
    local = serializers.BooleanField(required=False)
    seal_wrap = serializers.BooleanField(required=False)
    external_entropy_access = serializers.BooleanField(required=False)
    plugin_name = serializers.RegexField(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$", required=False)

    def validate_mount_path(self, value):
        return _safe_contract(normalize_mount_path, value)

    def openbao_payload(self):
        data = dict(self.validated_data)
        data.pop("reason", None)
        data.pop("mount_path")
        method_type = data.pop("method_type")
        config_keys = {
            "allowed_response_headers",
            "audit_non_hmac_request_keys",
            "audit_non_hmac_response_keys",
            "default_lease_ttl",
            "listing_visibility",
            "max_lease_ttl",
            "passthrough_request_headers",
            "token_type",
            "user_lockout_config",
        }
        config = {key: data.pop(key) for key in tuple(data) if key in config_keys}
        return {"type": method_type, **data, **({"config": config} if config else {})}


class TuneAuthMethodSerializer(ReasonSerializer, MountTuningFields):
    def openbao_payload(self):
        return {key: value for key, value in self.validated_data.items() if key != "reason"}


class RemountAuthMethodSerializer(ReasonSerializer):
    source = serializers.CharField(max_length=128)
    destination = serializers.CharField(max_length=128)

    def validate_source(self, value):
        return _safe_contract(normalize_mount_path, value)

    def validate_destination(self, value):
        return _safe_contract(normalize_mount_path, value)

    def validate(self, attrs):
        if attrs.get("source") == attrs.get("destination"):
            raise serializers.ValidationError("The destination must differ from the source.")
        return attrs


class ReviewedPayloadSerializer(ReasonSerializer):
    payload = serializers.JSONField(write_only=True)

    def validate_payload(self, value):
        fields = self.context["fields"]
        return _safe_contract(validate_reviewed_payload, value, fields)


class AuthResourceRequestSerializer(ReviewedPayloadSerializer):
    def validate_payload(self, value):
        return _safe_contract(
            validate_auth_resource_payload,
            self.context["resource_key"],
            self.context["method_type"],
            "write",
            value,
        )


class AppRoleSecretIDSerializer(ReasonSerializer):
    metadata = serializers.DictField(child=serializers.CharField(max_length=2_000), required=False)
    cidr_list = serializers.ListField(child=serializers.CharField(max_length=200), max_length=256, required=False)
    token_bound_cidrs = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=256, required=False
    )
    num_uses = serializers.IntegerField(min_value=0, max_value=2**31 - 1, required=False)
    ttl = serializers.IntegerField(min_value=0, max_value=2**31 - 1, required=False)

    def validate_metadata(self, value):
        if len(value) > 64 or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,199}", key) for key in value):
            raise serializers.ValidationError("The SecretID metadata is invalid.")
        return value

    def openbao_payload(self):
        payload = {key: value for key, value in self.validated_data.items() if key != "reason"}
        if "metadata" in payload:
            payload["metadata"] = json.dumps(payload["metadata"], sort_keys=True, separators=(",", ":"))
        return payload


class AppRoleRoleIDSerializer(ReasonSerializer):
    role_id = serializers.RegexField(
        r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,999}$",
        write_only=True,
    )


class SecretIDAccessorSerializer(ReasonSerializer):
    accessor = serializers.CharField(max_length=1_000, write_only=True, trim_whitespace=False)
    confirmation = serializers.CharField(max_length=400, required=False)

    def validate(self, attrs):
        if self.context.get("destructive"):
            expected = self.context["expected_confirmation"]
            if attrs.get("confirmation") != expected:
                raise serializers.ValidationError({"confirmation": f"Type exactly: {expected}"})
        attrs["accessor"] = _safe_contract(
            lambda value: normalize_resource_name(value, uuid_only=True), attrs["accessor"]
        )
        return attrs


class AuthenticationLoginSerializer(ReasonSerializer):
    method_type = serializers.ChoiceField(
        choices=("token", "userpass", "ldap", "radius", "jwt", "approle", "kubernetes")
    )
    username = serializers.CharField(max_length=200, required=False)
    password = serializers.CharField(max_length=20_000, write_only=True, required=False, trim_whitespace=False)
    token = serializers.CharField(max_length=20_000, write_only=True, required=False, trim_whitespace=False)
    role = serializers.CharField(max_length=200, required=False)
    jwt = serializers.CharField(max_length=100_000, write_only=True, required=False, trim_whitespace=False)
    role_id = serializers.CharField(max_length=2_000, write_only=True, required=False)
    secret_id = serializers.CharField(max_length=20_000, write_only=True, required=False, trim_whitespace=False)

    def validate(self, attrs):
        required = {
            "token": {"token"},
            "userpass": {"username", "password"},
            "ldap": {"username", "password"},
            "radius": {"username", "password"},
            "jwt": {"role", "jwt"},
            "approle": {"role_id", "secret_id"},
            "kubernetes": {"role", "jwt"},
        }[attrs["method_type"]]
        supplied = set(attrs) - {"method_type", "reason"}
        if supplied != required:
            raise serializers.ValidationError("Provide exactly the reviewed fields for the selected login method.")
        for name in ("username", "role"):
            if name in attrs:
                attrs[name] = _safe_contract(normalize_resource_name, attrs[name])
        return attrs

    def openbao_payload(self):
        data = dict(self.validated_data)
        data.pop("method_type")
        data.pop("reason")
        return data


class OIDCStartSerializer(ReasonSerializer):
    role = serializers.CharField(max_length=200)

    def validate_role(self, value):
        return _safe_contract(normalize_resource_name, value)


class OIDCPollSerializer(ReasonSerializer):
    state = serializers.CharField(max_length=1_000, write_only=True, trim_whitespace=False)
    client_nonce = serializers.RegexField(NONCE_RE, max_length=200, write_only=True)
    envelope = serializers.CharField(max_length=4_000, write_only=True, trim_whitespace=False)


class MFAValidateSerializer(ReasonSerializer):
    mfa_request_id = serializers.CharField(max_length=1_000, write_only=True, trim_whitespace=False)
    mfa_payload = serializers.DictField(
        child=serializers.ListField(
            child=serializers.CharField(max_length=2_000, trim_whitespace=False), max_length=16
        ),
        write_only=True,
    )

    def validate_mfa_payload(self, value):
        if not value or len(value) > 32 or any(not NONCE_RE.fullmatch(key) for key in value):
            raise serializers.ValidationError("The MFA payload is invalid.")
        return value


class TOTPSetupSelfSerializer(ReasonSerializer):
    token = serializers.CharField(max_length=20_000, write_only=True, trim_whitespace=False)


class TOTPSetupSelfResetSerializer(TOTPSetupSelfSerializer):
    confirmation = serializers.CharField(max_length=400, trim_whitespace=True)

    def validate_confirmation(self, value):
        expected = self.context["expected_confirmation"]
        if value != expected:
            raise serializers.ValidationError(f"Type exactly: {expected}")
        return value


class TokenOperationSerializer(ReasonSerializer):
    token = serializers.CharField(max_length=20_000, write_only=True, required=False, trim_whitespace=False)
    accessor = serializers.CharField(max_length=1_000, write_only=True, required=False, trim_whitespace=False)
    increment = serializers.IntegerField(min_value=0, max_value=2**31 - 1, required=False)
    confirmation = serializers.CharField(max_length=400, required=False)

    def validate(self, attrs):
        operation = self.context["operation"]
        key = "token" if operation.endswith("self") else "accessor"
        allowed = {key, "reason", "confirmation"}
        if operation.startswith("renew"):
            allowed.add("increment")
        if key not in attrs or set(attrs) - allowed:
            raise serializers.ValidationError("Provide exactly the reviewed fields for this token operation.")
        if operation.startswith("revoke"):
            expected = self.context["expected_confirmation"]
            if attrs.get("confirmation") != expected:
                raise serializers.ValidationError({"confirmation": f"Type exactly: {expected}"})
        else:
            attrs.pop("confirmation", None)
        return attrs

    def openbao_payload(self):
        return {key: value for key, value in self.validated_data.items() if key not in {"reason", "confirmation"}}


def mfa_method_fields(method_type: str) -> dict[str, FieldRule]:
    return _safe_contract(MFA_METHOD_FIELDS.__getitem__, method_type)


def mfa_enforcement_fields() -> dict[str, FieldRule]:
    return MFA_ENFORCEMENT_FIELDS


def auth_config_fields(method_type: str) -> dict[str, FieldRule]:
    return _safe_contract(AUTH_CONFIG_FIELDS.__getitem__, method_type)
