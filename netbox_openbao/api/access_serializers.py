"""Fail-closed request contracts for policy, identity, OIDC, and namespaces."""

from __future__ import annotations

from rest_framework import serializers

from netbox_openbao.administration.access import (
    normalize_identifier,
    operation_contract,
    validate_access_payload,
)
from netbox_openbao.administration.schema import CapabilitySchemaError


def _safe(callable_, *args):
    try:
        return callable_(*args)
    except (CapabilitySchemaError, KeyError, TypeError, ValueError):
        raise serializers.ValidationError("The request does not match a reviewed OpenBao 2.6.2 contract.") from None


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["The request contains unsupported fields."]})
        return super().to_internal_value(data)


class AccessPreviewSerializer(StrictSerializer):
    resource = serializers.CharField(max_length=100)
    operation = serializers.ChoiceField(choices=("delete", "rotate", "merge"))
    identifier = serializers.CharField(max_length=500, required=False, allow_blank=True)
    payload = serializers.JSONField(required=False, default=dict)
    capability_digest = serializers.RegexField(r"^[0-9a-f]{64}$")

    def validate(self, attrs):
        resource, operation = _safe(operation_contract, attrs["resource"], attrs["operation"])
        if not operation.confirmation:
            raise serializers.ValidationError("The selected operation does not have an impact preview.")
        identifier = attrs.get("identifier", "")
        if "{identifier}" in operation.path_template:
            attrs["identifier"] = _safe(normalize_identifier, identifier, resource.identifier_kind)
        elif identifier:
            raise serializers.ValidationError({"identifier": "This operation does not accept an identifier."})
        attrs["payload"] = _safe(validate_access_payload, attrs.get("payload", {}), operation.fields)
        attrs["resource_spec"] = resource
        attrs["operation_spec"] = operation
        return attrs


class AccessExecuteSerializer(StrictSerializer):
    resource = serializers.CharField(max_length=100)
    operation = serializers.CharField(max_length=32)
    identifier = serializers.CharField(max_length=500, required=False, allow_blank=True)
    payload = serializers.JSONField(required=False, default=dict)
    reason = serializers.CharField(min_length=3, max_length=1_000, trim_whitespace=True)
    capability_digest = serializers.RegexField(r"^[0-9a-f]{64}$")
    impact_digest = serializers.RegexField(r"^[0-9a-f]{64}$", required=False)
    confirmation = serializers.CharField(max_length=500, required=False, allow_blank=True)

    def validate(self, attrs):
        resource, operation = _safe(operation_contract, attrs["resource"], attrs["operation"])
        identifier = attrs.get("identifier", "")
        if "{identifier}" in operation.path_template:
            attrs["identifier"] = _safe(normalize_identifier, identifier, resource.identifier_kind)
        elif identifier:
            raise serializers.ValidationError({"identifier": "This operation does not accept an identifier."})
        attrs["payload"] = _safe(validate_access_payload, attrs.get("payload", {}), operation.fields)
        expected = operation.confirmation.format(
            resource=resource.key,
            identifier=attrs.get("identifier", ""),
            cluster=self.context["cluster"].slug,
        )
        if operation.confirmation:
            if not attrs.get("impact_digest"):
                raise serializers.ValidationError({"impact_digest": "Preview the current impact before continuing."})
            if attrs.get("confirmation") != expected:
                raise serializers.ValidationError({"confirmation": f"Type exactly: {expected}"})
        elif attrs.get("impact_digest") or attrs.get("confirmation"):
            raise serializers.ValidationError("This operation does not accept destructive confirmation fields.")
        attrs["resource_spec"] = resource
        attrs["operation_spec"] = operation
        attrs["expected_confirmation"] = expected
        return attrs
