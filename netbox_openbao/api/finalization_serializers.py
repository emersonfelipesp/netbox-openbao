"""Fail-closed request contracts for leases, tools, and UI configuration."""

from rest_framework import serializers

from netbox_openbao.administration.finalization import (
    normalize_final_identifier,
    operation_contract,
    validate_payload,
)
from netbox_openbao.administration.schema import CapabilitySchemaError


class FinalOperationSerializer(serializers.Serializer):
    resource = serializers.CharField(max_length=100)
    operation = serializers.CharField(max_length=100)
    identifier = serializers.CharField(max_length=500, required=False, allow_blank=True)
    payload = serializers.JSONField(required=False, default=dict)
    reason = serializers.CharField(min_length=3, max_length=1_000, trim_whitespace=True)
    capability_digest = serializers.RegexField(r"^[0-9a-f]{64}$")
    impact_digest = serializers.RegexField(r"^[0-9a-f]{64}$", required=False)
    confirmation = serializers.CharField(max_length=500, required=False, allow_blank=True)
    preview = serializers.BooleanField(required=False, default=False)

    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["The request contains unsupported fields."]})
        return super().to_internal_value(data)

    def validate(self, attrs):
        try:
            resource, operation = operation_contract(attrs["resource"], attrs["operation"])
            identifier = attrs.get("identifier", "")
            if "{identifier}" in operation.path_template:
                if resource.key == "leases" and attrs["operation"] == "list" and identifier == "":
                    attrs["identifier"] = ""
                else:
                    attrs["identifier"] = normalize_final_identifier(identifier, operation.identifier_kind)
            elif identifier:
                raise CapabilitySchemaError("This operation does not accept an identifier.")
            attrs["payload"] = validate_payload(attrs.get("payload", {}), operation)
        except (CapabilitySchemaError, KeyError, TypeError, ValueError):
            raise serializers.ValidationError("The request does not match a reviewed OpenBao 2.6.2 contract.") from None
        target = attrs.get("identifier") or attrs["payload"].get("lease_id", resource.key)
        expected = operation.confirmation.format(target=target, cluster=self.context["cluster"].slug)
        if operation.confirmation and not attrs["preview"]:
            if not attrs.get("impact_digest"):
                raise serializers.ValidationError({"impact_digest": "Preview the current impact before continuing."})
            if attrs.get("confirmation") != expected:
                raise serializers.ValidationError({"confirmation": f"Type exactly: {expected}"})
        elif not operation.confirmation and (attrs.get("impact_digest") or attrs.get("confirmation")):
            raise serializers.ValidationError("This operation does not accept destructive confirmation fields.")
        attrs["resource_spec"] = resource
        attrs["operation_spec"] = operation
        attrs["expected_confirmation"] = expected
        return attrs
