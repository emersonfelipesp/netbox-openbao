"""Strict request envelopes for secrets-engine administration."""

from rest_framework import serializers

from netbox_openbao.administration.engines import (
    RESERVED_MOUNT_PATHS,
    normalize_migration_id,
    normalize_mount_path,
    normalize_resource_path,
    validate_bounded_json,
    validate_enable_payload,
    validate_query,
    validate_tune_payload,
)
from netbox_openbao.administration.schema import CapabilitySchemaError


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Expected an object.")
        unknown = set(data) - set(self.fields)
        if unknown:
            raise serializers.ValidationError("The request contains an undeclared field.")
        return super().to_internal_value(data)


def _safe(callable_, value):
    try:
        return callable_(value)
    except CapabilitySchemaError as exc:
        raise serializers.ValidationError(str(exc)) from None


class EnableSecretEngineSerializer(StrictSerializer):
    mount_path = serializers.CharField(max_length=128)
    configuration = serializers.JSONField()
    reason = serializers.CharField(max_length=500)

    def validate_mount_path(self, value):
        mount = _safe(normalize_mount_path, value)
        if mount in RESERVED_MOUNT_PATHS:
            raise serializers.ValidationError("This mount path is reserved by OpenBao.")
        return mount

    def validate_configuration(self, value):
        return _safe(validate_enable_payload, value)


class TuneSecretEngineSerializer(StrictSerializer):
    mount_path = serializers.CharField(max_length=128)
    configuration = serializers.JSONField()
    reason = serializers.CharField(max_length=500)

    def validate_mount_path(self, value):
        return _safe(normalize_mount_path, value)

    def validate_configuration(self, value):
        return _safe(validate_tune_payload, value)


class RemountSecretEngineSerializer(StrictSerializer):
    source = serializers.CharField(max_length=128)
    destination = serializers.CharField(max_length=128)
    reason = serializers.CharField(max_length=500)
    confirmation = serializers.CharField(max_length=500)

    def validate_source(self, value):
        return _safe(normalize_mount_path, value)

    def validate_destination(self, value):
        value = _safe(normalize_mount_path, value)
        if value in RESERVED_MOUNT_PATHS:
            raise serializers.ValidationError("This destination is reserved by OpenBao.")
        return value

    def validate(self, attrs):
        cluster = self.context["cluster"]
        expected = f"REMOUNT {attrs['source']} TO {attrs['destination']} ON {cluster.slug}"
        if attrs["source"] == attrs["destination"] or attrs["confirmation"] != expected:
            raise serializers.ValidationError("The exact remount confirmation is required.")
        return attrs


class DisableSecretEngineSerializer(StrictSerializer):
    mount_path = serializers.CharField(max_length=128)
    reason = serializers.CharField(max_length=500)
    confirmation = serializers.CharField(max_length=500)

    def validate_mount_path(self, value):
        return _safe(normalize_mount_path, value)

    def validate(self, attrs):
        cluster = self.context["cluster"]
        expected = f"DISABLE ENGINE {attrs['mount_path']} ON {cluster.slug}"
        if attrs["mount_path"] in RESERVED_MOUNT_PATHS or attrs["confirmation"] != expected:
            raise serializers.ValidationError("The exact disable confirmation is required.")
        return attrs


class RemountStatusSerializer(StrictSerializer):
    migration_id = serializers.CharField(max_length=200)

    def validate_migration_id(self, value):
        return _safe(normalize_migration_id, value)


class ReadSecretEngineSerializer(StrictSerializer):
    mount_path = serializers.CharField(max_length=128)

    def validate_mount_path(self, value):
        return _safe(normalize_mount_path, value)


class ExplorerExecuteSerializer(StrictSerializer):
    operation_key = serializers.CharField(max_length=1024)
    capability_digest = serializers.RegexField(r"^[0-9a-f]{64}$")
    mount_path = serializers.CharField(max_length=128)
    resource_path = serializers.CharField(max_length=1024, required=False, allow_blank=True, default="")
    path_parameters = serializers.JSONField(required=False, default=dict)
    query = serializers.JSONField(required=False, default=dict)
    body = serializers.JSONField(required=False, default=dict)
    reason = serializers.CharField(max_length=500)
    confirmation = serializers.CharField(max_length=1200, required=False, allow_blank=True, default="")

    def validate_mount_path(self, value):
        return _safe(normalize_mount_path, value)

    def validate_resource_path(self, value):
        return _safe(normalize_resource_path, value) if value else ""

    def validate_path_parameters(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("The mounted operation path parameters are invalid.")
        return value

    def validate_query(self, value):
        return _safe(validate_query, value)

    def validate_body(self, value):
        return _safe(validate_bounded_json, value)


class EngineJourneyExecuteSerializer(ExplorerExecuteSerializer):
    journey_id = serializers.RegexField(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$", max_length=100)
    operation_key = None
