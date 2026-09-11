"""The narrow, authenticated execution-bound resolution API."""

from __future__ import annotations

import json

from rest_framework import serializers


class AutomationResolveRequestSerializer(serializers.Serializer):
    """Only an execution and frozen reference name can select material."""

    schema_version = serializers.IntegerField(min_value=1, max_value=1)
    execution_id = serializers.IntegerField(min_value=1, max_value=9223372036854775807)
    step_id = serializers.RegexField(r'\A[a-zA-Z0-9_.-]{0,100}\Z', required=False, default='', allow_blank=True)
    reference_name = serializers.RegexField(r'\A[a-zA-Z][a-zA-Z0-9_.-]{0,99}\Z')
    dispatch_lease = serializers.DictField()

    def to_internal_value(self, data: object) -> dict:
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError('Invalid automation resolution request.')
        if type(data.get('schema_version')) is not int or type(data.get('execution_id')) is not int:
            raise serializers.ValidationError('Invalid automation resolution request.')
        if len(json.dumps(data).encode('utf-8')) > 16384:
            raise serializers.ValidationError('Invalid automation resolution request.')
        return super().to_internal_value(data)


class AutomationResolveResponseSerializer(serializers.Serializer):
    """Transient response contract; values are never model-backed."""

    schema_version = serializers.IntegerField(read_only=True)
    credential_uuid = serializers.UUIDField(read_only=True)
    assignment_id = serializers.IntegerField(read_only=True)
    resolved_version = serializers.IntegerField(read_only=True)
    ttl = serializers.IntegerField(read_only=True)
    secret = serializers.BooleanField(read_only=True)
    fields = serializers.DictField(child=serializers.CharField(), read_only=True)
    access_log_id = serializers.IntegerField(read_only=True)
