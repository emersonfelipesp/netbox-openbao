"""
REST API serializers.

The central invariant: `secret_data` is declared `write_only`. That is not a
convention the code is expected to respect — it is enforced by DRF itself, so
the field cannot appear in a `GET` response, a `brief=true` response, the
browsable API form, an export template, or an OpenAPI example, regardless of
what any view does. There is also no model field for it to fall back to.
"""

from django.core.exceptions import ValidationError as DjangoValidationError
from netbox.api.fields import ChoiceField, ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import NetBoxModelSerializer, OrganizationalModelSerializer, PrimaryModelSerializer
from rest_framework import serializers

from netbox_openbao.choices import (
    AccessActionChoices,
    AuthMethodChoices,
    CredentialStatusChoices,
    EngineStatusChoices,
    PurposeChoices,
)
from netbox_openbao.models import (
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    CredentialTypeSchema,
    SecretEngine,
)
from netbox_openbao.secrets.registry import validate_payload
from netbox_openbao.utils import assignable_content_types

__all__ = (
    'CredentialAccessLogSerializer',
    'PromoteRequestSerializer',
    'CredentialAssignmentSerializer',
    'CredentialPolicySerializer',
    'CredentialSerializer',
    'CredentialTypeSchemaSerializer',
    'RevealResponseSerializer',
    'RevealRequestSerializer',
    'SecretEngineSerializer',
)


class SecretEngineSerializer(PrimaryModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_openbao-api:secretengine-detail')
    auth_method = ChoiceField(choices=AuthMethodChoices, required=False)
    status = ChoiceField(choices=EngineStatusChoices, read_only=True)
    credential_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = SecretEngine
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'slug', 'backend', 'api_url', 'namespace', 'kv_mount',
            'kv_version', 'auth_method', 'tls_verify', 'ca_cert_path', 'is_default', 'status',
            'status_message', 'last_checked', 'env_prefix', 'credential_count', 'description', 'owner',
            'comments', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'description')
        read_only_fields = ('status', 'status_message', 'last_checked')


class CredentialPolicySerializer(OrganizationalModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_openbao-api:credentialpolicy-detail')
    engine = SecretEngineSerializer(nested=True)
    credential_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = CredentialPolicy
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'slug', 'engine', 'openbao_policy',
            'approle_env_prefix', 'groups', 'max_reveal_ttl', 'require_reason', 'credential_count',
            'description', 'owner', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'description')


class CredentialSerializer(PrimaryModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_openbao-api:credential-detail')
    # Dynamic: built-in types plus every operator-defined one.
    credential_type = serializers.CharField()
    status = ChoiceField(choices=CredentialStatusChoices, required=False)
    policy = CredentialPolicySerializer(nested=True)
    engine = SecretEngineSerializer(nested=True, required=False)
    assignment_count = serializers.IntegerField(read_only=True)
    has_staged_version = serializers.BooleanField(read_only=True)

    # The material. Write-only by declaration, so DRF will not serialize it
    # under any circumstance. It is consumed by the viewset and handed to the
    # backend; it never reaches a model field.
    secret_data = serializers.DictField(
        write_only=True,
        required=False,
        help_text='Secret payload written to OpenBao. Never returned by any endpoint.',
    )

    class Meta:
        model = Credential
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'uuid', 'credential_type', 'policy', 'engine',
            'path', 'username', 'public_key', 'fingerprint', 'key_type', 'cert_serial', 'cert_subject',
            'cert_issuer', 'valid_from', 'valid_until', 'status', 'rotation_interval', 'last_rotated',
            'import_source', 'kv_version', 'live_kv_version', 'staged_kv_version', 'has_staged_version',
            'last_verified',
            'assignment_count',
            'secret_data', 'description', 'owner', 'comments', 'tags', 'custom_fields', 'created',
            'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'credential_type', 'status', 'description')
        read_only_fields = (
            'uuid', 'path', 'import_source', 'kv_version', 'live_kv_version', 'staged_kv_version',
            'last_verified',
        )

    def validate(self, data):
        # NetBox's ValidatedModelSerializer builds `Model(**attrs)` to run
        # full_clean(), so `secret_data` must not be present when super() runs
        # — Credential has no such field, by design. Pop it, validate it on its
        # own terms, and restore it for the viewset.
        secret_data = data.pop('secret_data', None)

        # Creating a credential without material would leave a row pointing at
        # an empty path, which every consumer would then fail to resolve.
        if self.instance is None and not secret_data:
            raise serializers.ValidationError({
                'secret_data': 'Secret data is required when creating a credential.',
            })

        if secret_data:
            credential_type = data.get('credential_type') or getattr(self.instance, 'credential_type', None)
            try:
                validate_payload(credential_type, secret_data)
            except DjangoValidationError as exc:
                # Surface schema errors as field errors rather than a 500.
                detail = exc.message_dict if hasattr(exc, 'message_dict') else str(exc)
                raise serializers.ValidationError(detail) from None

        data = super().validate(data)

        if secret_data is not None:
            data['secret_data'] = secret_data
        return data


class CredentialTypeSchemaSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:credentialtypeschema-detail'
    )

    class Meta:
        model = CredentialTypeSchema
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'slug', 'description', 'schema',
            'secret_fields', 'extractor', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'description')


class PromoteRequestSerializer(serializers.Serializer):
    """Body accepted by the promote action."""

    verified = serializers.BooleanField(required=False, default=False)
    note = serializers.CharField(required=False, allow_blank=True, max_length=500)


class CredentialAssignmentSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:credentialassignment-detail'
    )
    credential = CredentialSerializer(nested=True)
    assigned_object_type = ContentTypeField(queryset=assignable_content_types())
    assigned_object = GFKSerializerField(read_only=True)
    purpose = ChoiceField(choices=PurposeChoices, required=False)

    class Meta:
        model = CredentialAssignment
        fields = (
            'id', 'url', 'display_url', 'display', 'credential', 'assigned_object_type',
            'assigned_object_id', 'assigned_object', 'purpose', 'is_primary', 'description',
            'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'credential', 'purpose')


class CredentialAccessLogSerializer(serializers.ModelSerializer):
    """Read-only. The log is append-only evidence, not an editable object."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:credentialaccesslog-detail'
    )
    credential = CredentialSerializer(nested=True, read_only=True)
    action = ChoiceField(choices=AccessActionChoices, read_only=True)
    display = serializers.CharField(read_only=True, source='__str__')

    class Meta:
        model = CredentialAccessLog
        fields = (
            'id', 'url', 'display', 'credential', 'credential_name_snapshot', 'credential_uuid_snapshot',
            'user', 'username_snapshot', 'action', 'source_ip', 'reason', 'request_id', 'success',
            'message', 'timestamp',
        )
        brief_fields = ('id', 'url', 'display', 'action', 'timestamp')
        read_only_fields = fields


class RevealRequestSerializer(serializers.Serializer):
    """Query parameters accepted by the reveal endpoint."""

    reason = serializers.CharField(required=False, allow_blank=True, max_length=500)
    version = serializers.IntegerField(required=False, min_value=1)


class RevealResponseSerializer(serializers.Serializer):
    """
    Shape of a reveal response.

    Declared explicitly so the OpenAPI schema documents the envelope without
    any generator ever introspecting a model field for the payload.
    """

    id = serializers.IntegerField(read_only=True)
    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    credential_type = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True, allow_blank=True)
    kv_version = serializers.IntegerField(read_only=True, allow_null=True)
    ttl = serializers.IntegerField(read_only=True)
    secret_data = serializers.DictField(read_only=True)
