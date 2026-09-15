"""
REST API serializers.

The central invariant: `secret_data` is declared `write_only`. That is not a
convention the code is expected to respect — it is enforced by DRF itself, so
the field cannot appear in a `GET` response, a `brief=true` response, the
browsable API form, an export template, or an OpenAPI example, regardless of
what any view does. There is also no model field for it to fall back to.
"""

import base64
import binascii

from dcim.models import Device
from django.core.exceptions import ValidationError as DjangoValidationError
from netbox.api.fields import ChoiceField, ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import (
    BaseModelSerializer,
    NetBoxModelSerializer,
    OrganizationalModelSerializer,
    PrimaryModelSerializer,
)
from openpgp.composed import MessageBuilder, SignedPublicKey, SignedPublicSubKey
from openpgp.errors import Error as OpenPGPError
from openpgp.packet import Signature
from rest_framework import serializers

from netbox_openbao.choices import (
    AccessActionChoices,
    AuthMethodChoices,
    BackendChoices,
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
    OpenBaoAdministrationLog,
    OpenBaoCluster,
    OpenBaoProcedureRun,
    OpenBaoSettings,
    SecretEngine,
)
from netbox_openbao.rpc import ENGINE_BOUND_PARAM_KEYS, OPENBAO_READ_PROCEDURES, OPENBAO_WRITE_PROCEDURES
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
    'RunProcedureSerializer',
    'OpenBaoProcedureRunSerializer',
    'OpenBaoAdministrationLogSerializer',
    'OpenBaoClusterSerializer',
    'OpenBaoSettingsSerializer',
    'SecretEngineSerializer',
    'InitializeClusterSerializer',
    'UnsealClusterSerializer',
    'ConfirmClusterActionSerializer',
    'RemoveRaftPeerSerializer',
    'RestoreRaftSnapshotSerializer',
)


class _ClusterConfirmationSerializer(serializers.Serializer):
    reason = serializers.CharField(min_length=3, max_length=1000, trim_whitespace=True)
    confirmation = serializers.CharField(max_length=300, trim_whitespace=True)

    def expected_confirmation(self, attrs):
        raise NotImplementedError

    def validate(self, attrs):
        expected = self.expected_confirmation(attrs)
        if attrs.get('confirmation') != expected:
            raise serializers.ValidationError({'confirmation': f'Type exactly: {expected}'})
        return attrs


OPENPGP_VALIDATION_PAYLOAD = b'netbox-openbao-encryption-key-validation'
OpenPGPRecipient = SignedPublicKey | SignedPublicSubKey


def _signature_allows_encryption(signature: Signature) -> bool:
    flags = signature.key_flags()
    return flags.encrypt_communications or flags.encrypt_storage


def _encryption_recipients(key: SignedPublicKey) -> list[OpenPGPRecipient]:
    """Return only certified entity keys that explicitly permit encryption."""
    primary_signatures = list(key.details.direct_signatures)
    for identity in (*key.details.users, *key.details.user_attributes):
        primary_signatures.extend(identity.signatures)
    recipients = []
    if key.primary_key.algorithm.can_encrypt() and any(map(_signature_allows_encryption, primary_signatures)):
        recipients.append(key)
    for subkey in key.public_subkeys:
        if subkey.key.algorithm.can_encrypt() and any(map(_signature_allows_encryption, subkey.signatures)):
            recipients.append(subkey)
    return recipients


def _recipient_can_encrypt(recipient: OpenPGPRecipient) -> bool:
    try:
        encrypted = (
            MessageBuilder.from_bytes('', OPENPGP_VALIDATION_PAYLOAD)
            .seipd_v1('aes256')
            .encrypt_to_key(recipient)
            .to_vec()
        )
    except OpenPGPError:
        return False
    return bool(encrypted)


def _validate_openpgp_export(data: bytes) -> None:
    """Require one exact, fully verified entity usable for OpenBao encryption."""
    key = SignedPublicKey.from_bytes(data)
    if key.to_bytes() != data:
        raise ValueError
    key.verify_bindings()
    if not any(map(_recipient_can_encrypt, _encryption_recipients(key))):
        raise ValueError


def _validate_openpgp_public_key(value: str) -> str:
    """Accept one verified, encryption-capable standard-base64 public export."""
    try:
        decoded = base64.b64decode(value, validate=True)
        _validate_openpgp_export(decoded)
    except (binascii.Error, OpenPGPError, TypeError, ValueError):
        raise serializers.ValidationError(
            'Use standard base64 of one complete binary OpenPGP public-key export without ASCII armor.'
        ) from None
    return value


class InitializeClusterSerializer(_ClusterConfirmationSerializer):
    secret_shares = serializers.IntegerField(min_value=1, max_value=64, required=False)
    secret_threshold = serializers.IntegerField(min_value=1, max_value=64, required=False)
    recovery_shares = serializers.IntegerField(min_value=0, max_value=64, required=False)
    recovery_threshold = serializers.IntegerField(min_value=0, max_value=64, required=False)
    pgp_keys = serializers.ListField(
        child=serializers.CharField(
            min_length=1,
            max_length=20_000,
            validators=[_validate_openpgp_public_key],
        ),
        max_length=64,
        required=False,
    )
    recovery_pgp_keys = serializers.ListField(
        child=serializers.CharField(
            min_length=1,
            max_length=20_000,
            validators=[_validate_openpgp_public_key],
        ),
        max_length=64,
        required=False,
    )
    root_token_pgp_key = serializers.CharField(
        min_length=1,
        max_length=20_000,
        required=False,
        validators=[_validate_openpgp_public_key],
    )

    def expected_confirmation(self, attrs):
        del attrs
        return f"INITIALIZE {self.context['cluster'].slug}"

    def validate(self, attrs):
        attrs = super().validate(attrs)
        shamir = 'secret_shares' in attrs or 'secret_threshold' in attrs
        recovery = 'recovery_shares' in attrs or 'recovery_threshold' in attrs
        if shamir == recovery:
            raise serializers.ValidationError(
                'Specify either a complete Shamir share pair or a complete recovery share pair.'
            )
        shares_key, threshold_key, pgp_key = (
            ('secret_shares', 'secret_threshold', 'pgp_keys')
            if shamir
            else ('recovery_shares', 'recovery_threshold', 'recovery_pgp_keys')
        )
        if shares_key not in attrs or threshold_key not in attrs:
            raise serializers.ValidationError('Both share count and threshold are required.')
        shares = attrs[shares_key]
        threshold = attrs[threshold_key]
        if threshold > shares:
            raise serializers.ValidationError({threshold_key: 'Threshold cannot exceed the share count.'})
        if pgp_key in attrs and len(attrs[pgp_key]) != shares:
            raise serializers.ValidationError({pgp_key: 'Provide exactly one PGP key for every share.'})
        return attrs

    def openbao_payload(self) -> dict:
        excluded = {'reason', 'confirmation'}
        return {key: value for key, value in self.validated_data.items() if key not in excluded}


class UnsealClusterSerializer(_ClusterConfirmationSerializer):
    key = serializers.CharField(min_length=1, max_length=20_000, write_only=True, required=False, trim_whitespace=True)
    reset = serializers.BooleanField(default=False)
    migrate = serializers.BooleanField(default=False)

    def expected_confirmation(self, attrs):
        action = 'RESET UNSEAL' if attrs.get('reset') else 'UNSEAL'
        return f"{action} {self.context['cluster'].slug}"

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs.get('reset'):
            attrs.pop('key', None)
        elif not attrs.get('key'):
            raise serializers.ValidationError({'key': 'One unseal share is required.'})
        return attrs


class ConfirmClusterActionSerializer(_ClusterConfirmationSerializer):
    action = None

    def expected_confirmation(self, attrs):
        del attrs
        return f"{self.action} {self.context['cluster'].slug}"


class RemoveRaftPeerSerializer(_ClusterConfirmationSerializer):
    server_id = serializers.RegexField(r'^[A-Za-z0-9_.:-]{1,200}$')
    configuration_index = serializers.IntegerField(min_value=0)

    def expected_confirmation(self, attrs):
        return f"REMOVE {attrs.get('server_id', '')} FROM {self.context['cluster'].slug}"


class RestoreRaftSnapshotSerializer(_ClusterConfirmationSerializer):
    cluster_id = serializers.CharField(min_length=1, max_length=200, trim_whitespace=True)
    configuration_index = serializers.IntegerField(min_value=0)
    force = False

    def expected_confirmation(self, attrs):
        action = 'FORCE RESTORE SNAPSHOT' if self.force else 'RESTORE SNAPSHOT'
        return f"{action} {self.context['cluster'].slug}"


class OpenBaoClusterSerializer(PrimaryModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:openbaocluster-detail'
    )
    backend = ChoiceField(choices=BackendChoices, required=False)
    auth_method = ChoiceField(choices=AuthMethodChoices, required=False)
    status = ChoiceField(choices=EngineStatusChoices, read_only=True)
    mount_count = serializers.IntegerField(read_only=True)
    host_device = serializers.PrimaryKeyRelatedField(
        queryset=Device.objects.all(), allow_null=True, required=False,
    )

    class Meta:
        model = OpenBaoCluster
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'slug', 'backend', 'api_url',
            'namespace', 'auth_method', 'tls_verify', 'ca_cert_path', 'host_device',
            'status', 'status_message', 'last_checked', 'openbao_version',
            'capability_digest', 'capabilities_checked', 'env_prefix', 'mount_count',
            'description', 'owner', 'comments', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'status', 'description')
        read_only_fields = (
            'status', 'status_message', 'last_checked', 'openbao_version',
            'capability_digest', 'capabilities_checked',
        )


class OpenBaoAdministrationLogSerializer(BaseModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:openbaoadministrationlog-detail'
    )
    cluster = OpenBaoClusterSerializer(nested=True, read_only=True)
    display = serializers.CharField(read_only=True, source='__str__')

    class Meta:
        model = OpenBaoAdministrationLog
        fields = (
            'id', 'url', 'display', 'cluster', 'cluster_name_snapshot', 'cluster_slug_snapshot',
            'user', 'username_snapshot', 'action', 'operation_id', 'risk_level', 'method',
            'path_template', 'source_ip', 'reason', 'request_id', 'capability_digest',
            'outcome', 'success', 'status_code', 'message', 'timestamp',
        )
        brief_fields = ('id', 'url', 'display', 'action', 'risk_level', 'outcome', 'success', 'timestamp')
        read_only_fields = fields


class SecretEngineSerializer(PrimaryModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_openbao-api:secretengine-detail')
    auth_method = ChoiceField(choices=AuthMethodChoices, required=False)
    status = ChoiceField(choices=EngineStatusChoices, read_only=True)
    credential_count = serializers.IntegerField(read_only=True)
    host_device = serializers.PrimaryKeyRelatedField(
        queryset=Device.objects.all(),
        allow_null=True,
        required=False,
    )
    cluster = OpenBaoClusterSerializer(nested=True, required=False, allow_null=True)

    class Meta:
        model = SecretEngine
        fields = (
            'id', 'url', 'display_url', 'display', 'name', 'slug', 'cluster', 'backend',
            'api_url', 'namespace', 'host_device',
            'kv_mount', 'kv_version', 'auth_method', 'tls_verify', 'ca_cert_path', 'is_default', 'status',
            'status_message', 'last_checked', 'env_prefix', 'credential_count', 'description', 'owner',
            'comments', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'description')
        read_only_fields = ('status', 'status_message', 'last_checked')


class OpenBaoSettingsSerializer(NetBoxModelSerializer):
    """REST representation of the singleton plugin settings row."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:openbaosettings-detail'
    )

    def validate(self, data):
        data = super().validate(data)
        if self.instance is None and OpenBaoSettings.objects.exists():
            raise serializers.ValidationError(
                {'non_field_errors': ['The OpenBao settings row already exists.']}
            )
        return data

    class Meta:
        model = OpenBaoSettings
        fields = (
            'id', 'url', 'display', 'singleton_key',
            'path_prefix', 'assignable_models', 'assignable_models_deny',
            'store_public_material', 'reveal_rate_limit', 'reveal_ttl',
            'token_cache_ttl', 'audit_retention_days', 'allow_generation',
            'default_ssh_key_type', 'expiry_warning_days',
            'engine_health_interval', 'expiry_scan_interval',
            'credential_verify_interval', 'rotation_due_interval',
            'access_log_prune_interval', 'tags', 'custom_fields',
            'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display')
        read_only_fields = ('singleton_key',)


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
            'assigned_object_id', 'assigned_object', 'purpose', 'is_primary', 'enabled', 'description',
            'tags', 'custom_fields', 'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'credential', 'purpose')


class CredentialAccessLogSerializer(BaseModelSerializer):
    """
    Read-only. The log is append-only evidence, not an editable object.

    `BaseModelSerializer` rather than DRF's `ModelSerializer`, even though
    `CredentialAccessLog` is a plain Django model with no NetBox features to
    inherit. NetBox's `BaseViewSet.get_serializer()` passes `fields` and `omit`
    keyword arguments down for `?fields=`, `?omit=`, and `?brief=true`, and a
    serializer that does not accept them raises
    `TypeError: Field.__init__() got an unexpected keyword argument 'fields'`
    — a 500 on three ordinary query modes, of which only `brief` is obvious
    enough to have been noticed.

    That was invisible while the viewset was DRF's plain `ReadOnlyModelViewSet`,
    because nothing was passing the arguments. Moving to
    `NetBoxReadOnlyModelViewSet` to get object-permission constraints applied
    is what started passing them.
    """

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:credentialaccesslog-detail'
    )
    credential = CredentialSerializer(nested=True, read_only=True)
    action = ChoiceField(choices=AccessActionChoices, read_only=True)
    display = serializers.CharField(read_only=True, source='__str__')

    class Meta:
        model = CredentialAccessLog
        fields = (
            'id', 'url', 'display_url', 'display', 'credential', 'credential_name_snapshot',
            'credential_uuid_snapshot', 'user', 'username_snapshot', 'action', 'source_ip', 'reason',
            'request_id', 'success', 'message', 'timestamp', 'executor', 'executor_snapshot',
            'execution_id', 'intent_run_id', 'step_id', 'reference_name', 'assignment_id',
            'resolved_version', 'purpose', 'dispatch_nonce_digest',
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


class RunProcedureSerializer(serializers.Serializer):
    """Dispatch a seeded OpenBao RPC procedure against the engine host device."""

    procedure_name = serializers.ChoiceField(
        choices=[
            (name, name.removeprefix('service.openbao.1.'))
            for name in sorted(OPENBAO_READ_PROCEDURES | OPENBAO_WRITE_PROCEDURES)
        ],
    )
    params = serializers.DictField(required=False, default=dict)

    def validate(self, attrs):
        params = attrs.get('params') or {}
        if bound := ENGINE_BOUND_PARAM_KEYS & params.keys():
            raise serializers.ValidationError({
                'params': (
                    'The following parameters are derived from the selected engine and cannot be overridden: '
                    + ', '.join(sorted(bound))
                ),
            })
        return attrs


class OpenBaoProcedureRunSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_openbao-api:openbaoprocedurerun-detail',
    )
    engine = SecretEngineSerializer(nested=True, read_only=True)
    rpc_execution_id = serializers.PrimaryKeyRelatedField(
        source='rpc_execution',
        read_only=True,
    )
    status = serializers.CharField(source='rpc_execution.status', read_only=True)
    result = serializers.JSONField(source='rpc_execution.result', read_only=True)
    error_message = serializers.CharField(source='rpc_execution.error_message', read_only=True)

    class Meta:
        model = OpenBaoProcedureRun
        fields = (
            'id', 'url', 'display_url', 'display', 'engine', 'procedure_name', 'initiated_by',
            'rpc_execution_id', 'status', 'result', 'error_message',
        ) + tuple(
            name for name in ('comments', 'tags', 'custom_fields')
            if any(field.name == name for field in OpenBaoProcedureRun._meta.get_fields())
        ) + (
            'created', 'last_updated',
        )
        brief_fields = ('id', 'url', 'display', 'procedure_name', 'status')
        read_only_fields = (
            'engine', 'procedure_name', 'initiated_by', 'rpc_execution_id', 'status', 'result', 'error_message',
        )
