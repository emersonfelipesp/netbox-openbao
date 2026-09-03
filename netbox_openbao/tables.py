import django_tables2 as tables
from django.utils.translation import gettext_lazy as _
from netbox.tables import NetBoxTable, columns

from .models import (
    Credential,
    CredentialAccessLog,
    CredentialAssignment,
    CredentialPolicy,
    CredentialTypeSchema,
    OpenBaoProcedureRun,
    OpenBaoSettings,
    SecretEngine,
)

__all__ = (
    'CredentialAccessLogTable',
    'CredentialAssignmentTable',
    'CredentialPolicyTable',
    'CredentialTable',
    'CredentialTypeSchemaTable',
    'OpenBaoProcedureRunTable',
    'SecretEngineTable',
)


class SecretEngineTable(NetBoxTable):
    name = tables.Column(linkify=True)
    host_device = tables.Column(linkify=True, verbose_name=_('OpenBao host'))
    status = columns.ChoiceFieldColumn()
    tls_verify = columns.BooleanColumn(verbose_name=_('Verify TLS'))
    is_default = columns.BooleanColumn(verbose_name=_('Default'))
    credential_count = columns.LinkedCountColumn(
        viewname='plugins:netbox_openbao:credential_list',
        url_params={'engine_id': 'pk'},
        verbose_name=_('Credentials'),
    )
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:secretengine_list')

    class Meta(NetBoxTable.Meta):
        model = SecretEngine
        fields = (
            'pk', 'id', 'name', 'slug', 'backend', 'api_url', 'namespace', 'host_device', 'kv_mount', 'kv_version',
            'auth_method', 'tls_verify', 'is_default', 'status', 'status_message', 'last_checked', 'credential_count',
            'description', 'comments', 'tags', 'created', 'last_updated',
        )
        default_columns = (
            'name', 'host_device', 'api_url', 'kv_mount', 'auth_method', 'status', 'is_default', 'credential_count',
        )


class CredentialPolicyTable(NetBoxTable):
    name = tables.Column(linkify=True)
    engine = tables.Column(linkify=True)
    require_reason = columns.BooleanColumn(verbose_name=_('Requires reason'))
    credential_count = columns.LinkedCountColumn(
        viewname='plugins:netbox_openbao:credential_list',
        url_params={'policy_id': 'pk'},
        verbose_name=_('Credentials'),
    )
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:credentialpolicy_list')

    class Meta(NetBoxTable.Meta):
        model = CredentialPolicy
        fields = (
            'pk', 'id', 'name', 'slug', 'engine', 'openbao_policy', 'approle_env_prefix', 'max_reveal_ttl',
            'require_reason', 'credential_count', 'description', 'tags', 'created', 'last_updated',
        )
        default_columns = ('name', 'engine', 'openbao_policy', 'require_reason', 'credential_count')


class CredentialTable(NetBoxTable):
    name = tables.Column(linkify=True)
    credential_type = columns.ChoiceFieldColumn(verbose_name=_('Type'))
    status = columns.ChoiceFieldColumn()
    policy = tables.Column(linkify=True)
    engine = tables.Column(linkify=True)
    valid_until = columns.DateTimeColumn(verbose_name=_('Expires'))
    assignment_count = columns.LinkedCountColumn(
        viewname='plugins:netbox_openbao:credentialassignment_list',
        url_params={'credential_id': 'pk'},
        verbose_name=_('Assignments'),
    )
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:credential_list')

    class Meta(NetBoxTable.Meta):
        model = Credential
        fields = (
            'pk', 'id', 'name', 'uuid', 'credential_type', 'policy', 'engine', 'path', 'username',
            'fingerprint', 'key_type', 'cert_serial', 'cert_subject', 'cert_issuer', 'valid_from',
            'valid_until', 'status', 'rotation_interval', 'last_rotated', 'kv_version', 'last_verified',
            'assignment_count', 'description', 'comments', 'tags', 'created', 'last_updated',
        )
        default_columns = (
            'name', 'credential_type', 'username', 'policy', 'status', 'valid_until', 'assignment_count',
        )


class CredentialAssignmentTable(NetBoxTable):
    credential = tables.Column(linkify=True)
    assigned_object = tables.Column(linkify=True, orderable=False, verbose_name=_('Object'))
    assigned_object_type = columns.ContentTypeColumn(verbose_name=_('Object type'))
    purpose = columns.ChoiceFieldColumn()
    is_primary = columns.BooleanColumn(verbose_name=_('Primary'))
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:credentialassignment_list')

    class Meta(NetBoxTable.Meta):
        model = CredentialAssignment
        fields = (
            'pk', 'id', 'credential', 'assigned_object_type', 'assigned_object', 'purpose', 'is_primary',
            'description', 'tags', 'created', 'last_updated',
        )
        default_columns = ('credential', 'assigned_object_type', 'assigned_object', 'purpose', 'is_primary')


class CredentialAccessLogTable(NetBoxTable):
    """
    Read-only view of the audit trail.

    The actions dropdown is removed outright: there is nothing to edit or
    delete, because the log is evidence rather than an object. It also cannot
    render — CredentialAccessLog is a plain Django model with no changelog
    view, so the default column raises NoReverseMatch on
    `credentialaccesslog_changelog`.
    """

    actions = columns.ActionsColumn(actions=())
    timestamp = columns.DateTimeColumn(linkify=True)
    credential = tables.Column(linkify=True)
    action = columns.ChoiceFieldColumn()
    success = columns.BooleanColumn()

    class Meta(NetBoxTable.Meta):
        model = CredentialAccessLog
        fields = (
            'pk', 'id', 'timestamp', 'credential', 'credential_name_snapshot', 'username_snapshot',
            'action', 'success', 'source_ip', 'reason', 'request_id', 'message',
        )
        default_columns = (
            'timestamp', 'credential_name_snapshot', 'username_snapshot', 'action', 'success', 'source_ip',
        )


class CredentialTypeSchemaTable(NetBoxTable):
    name = tables.Column(linkify=True)
    secret_fields = columns.ArrayColumn(verbose_name=_('Secret fields'))
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:credentialtypeschema_list')

    class Meta(NetBoxTable.Meta):
        model = CredentialTypeSchema
        fields = (
            'pk', 'id', 'name', 'slug', 'extractor', 'secret_fields', 'description',
            'tags', 'created', 'last_updated',
        )
        default_columns = ('name', 'slug', 'extractor', 'secret_fields', 'description')


class OpenBaoProcedureRunTable(NetBoxTable):
    engine = tables.Column(linkify=True)
    procedure_name = tables.Column(verbose_name=_('Procedure'))
    initiated_by = tables.Column(linkify=True)
    rpc_execution = tables.Column(linkify=True, verbose_name=_('RPC execution'))
    status = columns.ChoiceFieldColumn(accessor='rpc_execution__status', verbose_name=_('Status'))
    tags = columns.TagColumn(url_name='plugins:netbox_openbao:openbaoprocedurerun_list')

    class Meta(NetBoxTable.Meta):
        model = OpenBaoProcedureRun
        fields = (
            'pk', 'id', 'engine', 'procedure_name', 'initiated_by', 'rpc_execution', 'status',
            'tags', 'created', 'last_updated',
        )
        default_columns = ('created', 'engine', 'procedure_name', 'status', 'initiated_by', 'rpc_execution')


class OpenBaoSettingsTable(NetBoxTable):
    """
    The singleton, rendered as a one-row list because NetBox routes every model
    through a list view. The interesting columns are the ones an operator would
    check before opening the form.
    """

    path_prefix = tables.Column(linkify=True, verbose_name=_('Path prefix'))
    reveal_rate_limit = tables.Column(verbose_name=_('Reveal rate limit'))
    store_public_material = columns.BooleanColumn(verbose_name=_('Store public material'))
    allow_generation = columns.BooleanColumn(verbose_name=_('Allow generation'))

    class Meta(NetBoxTable.Meta):
        model = OpenBaoSettings
        fields = (
            'pk', 'id', 'path_prefix', 'reveal_rate_limit', 'reveal_ttl',
            'store_public_material', 'allow_generation', 'audit_retention_days',
            'last_updated',
        )
        default_columns = (
            'path_prefix', 'reveal_rate_limit', 'store_public_material',
            'allow_generation', 'last_updated',
        )
