"""
Declarative detail-view panels.

Built on NetBox 4.7's `netbox.ui` component framework rather than hand-written
templates, so the plugin's pages inherit core's look, spacing, and HTMX table
behaviour automatically instead of drifting from them at every release.

Every attribute rendered here is non-secret. There is no panel, and no attr,
that can display material — revealing is a separate POST-only view guarded by
its own permission.
"""

from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from netbox.ui import actions, attrs, panels

from netbox_openbao.compat import ArrayAttr

__all__ = (
    'AccessLogDetailPanel',
    'AccessLogPanel',
    'CredentialAssignmentDetailPanel',
    'CredentialAssignmentPanel',
    'CredentialLifecyclePanel',
    'CredentialPanel',
    'CredentialPolicyPanel',
    'CredentialPublicMaterialPanel',
    'CredentialRevealPanel',
    'CredentialRotationPanel',
    'CredentialStoragePanel',
    'CredentialTypeSchemaDefinitionPanel',
    'CredentialTypeSchemaPanel',
    'EnginePolicyPanel',
    'EngineProcedureRunPanel',
    'OpenBaoProcedureRunPanel',
    'OpenBaoProcedureRunResultPanel',
    'PolicyCredentialPanel',
    'SecretEnginePanel',
    'SecretEngineStatusPanel',
    'OpenBaoClusterPanel',
    'OpenBaoClusterStatusPanel',
    'OpenBaoAdministrationLogPanel',
)


class OpenBaoClusterPanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    slug = attrs.TextAttr('slug', style='font-monospace')
    backend = attrs.ChoiceAttr('backend')
    api_url = attrs.TextAttr('api_url', label=_('API URL'), style='font-monospace', copy_button=True)
    namespace = attrs.TextAttr('namespace')
    auth_method = attrs.ChoiceAttr('auth_method', label=_('Auth method'))
    host_device = attrs.RelatedObjectAttr('host_device', linkify=True, label=_('OpenBao host'))
    description = attrs.TextAttr('description')


class OpenBaoClusterStatusPanel(panels.ObjectAttributesPanel):
    title = _('Observed administration state')
    status = attrs.ChoiceAttr('status')
    status_message = attrs.TextAttr('status_message', label=_('Detail'))
    last_checked = attrs.DateTimeAttr('last_checked', label=_('Last checked'))
    openbao_version = attrs.TextAttr('openbao_version', label=_('OpenBao version'))
    tls_verify = attrs.BooleanAttr('tls_verify', label=_('Verify TLS'))
    ca_cert_path = attrs.TextAttr('ca_cert_path', label=_('CA bundle'), style='font-monospace')
    env_prefix = attrs.TextAttr('env_prefix', label=_('Environment prefix'), style='font-monospace', copy_button=True)
    capability_digest = attrs.TextAttr('capability_digest', label=_('Capability digest'), style='font-monospace')
    capabilities_checked = attrs.DateTimeAttr('capabilities_checked', label=_('Capabilities checked'))


class OpenBaoAdministrationLogPanel(panels.ObjectAttributesPanel):
    cluster = attrs.RelatedObjectAttr('cluster', linkify=True)
    cluster_name_snapshot = attrs.TextAttr('cluster_name_snapshot', label=_('Cluster snapshot'))
    username_snapshot = attrs.TextAttr('username_snapshot', label=_('User'))
    action = attrs.TextAttr('action')
    operation_id = attrs.TextAttr('operation_id', label=_('Operation ID'), style='font-monospace')
    risk_level = attrs.TextAttr('risk_level', label=_('Risk'))
    method = attrs.TextAttr('method', style='font-monospace')
    path_template = attrs.TextAttr('path_template', label=_('Path template'), style='font-monospace')
    source_ip = attrs.TextAttr('source_ip', label=_('Source IP'))
    reason = attrs.TextAttr('reason')
    request_id = attrs.TextAttr('request_id', label=_('Request ID'), style='font-monospace')
    capability_digest = attrs.TextAttr('capability_digest', label=_('Capability digest'), style='font-monospace')
    outcome = attrs.TextAttr('outcome')
    success = attrs.BooleanAttr('success')
    status_code = attrs.NumericAttr('status_code', label=_('Status code'))
    message = attrs.TextAttr('message')
    timestamp = attrs.DateTimeAttr('timestamp')


class SecretEnginePanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    slug = attrs.TextAttr('slug', style='font-monospace')
    cluster = attrs.RelatedObjectAttr('cluster', linkify=True, label=_('OpenBao cluster'))
    backend = attrs.ChoiceAttr('backend')
    api_url = attrs.TextAttr('api_url', label=_('API URL'), style='font-monospace', copy_button=True)
    namespace = attrs.TextAttr('namespace')
    kv_mount = attrs.TextAttr('kv_mount', label=_('KV mount'), style='font-monospace')
    kv_version = attrs.NumericAttr('kv_version', label=_('KV version'))
    auth_method = attrs.ChoiceAttr('auth_method', label=_('Auth method'))
    host_device = attrs.RelatedObjectAttr('host_device', linkify=True, label=_('OpenBao host'))
    is_default = attrs.BooleanAttr('is_default', label=_('Default engine'))
    description = attrs.TextAttr('description')


class SecretEngineStatusPanel(panels.ObjectAttributesPanel):
    """
    Observed state plus the environment contract.

    `env_prefix` is shown because it is the single most common source of a
    failed deployment: the operator must export `<prefix>_ROLE_ID` and
    `<prefix>_SECRET_ID`, and nothing in the database records whether they did.
    """

    title = _('Status')

    status = attrs.ChoiceAttr('status')
    status_message = attrs.TextAttr('status_message', label=_('Detail'))
    last_checked = attrs.DateTimeAttr('last_checked', label=_('Last checked'))
    tls_verify = attrs.BooleanAttr('tls_verify', label=_('Verify TLS'))
    ca_cert_path = attrs.TextAttr('ca_cert_path', label=_('CA bundle'), style='font-monospace')
    env_prefix = attrs.TextAttr(
        'env_prefix',
        label=_('Environment prefix'),
        style='font-monospace',
        copy_button=True,
    )


class CredentialPolicyPanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    slug = attrs.TextAttr('slug', style='font-monospace')
    engine = attrs.RelatedObjectAttr('engine', linkify=True, label=_('Secret engine'))
    openbao_policy = attrs.TextAttr('openbao_policy', label=_('OpenBao policy'), style='font-monospace')
    env_prefix = attrs.TextAttr('env_prefix', label=_('AppRole prefix'), style='font-monospace')
    max_reveal_ttl = attrs.NumericAttr('max_reveal_ttl', label=_('Max reveal TTL (s)'))
    require_reason = attrs.BooleanAttr('require_reason', label=_('Requires reason'))
    description = attrs.TextAttr('description')


class CredentialPanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    credential_type = attrs.ChoiceAttr('credential_type', label=_('Type'))
    username = attrs.TextAttr('username', copy_button=True)
    policy = attrs.RelatedObjectAttr('policy', linkify=True)
    status = attrs.ChoiceAttr('status')
    description = attrs.TextAttr('description')


class CredentialStoragePanel(panels.ObjectAttributesPanel):
    """Where the material lives. Never what it is."""

    title = _('Storage')

    engine = attrs.RelatedObjectAttr('engine', linkify=True, label=_('Secret engine'))
    path = attrs.TextAttr('path', style='font-monospace', copy_button=True)
    uuid = attrs.TextAttr('uuid', label=_('UUID'), style='font-monospace', copy_button=True)
    kv_version = attrs.NumericAttr('kv_version', label=_('KV version'))
    live_kv_version = attrs.NumericAttr('live_kv_version', label=_('Live version'))
    staged_kv_version = attrs.NumericAttr('staged_kv_version', label=_('Staged version'))
    import_source = attrs.TextAttr('import_source', label=_('Imported from'), style='font-monospace')
    last_verified = attrs.DateTimeAttr('last_verified', label=_('Last verified'))


class CredentialPublicMaterial(panels.ObjectAttributesPanel):
    title = _('Public material')

    fingerprint = attrs.TextAttr('fingerprint', style='font-monospace', copy_button=True)
    key_type = attrs.TextAttr('key_type', label=_('Key type'))
    cert_subject = attrs.TextAttr('cert_subject', label=_('Subject'))
    cert_issuer = attrs.TextAttr('cert_issuer', label=_('Issuer'))
    cert_serial = attrs.TextAttr('cert_serial', label=_('Serial'), style='font-monospace')
    valid_from = attrs.DateTimeAttr('valid_from', label=_('Valid from'), spec='date')
    valid_until = attrs.DateTimeAttr('valid_until', label=_('Valid until'), spec='date')


# Kept under the documented name while the class name stays descriptive.
CredentialPublicMaterialPanel = CredentialPublicMaterial


class CredentialLifecyclePanel(panels.ObjectAttributesPanel):
    title = _('Lifecycle')

    status = attrs.ChoiceAttr('status')
    rotation_interval = attrs.NumericAttr('rotation_interval', label=_('Rotation interval (days)'))
    last_rotated = attrs.DateTimeAttr('last_rotated', label=_('Last rotated'))


class CredentialAssignmentPanel(panels.ObjectsTablePanel):
    """Objects this credential is bound to."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('Assignments'))
        kwargs.setdefault('filters', {'credential_id': lambda ctx: ctx['object'].pk})
        kwargs.setdefault('exclude_columns', ['credential'])
        kwargs.setdefault('actions', [
            actions.AddObject(
                'netbox_openbao.CredentialAssignment',
                url_params={'credential': lambda ctx: ctx['object'].pk},
                label=_('Assign'),
            ),
        ])
        super().__init__('netbox_openbao.CredentialAssignment', **kwargs)


class AccessLogPanel(panels.ObjectsTablePanel):
    """Who has read this credential, and when."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('Access log'))
        kwargs.setdefault('filters', {'credential_id': lambda ctx: ctx['object'].pk})
        kwargs.setdefault('exclude_columns', ['credential', 'credential_name_snapshot'])
        super().__init__('netbox_openbao.CredentialAccessLog', **kwargs)


class CredentialAssignmentDetailPanel(panels.ObjectAttributesPanel):
    credential = attrs.RelatedObjectAttr('credential', linkify=True)
    assigned_object = attrs.GenericForeignKeyAttr('assigned_object', label=_('Object'), linkify=True)
    purpose = attrs.ChoiceAttr('purpose')
    is_primary = attrs.BooleanAttr('is_primary', label=_('Primary'))
    description = attrs.TextAttr('description')


class AccessLogDetailPanel(panels.ObjectAttributesPanel):
    timestamp = attrs.DateTimeAttr('timestamp')
    credential = attrs.RelatedObjectAttr('credential', linkify=True)
    credential_name_snapshot = attrs.TextAttr('credential_name_snapshot', label=_('Credential name'))
    username_snapshot = attrs.TextAttr('username_snapshot', label=_('User'))
    action = attrs.ChoiceAttr('action')
    success = attrs.BooleanAttr('success')
    source_ip = attrs.TextAttr('source_ip', label=_('Source IP'), style='font-monospace')
    request_id = attrs.TextAttr('request_id', label=_('Request ID'), style='font-monospace')
    reason = attrs.TextAttr('reason')
    message = attrs.TextAttr('message')


class EnginePolicyPanel(panels.ObjectsTablePanel):
    """Policy tiers backed by this engine."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('Policies'))
        kwargs.setdefault('filters', {'engine_id': lambda ctx: ctx['object'].pk})
        kwargs.setdefault('exclude_columns', ['engine'])
        kwargs.setdefault('actions', [
            actions.AddObject(
                'netbox_openbao.CredentialPolicy',
                url_params={'engine': lambda ctx: ctx['object'].pk},
            ),
        ])
        super().__init__('netbox_openbao.CredentialPolicy', **kwargs)


class EngineProcedureRunPanel(panels.ObjectsTablePanel):
    """Recent audited RPC operations against this engine's host device."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('Host operations'))
        kwargs.setdefault('filters', {'engine_id': lambda ctx: ctx['object'].pk})
        kwargs.setdefault('exclude_columns', ['engine'])
        kwargs.setdefault('actions', [
            RunProcedureLinkAction(),
        ])
        super().__init__('netbox_openbao.OpenBaoProcedureRun', **kwargs)


class RunProcedureLinkAction(actions.LinkAction):
    """Jump to the engine-scoped RPC dispatch form."""

    def __init__(self, **kwargs):
        super().__init__(
            view_name='plugins:netbox_openbao:secretengine_run-procedure',
            label=_('Run procedure'),
            button_icon='console-line',
            permissions=[
                'netbox_openbao.change_secretengine',
                'netbox_rpc.execute_rpcprocedure',
            ],
            **kwargs,
        )

    def get_url(self, context):
        return reverse(
            'plugins:netbox_openbao:secretengine_run-procedure',
            kwargs={'pk': context['object'].pk},
        )


class OpenBaoProcedureRunPanel(panels.ObjectAttributesPanel):
    engine = attrs.RelatedObjectAttr('engine', linkify=True)
    procedure_name = attrs.TextAttr('procedure_name', label=_('Procedure'), style='font-monospace')
    initiated_by = attrs.RelatedObjectAttr('initiated_by', linkify=True, label=_('Initiated by'))
    rpc_execution = attrs.RelatedObjectAttr('rpc_execution', linkify=True, label=_('RPC execution'))


class OpenBaoProcedureRunResultPanel(panels.ObjectAttributesPanel):
    title = _('Execution')

    status = attrs.TextAttr('rpc_execution.status', label=_('Status'))
    error_message = attrs.TextAttr('rpc_execution.error_message', label=_('Error'))
    started_at = attrs.DateTimeAttr('rpc_execution.started_at', label=_('Started'))
    finished_at = attrs.DateTimeAttr('rpc_execution.finished_at', label=_('Finished'))


class PolicyCredentialPanel(panels.ObjectsTablePanel):
    """Credentials governed by this policy tier."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('Credentials'))
        kwargs.setdefault('filters', {'policy_id': lambda ctx: ctx['object'].pk})
        kwargs.setdefault('exclude_columns', ['policy'])
        super().__init__('netbox_openbao.Credential', **kwargs)


class CredentialRevealPanel(panels.Panel):
    """
    The reveal control.

    A POST form rather than a link, so the secret is never fetched by a
    prefetch, a bookmark, a link scanner, or a history replay. The panel is
    hidden entirely from users without `reveal_credential` on this object,
    which is resolved in the view rather than guessed at in the template.
    """

    template_name = 'netbox_openbao/panels/reveal.html'
    title = _('Reveal')

    def should_render(self, context):
        return bool(context.get('can_reveal'))

    def get_context(self, context):
        return {
            **super().get_context(context),
            'object': context['object'],
            'require_reason': context['object'].policy.require_reason,
        }


class CredentialRotationPanel(panels.Panel):
    """
    Promote or discard a staged rotation.

    Renders only while something is actually staged — an always-present panel
    offering to promote nothing would be noise on every credential page in the
    estate.
    """

    template_name = 'netbox_openbao/panels/rotation.html'
    title = _('Staged rotation')

    def should_render(self, context):
        obj = context.get('object')
        return bool(obj is not None and obj.has_staged_version and context.get('can_rotate'))

    def get_context(self, context):
        return {**super().get_context(context), 'object': context['object']}


class CredentialTypeSchemaPanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    slug = attrs.TextAttr('slug', style='font-monospace')
    extractor = attrs.TextAttr('extractor', style='font-monospace')
    secret_fields = ArrayAttr('secret_fields', label=_('Secret fields'))
    description = attrs.TextAttr('description')


class CredentialTypeSchemaDefinitionPanel(panels.JSONPanel):
    """The stored JSON Schema, rendered as-is."""

    def __init__(self, **kwargs):
        kwargs.setdefault('title', _('JSON Schema'))
        super().__init__('schema', **kwargs)


class OpenBaoSettingsPanel(panels.ObjectAttributesPanel):
    """The settings an operator changes, grouped as they are on the form."""

    path_prefix = attrs.TextAttr('path_prefix', label=_('Path prefix'), style='font-monospace')
    store_public_material = attrs.BooleanAttr('store_public_material', label=_('Store public material'))
    reveal_rate_limit = attrs.TextAttr('reveal_rate_limit', label=_('Reveal rate limit'), style='font-monospace')
    reveal_ttl = attrs.NumericAttr('reveal_ttl', label=_('Reveal TTL (seconds)'))
    token_cache_ttl = attrs.NumericAttr('token_cache_ttl', label=_('Token cache TTL (seconds)'))
    allow_generation = attrs.BooleanAttr('allow_generation', label=_('Allow generation'))
    default_ssh_key_type = attrs.ChoiceAttr('default_ssh_key_type', label=_('Default SSH key type'))
    audit_retention_days = attrs.NumericAttr('audit_retention_days', label=_('Audit retention (days)'))


class OpenBaoSettingsSourcePanel(panels.ObjectAttributesPanel):
    """
    Where configuration is actually coming from, and what is being ignored.

    The second part is the reason this panel exists. Once a settings row is
    saved it becomes authoritative, and a key still present in `PLUGINS_CONFIG`
    is silently ignored — which is how an operator spends an afternoon on a
    value they can see in a file, have edited, and that does nothing. The same
    information is logged at startup; this puts it where they are already
    looking.
    """

    superseded_keys = attrs.TextAttr('superseded_plugins_config_keys', label=_('Ignored PLUGINS_CONFIG keys'))
    static_intervals = attrs.TextAttr('static_interval_summary', label=_('Restart-required settings'))
