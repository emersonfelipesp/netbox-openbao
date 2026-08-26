"""
Declarative detail-view panels.

Built on NetBox 4.7's `netbox.ui` component framework rather than hand-written
templates, so the plugin's pages inherit core's look, spacing, and HTMX table
behaviour automatically instead of drifting from them at every release.

Every attribute rendered here is non-secret. There is no panel, and no attr,
that can display material — revealing is a separate POST-only view guarded by
its own permission.
"""

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
    'PolicyCredentialPanel',
    'SecretEnginePanel',
    'SecretEngineStatusPanel',
)


class SecretEnginePanel(panels.ObjectAttributesPanel):
    name = attrs.TextAttr('name')
    slug = attrs.TextAttr('slug', style='font-monospace')
    backend = attrs.ChoiceAttr('backend')
    api_url = attrs.TextAttr('api_url', label=_('API URL'), style='font-monospace', copy_button=True)
    namespace = attrs.TextAttr('namespace')
    kv_mount = attrs.TextAttr('kv_mount', label=_('KV mount'), style='font-monospace')
    kv_version = attrs.NumericAttr('kv_version', label=_('KV version'))
    auth_method = attrs.ChoiceAttr('auth_method', label=_('Auth method'))
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
