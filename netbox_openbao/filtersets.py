import django_filters
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from netbox.filtersets import BaseFilterSet, NetBoxModelFilterSet
from utilities.filters import ContentTypeFilter, MultiValueCharFilter, MultiValueNumberFilter

from .choices import (
    AccessActionChoices,
    AuthMethodChoices,
    CredentialStatusChoices,
    EngineStatusChoices,
    PurposeChoices,
)
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
    'CredentialAccessLogFilterSet',
    'CredentialAssignmentFilterSet',
    'CredentialFilterSet',
    'CredentialPolicyFilterSet',
    'CredentialTypeSchemaFilterSet',
    'OpenBaoProcedureRunFilterSet',
    'OpenBaoSettingsFilterSet',
    'SecretEngineFilterSet',
)


class OpenBaoSettingsFilterSet(NetBoxModelFilterSet):

    class Meta:
        model = OpenBaoSettings
        fields = ('id',)


class SecretEngineFilterSet(NetBoxModelFilterSet):
    auth_method = django_filters.MultipleChoiceFilter(choices=AuthMethodChoices)
    status = django_filters.MultipleChoiceFilter(choices=EngineStatusChoices)

    class Meta:
        model = SecretEngine
        fields = ('id', 'name', 'slug', 'backend', 'api_url', 'namespace', 'kv_mount', 'kv_version', 'tls_verify',
                  'is_default', 'host_device_id', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(slug__icontains=value)
            | Q(api_url__icontains=value)
            | Q(description__icontains=value)
        )


class CredentialPolicyFilterSet(NetBoxModelFilterSet):
    engine_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretEngine.objects.all(),
        label=_('Engine (ID)'),
    )
    engine = django_filters.ModelMultipleChoiceFilter(
        field_name='engine__slug',
        queryset=SecretEngine.objects.all(),
        to_field_name='slug',
        label=_('Engine (slug)'),
    )

    class Meta:
        model = CredentialPolicy
        fields = ('id', 'name', 'slug', 'openbao_policy', 'max_reveal_ttl', 'require_reason', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(slug__icontains=value)
            | Q(openbao_policy__icontains=value)
            | Q(description__icontains=value)
        )


class CredentialFilterSet(NetBoxModelFilterSet):
    # A plain char filter rather than a choice filter: the valid set now
    # includes operator-defined types, which a static choice list cannot know.
    credential_type = MultiValueCharFilter()
    status = django_filters.MultipleChoiceFilter(choices=CredentialStatusChoices)
    policy_id = django_filters.ModelMultipleChoiceFilter(
        queryset=CredentialPolicy.objects.all(),
        label=_('Policy (ID)'),
    )
    policy = django_filters.ModelMultipleChoiceFilter(
        field_name='policy__slug',
        queryset=CredentialPolicy.objects.all(),
        to_field_name='slug',
        label=_('Policy (slug)'),
    )
    engine_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretEngine.objects.all(),
        label=_('Engine (ID)'),
    )

    # The point of storing validity in NetBox: these answer "what expires soon"
    # with an indexed query and zero OpenBao reads.
    expires_before = django_filters.DateTimeFilter(field_name='valid_until', lookup_expr='lte')
    expires_after = django_filters.DateTimeFilter(field_name='valid_until', lookup_expr='gte')
    expires_within_days = django_filters.NumberFilter(
        method='filter_expires_within_days',
        label=_('Expires within N days'),
    )
    has_expiry = django_filters.BooleanFilter(
        field_name='valid_until',
        lookup_expr='isnull',
        exclude=True,
        label=_('Has an expiry date'),
    )

    # Traverses the assignment through-table: "which credentials does device
    # 88 hold?" An explicit field_name is required because NetBox derives
    # additional lookups from it, and the bare filter name does not resolve on
    # Credential itself.
    assigned_object_type = ContentTypeFilter(
        field_name='assignments__assigned_object_type',
        label=_('Assigned object type'),
    )
    assigned_object_id = MultiValueNumberFilter(
        field_name='assignments__assigned_object_id',
        label=_('Assigned object (ID)'),
    )
    purpose = django_filters.MultipleChoiceFilter(
        field_name='assignments__purpose',
        choices=PurposeChoices,
        label=_('Assignment purpose'),
    )
    fingerprint = MultiValueCharFilter(label=_('Fingerprint'))

    class Meta:
        model = Credential
        fields = ('id', 'name', 'uuid', 'username', 'key_type', 'cert_serial', 'path',
                  'rotation_interval', 'kv_version', 'description')

    def filter_expires_within_days(self, queryset, name, value):
        if value in (None, ''):
            return queryset
        from datetime import timedelta

        from django.utils import timezone

        horizon = timezone.now() + timedelta(days=float(value))
        return queryset.filter(valid_until__isnull=False, valid_until__lte=horizon)

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(username__icontains=value)
            | Q(fingerprint__icontains=value)
            | Q(cert_subject__icontains=value)
            | Q(cert_serial__icontains=value)
            | Q(description__icontains=value)
        )


class CredentialAssignmentFilterSet(NetBoxModelFilterSet):
    credential_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Credential.objects.all(),
        label=_('Credential (ID)'),
    )
    assigned_object_type = ContentTypeFilter()
    purpose = django_filters.MultipleChoiceFilter(choices=PurposeChoices)

    class Meta:
        model = CredentialAssignment
        fields = ('id', 'assigned_object_id', 'is_primary', 'enabled', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(credential__name__icontains=value) | Q(description__icontains=value)
        )


class CredentialAccessLogFilterSet(BaseFilterSet):
    """
    Filters for the audit trail. A plain BaseFilterSet because the log is not a
    NetBoxModel — it carries no tags or custom fields to filter on.
    """

    q = django_filters.CharFilter(method='search', label=_('Search'))
    action = django_filters.MultipleChoiceFilter(choices=AccessActionChoices)
    credential_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Credential.objects.all(),
        label=_('Credential (ID)'),
    )
    after = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='gte')
    before = django_filters.DateTimeFilter(field_name='timestamp', lookup_expr='lte')

    class Meta:
        model = CredentialAccessLog
        fields = (
            'id', 'credential_name_snapshot', 'username_snapshot', 'source_ip', 'request_id', 'success',
            'execution_id', 'intent_run_id', 'step_id', 'reference_name', 'executor_id',
        )

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(credential_name_snapshot__icontains=value)
            | Q(username_snapshot__icontains=value)
            | Q(reason__icontains=value)
        )


class CredentialTypeSchemaFilterSet(NetBoxModelFilterSet):

    class Meta:
        model = CredentialTypeSchema
        fields = ('id', 'name', 'slug', 'extractor', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(slug__icontains=value) | Q(description__icontains=value)
        )


class OpenBaoProcedureRunFilterSet(NetBoxModelFilterSet):
    engine_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretEngine.objects.all(),
        label=_('Engine (ID)'),
    )
    procedure_name = MultiValueCharFilter(field_name='procedure_name', lookup_expr='iexact')

    class Meta:
        model = OpenBaoProcedureRun
        fields = ('id', 'engine_id', 'procedure_name', 'initiated_by_id')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(procedure_name__icontains=value)
            | Q(engine__name__icontains=value)
            | Q(engine__slug__icontains=value)
        )
