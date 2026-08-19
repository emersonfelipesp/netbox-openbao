"""
UI views.

The reveal view is **POST-only**. A GET-reachable reveal URL can be
bookmarked, prefetched by the browser, followed by a link scanner, or replayed
from history — all of which would fetch a secret without anyone deciding to.
Requiring a POST means a reveal is always a deliberate act, and it keeps the
credential out of the URL bar and the referrer header.
"""

from django.contrib import messages
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.generic import View
from extras.ui.panels import CustomFieldsPanel, TagsPanel
from netbox.ui import layout
from netbox.ui.panels import CommentsPanel
from netbox.views import generic
from utilities.views import ObjectPermissionRequiredMixin, register_model_view

from . import filtersets, forms, tables
from .backends.exceptions import OpenBaoError
from .models import Credential, CredentialAccessLog, CredentialAssignment, CredentialPolicy, SecretEngine
from .services import reveal_material, store_credential
from .ui import panels as openbao_panels

__all__ = (
    'CredentialAccessLogListView',
    'CredentialAccessLogView',
    'CredentialAssignmentDeleteView',
    'CredentialAssignmentEditView',
    'CredentialAssignmentListView',
    'CredentialAssignmentView',
    'CredentialBulkDeleteView',
    'CredentialDeleteView',
    'CredentialEditView',
    'CredentialListView',
    'CredentialPolicyDeleteView',
    'CredentialPolicyEditView',
    'CredentialPolicyListView',
    'CredentialPolicyView',
    'CredentialRevealView',
    'CredentialView',
    'SecretEngineDeleteView',
    'SecretEngineEditView',
    'SecretEngineListView',
    'SecretEngineView',
)


#
# Secret engines
#

@register_model_view(SecretEngine, 'list', path='', detail=False)
class SecretEngineListView(generic.ObjectListView):
    queryset = SecretEngine.objects.annotate(credential_count=Count('credentials'))
    table = tables.SecretEngineTable
    filterset = filtersets.SecretEngineFilterSet
    filterset_form = forms.SecretEngineFilterForm


@register_model_view(SecretEngine)
class SecretEngineView(generic.ObjectView):
    queryset = SecretEngine.objects.all()
    layout = layout.SimpleLayout(
        left_panels=[
            openbao_panels.SecretEnginePanel(),
            CustomFieldsPanel(),
            TagsPanel(),
        ],
        right_panels=[
            openbao_panels.SecretEngineStatusPanel(),
            CommentsPanel(),
        ],
        bottom_panels=[
            openbao_panels.EnginePolicyPanel(),
        ],
    )


@register_model_view(SecretEngine, 'add', detail=False)
@register_model_view(SecretEngine, 'edit')
class SecretEngineEditView(generic.ObjectEditView):
    queryset = SecretEngine.objects.all()
    form = forms.SecretEngineForm


@register_model_view(SecretEngine, 'delete')
class SecretEngineDeleteView(generic.ObjectDeleteView):
    queryset = SecretEngine.objects.all()


#
# Credential policies
#

@register_model_view(CredentialPolicy, 'list', path='', detail=False)
class CredentialPolicyListView(generic.ObjectListView):
    queryset = CredentialPolicy.objects.select_related('engine').annotate(
        credential_count=Count('credentials')
    )
    table = tables.CredentialPolicyTable
    filterset = filtersets.CredentialPolicyFilterSet
    filterset_form = forms.CredentialPolicyFilterForm


@register_model_view(CredentialPolicy)
class CredentialPolicyView(generic.ObjectView):
    queryset = CredentialPolicy.objects.select_related('engine')
    layout = layout.SimpleLayout(
        left_panels=[
            openbao_panels.CredentialPolicyPanel(),
            CustomFieldsPanel(),
            TagsPanel(),
        ],
        right_panels=[
            openbao_panels.PolicyCredentialPanel(),
        ],
    )


@register_model_view(CredentialPolicy, 'add', detail=False)
@register_model_view(CredentialPolicy, 'edit')
class CredentialPolicyEditView(generic.ObjectEditView):
    queryset = CredentialPolicy.objects.all()
    form = forms.CredentialPolicyForm


@register_model_view(CredentialPolicy, 'delete')
class CredentialPolicyDeleteView(generic.ObjectDeleteView):
    queryset = CredentialPolicy.objects.all()


#
# Credentials
#

@register_model_view(Credential, 'list', path='', detail=False)
class CredentialListView(generic.ObjectListView):
    queryset = Credential.objects.select_related('policy', 'engine').annotate(
        assignment_count=Count('assignments')
    )
    table = tables.CredentialTable
    filterset = filtersets.CredentialFilterSet
    filterset_form = forms.CredentialFilterForm


@register_model_view(Credential)
class CredentialView(generic.ObjectView):
    queryset = Credential.objects.select_related('policy', 'engine')
    layout = layout.SimpleLayout(
        left_panels=[
            openbao_panels.CredentialPanel(),
            openbao_panels.CredentialPublicMaterialPanel(),
            CustomFieldsPanel(),
            TagsPanel(),
        ],
        right_panels=[
            openbao_panels.CredentialRevealPanel(),
            openbao_panels.CredentialStoragePanel(),
            openbao_panels.CredentialLifecyclePanel(),
            CommentsPanel(),
        ],
        bottom_panels=[
            openbao_panels.CredentialAssignmentPanel(),
            openbao_panels.AccessLogPanel(),
        ],
    )

    def get_extra_context(self, request, instance):
        # Drives the reveal panel: the button is only rendered for a user who
        # actually holds the permission on this object.
        return {
            'can_reveal': request.user.has_perm('netbox_openbao.reveal_credential', obj=instance),
        }


@register_model_view(Credential, 'add', detail=False)
@register_model_view(Credential, 'edit')
class CredentialEditView(generic.ObjectEditView):
    queryset = Credential.objects.all()
    form = forms.CredentialForm

    def form_valid_hook(self, form, request):  # pragma: no cover - hook for future use
        return None

    def post(self, request, *args, **kwargs):
        """
        Route the save through the service layer.

        NetBox's generic `ObjectEditView` would call `form.save()` directly,
        which persists the row without ever writing the material — leaving a
        credential whose path resolves to nothing. The material and the row
        have to be committed together, with the rollback compensator wrapping
        both.
        """
        obj = self.get_object(**kwargs)
        form = self.form(data=request.POST, files=request.FILES, instance=obj)

        if not form.is_valid():
            return render(request, self.template_name, {
                'model': self.queryset.model,
                'object': obj,
                'form': form,
                'return_url': self.get_return_url(request, obj),
                **self.get_extra_context(request, obj),
            })

        payload = getattr(form, 'secret_payload', None)
        try:
            if payload:
                instance, _version = store_credential(
                    lambda metadata: self._save_form(form, metadata),
                    form.cleaned_data['credential_type'],
                    payload,
                    cas=obj.kv_version if obj.pk else 0,
                    user=request.user,
                    request=request,
                )
            else:
                instance = form.save()
        except OpenBaoError as exc:
            messages.error(request, _('Could not write to OpenBao: {error}').format(error=exc))
            return render(request, self.template_name, {
                'model': self.queryset.model,
                'object': obj,
                'form': form,
                'return_url': self.get_return_url(request, obj),
                **self.get_extra_context(request, obj),
            })

        messages.success(request, _('Saved credential {name}.').format(name=instance))
        return redirect(self.get_return_url(request, instance))

    @staticmethod
    def _save_form(form, metadata):
        for field, value in metadata.items():
            setattr(form.instance, field, value)
        return form.save()


@register_model_view(Credential, 'delete')
class CredentialDeleteView(generic.ObjectDeleteView):
    queryset = Credential.objects.all()


@register_model_view(Credential, 'bulk_delete', path='delete', detail=False)
class CredentialBulkDeleteView(generic.BulkDeleteView):
    queryset = Credential.objects.select_related('policy', 'engine')
    filterset = filtersets.CredentialFilterSet
    table = tables.CredentialTable


@register_model_view(Credential, 'reveal')
class CredentialRevealView(ObjectPermissionRequiredMixin, View):
    """
    Reveal a credential's material in the UI.

    POST-only by design (see the module docstring), and the response carries
    `no-store` so neither the browser nor any proxy retains the rendered
    material.
    """

    queryset = Credential.objects.select_related('policy', 'engine')
    template_name = 'netbox_openbao/credential_reveal.html'

    def get_required_permission(self):
        return 'netbox_openbao.reveal_credential'

    def post(self, request, pk):
        credential = get_object_or_404(
            self.queryset.restrict(request.user, 'reveal'), pk=pk
        )
        reason = request.POST.get('reason', '')

        try:
            data, ttl = reveal_material(credential, request.user, request=request, reason=reason)
        except OpenBaoError as exc:
            messages.error(request, _('Could not read from OpenBao: {error}').format(error=exc))
            return redirect(credential.get_absolute_url())
        except Exception as exc:
            messages.error(request, str(exc))
            return redirect(credential.get_absolute_url())

        response = render(request, self.template_name, {
            'object': credential,
            'secret_data': data,
            'ttl': ttl,
        })
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        return response


#
# Assignments
#

@register_model_view(CredentialAssignment, 'list', path='', detail=False)
class CredentialAssignmentListView(generic.ObjectListView):
    queryset = CredentialAssignment.objects.select_related('credential', 'assigned_object_type')
    table = tables.CredentialAssignmentTable
    filterset = filtersets.CredentialAssignmentFilterSet
    filterset_form = forms.CredentialAssignmentFilterForm


@register_model_view(CredentialAssignment)
class CredentialAssignmentView(generic.ObjectView):
    queryset = CredentialAssignment.objects.select_related('credential', 'assigned_object_type')
    layout = layout.SimpleLayout(
        left_panels=[
            openbao_panels.CredentialAssignmentDetailPanel(),
        ],
        right_panels=[
            CustomFieldsPanel(),
            TagsPanel(),
        ],
    )


@register_model_view(CredentialAssignment, 'add', detail=False)
@register_model_view(CredentialAssignment, 'edit')
class CredentialAssignmentEditView(generic.ObjectEditView):
    queryset = CredentialAssignment.objects.all()
    form = forms.CredentialAssignmentForm


@register_model_view(CredentialAssignment, 'delete')
class CredentialAssignmentDeleteView(generic.ObjectDeleteView):
    queryset = CredentialAssignment.objects.all()


#
# Access log (read-only)
#

@register_model_view(CredentialAccessLog, 'list', path='', detail=False)
class CredentialAccessLogListView(generic.ObjectListView):
    queryset = CredentialAccessLog.objects.select_related('credential', 'user')
    table = tables.CredentialAccessLogTable
    filterset = filtersets.CredentialAccessLogFilterSet
    actions = {}


@register_model_view(CredentialAccessLog)
class CredentialAccessLogView(generic.ObjectView):
    queryset = CredentialAccessLog.objects.select_related('credential', 'user')
    layout = layout.SimpleLayout(
        left_panels=[
            openbao_panels.AccessLogDetailPanel(),
        ],
    )
