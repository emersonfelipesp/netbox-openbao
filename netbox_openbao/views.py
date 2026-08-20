"""
UI views.

The reveal view is **POST-only**. A GET-reachable reveal URL can be
bookmarked, prefetched by the browser, followed by a link scanner, or replayed
from history — all of which would fetch a secret without anyone deciding to.
Requiring a POST means a reveal is always a deliberate act, and it keeps the
credential out of the URL bar and the referrer header.
"""

from django.contrib import messages
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
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
from .services import discard_staged, promote_staged, reveal_material
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
    'CredentialDiscardView',
    'CredentialPromoteView',
    'CredentialRevealPartialView',
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
            openbao_panels.CredentialRotationPanel(),
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
            'can_rotate': request.user.has_perm('netbox_openbao.rotate_credential', obj=instance),
        }


@register_model_view(Credential, 'add', detail=False)
@register_model_view(Credential, 'edit')
class CredentialEditView(generic.ObjectEditView):
    """
    Standard NetBox edit view.

    The material write is hooked in `CredentialForm.save()`, not here, because
    the generic view already wraps `form.save()` in a transaction and also
    supplies `restrict_form_fields()`, changelog snapshots, `alter_object()`,
    and quick-add handling that a bespoke `post()` would have to reproduce
    correctly.
    """

    queryset = Credential.objects.all()
    form = forms.CredentialForm


@register_model_view(Credential, 'delete')
class CredentialDeleteView(generic.ObjectDeleteView):
    queryset = Credential.objects.all()


@register_model_view(Credential, 'bulk_delete', path='delete', detail=False)
class CredentialBulkDeleteView(generic.BulkDeleteView):
    queryset = Credential.objects.select_related('policy', 'engine')
    filterset = filtersets.CredentialFilterSet
    table = tables.CredentialTable


class _RevealBase(ObjectPermissionRequiredMixin, View):
    """
    Shared authorization and resolution for both reveal surfaces.

    Extracted rather than duplicated on purpose: two code paths to the same
    secret are two places for the permission check, the policy reason gate, and
    the `no-store` headers to drift apart, and drift on this path is a
    disclosure bug.

    POST-only. A GET-reachable reveal can be bookmarked, prefetched by the
    browser, followed by a link scanner, or replayed from history — all of
    which would fetch a secret without anyone deciding to.
    """

    queryset = Credential.objects.select_related('policy', 'engine')

    def get_required_permission(self):
        return 'netbox_openbao.reveal_credential'

    def resolve(self, request, pk):
        """Return `(credential, secret_data, ttl)`, or raise."""
        credential = get_object_or_404(self.queryset.restrict(request.user, 'reveal'), pk=pk)
        data, ttl = reveal_material(
            credential, request.user, request=request, reason=request.POST.get('reason', ''),
        )
        return credential, data, ttl

    @staticmethod
    def unstorable(response):
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        return response


@register_model_view(Credential, 'reveal')
class CredentialRevealView(_RevealBase):
    """
    Full-page reveal, retained as the no-JavaScript fallback.

    The HTMX partial below is the normal path; this one still works with
    scripting disabled.
    """

    template_name = 'netbox_openbao/credential_reveal.html'

    def post(self, request, pk):
        try:
            credential, data, ttl = self.resolve(request, pk)
        except OpenBaoError as exc:
            messages.error(request, _('Could not read from OpenBao: {error}').format(error=exc))
            return redirect(reverse('plugins:netbox_openbao:credential', args=[pk]))
        except DjangoValidationError as exc:
            messages.error(request, '; '.join(exc.messages))
            return redirect(reverse('plugins:netbox_openbao:credential', args=[pk]))

        return self.unstorable(render(request, self.template_name, {
            'object': credential,
            'secret_data': data,
            'ttl': ttl,
        }))


@register_model_view(Credential, 'reveal-partial', path='reveal-partial')
class CredentialRevealPartialView(_RevealBase):
    """
    Reveal into the credential page over HTMX.

    Returns only the material fragment, which the panel swaps in place. Same
    authorization, same policy gate, same headers as the full-page view —
    because it is literally the same code.
    """

    template_name = 'netbox_openbao/partials/reveal_fragment.html'
    error_template_name = 'netbox_openbao/partials/reveal_error.html'

    def post(self, request, pk):
        try:
            credential, data, ttl = self.resolve(request, pk)
        except OpenBaoError as exc:
            return self.unstorable(render(request, self.error_template_name, {
                'message': _('Could not read from OpenBao: {error}').format(error=exc),
            }, status=502))
        except DjangoValidationError as exc:
            return self.unstorable(render(request, self.error_template_name, {
                'message': '; '.join(exc.messages),
            }, status=400))

        return self.unstorable(render(request, self.template_name, {
            'object': credential,
            'secret_data': data,
            'ttl': ttl,
        }))


class _StagedTransitionView(ObjectPermissionRequiredMixin, View):
    """
    Shared base for promote and discard.

    POST-only, like reveal: both change what every consumer of this credential
    receives, which is not something a link prefetch should be able to do.
    """

    queryset = Credential.objects.select_related('policy', 'engine')
    success_message = ''

    def get_required_permission(self):
        return 'netbox_openbao.rotate_credential'

    def apply(self, credential, request):
        raise NotImplementedError

    def post(self, request, pk):
        credential = get_object_or_404(self.queryset.restrict(request.user, 'rotate'), pk=pk)
        try:
            self.apply(credential, request)
        except OpenBaoError as exc:
            messages.error(request, _('Could not reach OpenBao: {error}').format(error=exc))
        except DjangoValidationError as exc:
            messages.error(request, '; '.join(exc.messages))
        else:
            messages.success(request, self.success_message.format(name=credential))
        return redirect(credential.get_absolute_url())


@register_model_view(Credential, 'promote')
class CredentialPromoteView(_StagedTransitionView):
    success_message = _('Promoted the staged version of {name}.')

    def apply(self, credential, request):
        promote_staged(
            credential,
            user=request.user,
            request=request,
            verified=bool(request.POST.get('verified')),
            note=request.POST.get('note', ''),
        )


@register_model_view(Credential, 'discard')
class CredentialDiscardView(_StagedTransitionView):
    success_message = _('Discarded the staged version of {name}.')

    def apply(self, credential, request):
        discard_staged(credential, user=request.user, request=request)


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
