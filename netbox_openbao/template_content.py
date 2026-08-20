"""
Panels injected into core NetBox detail pages.

Shows credential *inventory* on a Device, VM, or Service — which credentials
exist for the object, what they are for, and when they expire. Never material:
revealing is a separate action, on the credential's own page, behind its own
permission. That separation is what lets an operator browse the estate's
credential coverage without ever holding reveal rights.
"""

from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from netbox.plugins import PluginTemplateExtension

from .config import assignable_model_labels
from .models import CredentialAssignment

__all__ = ('template_extensions',)


class CredentialsPanel(PluginTemplateExtension):
    """Lists the credentials assigned to the object being viewed."""

    def buttons(self):
        """
        A quick-add button, on the objects it makes sense for.

        Only Devices and VMs: adding SSH access to a Service would be circular,
        since the service is what the action creates.
        """
        obj = self.context['object']
        request = self.context['request']

        label = f'{obj._meta.app_label}.{obj._meta.model_name}'
        if label not in ('dcim.device', 'virtualization.virtualmachine'):
            return ''
        if not request.user.has_perm('netbox_openbao.add_credential'):
            return ''

        url = reverse('plugins:netbox_openbao:quickadd_ssh', kwargs={
            'app_label': obj._meta.app_label,
            'model_name': obj._meta.model_name,
            'pk': obj.pk,
        })
        return self.render('netbox_openbao/inc/quickadd_button.html', extra_context={'url': url})

    def right_page(self):
        obj = self.context['object']
        request = self.context['request']

        content_type = ContentType.objects.get_for_model(obj)
        assignments = CredentialAssignment.objects.restrict(request.user, 'view').filter(
            assigned_object_type=content_type,
            assigned_object_id=obj.pk,
        ).select_related('credential', 'credential__policy').order_by('-is_primary', 'credential__name')

        # Render nothing at all when there is nothing to say, rather than an
        # empty card on every device page in the estate.
        if not assignments and not request.user.has_perm('netbox_openbao.add_credentialassignment'):
            return ''

        return self.render('netbox_openbao/panels/object_credentials.html', extra_context={
            'title': _('Credentials'),
            'assignments': assignments,
        })


def _build_extensions():
    """
    Register the panel against exactly the models the deployment permits
    assignment to, so the two lists cannot drift apart.
    """
    labels = assignable_model_labels()
    if not labels:
        return []

    return [type('OpenBaoCredentialsPanel', (CredentialsPanel,), {'models': labels})]


template_extensions = _build_extensions()
