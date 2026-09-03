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
    """
    Lists the credentials assigned to the object being viewed.

    **Registered globally, filtered per request.** `models` is deliberately left
    unset. NetBox's `register_template_extensions()` reads `models` once, during
    the plugin's `ready()`, and files the class under each label it names — so a
    class built from a snapshot of `assignable_model_labels()` freezes that list
    at whatever it happened to be at that moment. An integrating plugin that
    registers its models from its own `ready()` would then be permitted to
    create assignments but get no panel, purely because `PLUGINS` happened to
    list `netbox_openbao` first. Same configuration, different UI, no error.

    Registering globally and checking the label on each render costs one set
    lookup per object detail page and cannot go stale.
    """

    @staticmethod
    def _canonical_label(obj):
        """
        The `app_label.model` an assignment to `obj` would actually carry.

        Resolved through `ContentType.objects.get_for_model()` rather than from
        `obj._meta`, because for a **proxy model** those two disagree: the
        content type resolves to the concrete model by default, so a proxy's
        assignments are filed under the concrete label while `_meta` reports the
        proxy's own. Comparing `_meta` against the allowlist while querying
        assignments by content type meant a proxy of an allowed model had valid
        assignments and never rendered a panel.

        `CredentialAssignment.clean()` validates against the content type too,
        so this is the label that decides everything else as well.
        """
        content_type = ContentType.objects.get_for_model(obj)
        return f'{content_type.app_label}.{content_type.model}'

    def _is_assignable(self):
        return self._canonical_label(self.context['object']) in assignable_model_labels()

    def buttons(self):
        """
        A quick-add button, on the objects it makes sense for.

        Only Devices and VMs: adding SSH access to a Service would be circular,
        since the service is what the action creates.
        """
        request = self.context['request']

        label = self._canonical_label(self.context['object'])
        if label not in ('dcim.device', 'virtualization.virtualmachine'):
            return ''
        if label not in assignable_model_labels():
            return ''
        if not request.user.has_perm('netbox_openbao.add_credential'):
            return ''

        obj = self.context['object']
        url = reverse('plugins:netbox_openbao:quickadd_ssh', kwargs={
            'app_label': obj._meta.app_label,
            'model_name': obj._meta.model_name,
            'pk': obj.pk,
        })
        return self.render('netbox_openbao/inc/quickadd_button.html', extra_context={'url': url})

    def right_page(self):
        obj = self.context['object']
        request = self.context['request']

        # Global registration means this runs on every object detail page in
        # NetBox, so the allowlist check is what scopes it — and because it
        # reads the live list rather than a startup snapshot, a model registered
        # by a plugin that initialized after this one still gets its panel.
        if not self._is_assignable():
            return ''

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


# Registered without `models`, which NetBox treats as global registration: the
# class is filed under the `None` key and merged into every object detail page's
# extension list at render time.
#
# This used to build a subclass carrying `models=assignable_model_labels()`.
# That kept the panel and the allowlist in sync only for labels known at import
# time, and `register_template_extensions()` reads `models` exactly once during
# `ready()` — so a plugin registering its models from its own `ready()` got
# assignments but no panel whenever `PLUGINS` listed `netbox_openbao` first.
# The scoping now happens per render, in `CredentialsPanel._is_assignable()`,
# where the list cannot be stale.
template_extensions = [CredentialsPanel]
