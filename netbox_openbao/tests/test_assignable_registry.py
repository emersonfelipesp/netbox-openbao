"""
The plugin-facing registration API for assignable object types.

These tests exist because the registry is a *contract with other plugins*, not
an internal detail: a plugin calls `register_assignable_models()` from its
`AppConfig.ready()` and expects `CredentialAssignment` to accept its models
without the operator touching `PLUGINS_CONFIG`. The precedence between the
configured list, the registry, and the deny list is the part most likely to be
got wrong by a later change, so each edge is pinned rather than inferred.

Every test that registers something cleans it up. The registry is module-level
and process-local by design — it is rebuilt from installed code on each start —
which also means a leaked registration would silently widen the allowlist for
every test that runs afterwards, and the resulting failure would point at the
wrong test entirely.
"""

from dcim.models import Site
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from netbox_openbao import registry
from netbox_openbao.config import assignable_model_labels
from netbox_openbao.models import CredentialAssignment

from .base import OpenBaoTestCase


class RegistryCleanupMixin:
    """
    Restore the registry after each test, whatever the test did to it.

    Both sets, not just the accepted one. A leaked rejection is quieter than a
    leaked registration but no less wrong: `rejected_assignable_models()` is a
    diagnostic surface, and a test that pollutes it makes the next test's
    reading of it meaningless.
    """

    def register(self, *labels):
        self.addCleanup(
            self._restore,
            registry.registered_assignable_models(),
            registry.rejected_assignable_models(),
        )
        registry.register_assignable_models(*labels)

    @staticmethod
    def _restore(registered, rejected=None):
        with registry._lock:
            registry._registered.clear()
            registry._registered.update(registered)
            if rejected is not None:
                registry._rejected.clear()
                registry._rejected.update(rejected)


class RegistrationTest(RegistryCleanupMixin, TestCase):

    def test_registered_label_joins_the_allowlist(self):
        self.register('dcim.rack')
        self.assertIn('dcim.rack', assignable_model_labels())

    def test_registration_is_idempotent(self):
        self.register('dcim.rack', 'dcim.rack')
        self.register('dcim.rack')
        self.assertEqual(
            [label for label in assignable_model_labels() if label.startswith('dcim.rack')],
            ['dcim.rack'],
        )

    def test_labels_are_normalized(self):
        self.register('  DCIM.Rack  ')
        self.assertIn('dcim.rack', assignable_model_labels())

    def test_registered_set_is_a_copy(self):
        self.register('dcim.rack')
        returned = registry.registered_assignable_models()
        returned.add('dcim.smuggled')
        self.assertNotIn('dcim.smuggled', assignable_model_labels())


class PrecedenceTest(RegistryCleanupMixin, TestCase):

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {
        'assignable_models': ['dcim.device'],
    }})
    def test_union_of_configuration_and_registry(self):
        self.register('dcim.rack')
        self.assertEqual(
            assignable_model_labels(),
            ['dcim.device', 'dcim.rack'],
        )

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {
        'assignable_models': ['dcim.device'],
        'assignable_models_deny': ['dcim.rack'],
    }})
    def test_deny_beats_registration(self):
        """
        Registration comes from installed code, not from the operator. Without
        a subtraction an operator could not refuse an integration's choice
        without patching a plugin they did not write.
        """
        self.register('dcim.rack')
        self.assertEqual(assignable_model_labels(), ['dcim.device'])

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {
        'assignable_models': ['dcim.device', 'ipam.service'],
        'assignable_models_deny': ['ipam.service'],
    }})
    def test_deny_beats_configuration(self):
        self.assertEqual(assignable_model_labels(), ['dcim.device'])

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {}})
    def test_missing_keys_yield_the_registry_alone(self):
        """
        NetBox merges `default_settings` at startup, so a deployment that
        replaces the dict afterwards — or a test like this one — can leave every
        key absent. An allowlist that raises there is worse than one that is
        narrow.
        """
        self.register('dcim.rack')
        self.assertEqual(assignable_model_labels(), ['dcim.rack'])

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {
        'assignable_models': ['ipam.service', 'dcim.device'],
    }})
    def test_result_is_sorted(self):
        """The list is rendered into a validation message; order must be stable."""
        self.register('dcim.rack')
        self.assertEqual(
            assignable_model_labels(),
            ['dcim.device', 'dcim.rack', 'ipam.service'],
        )


class RegisteredAssignmentTest(RegistryCleanupMixin, OpenBaoTestCase):
    """
    The end the integrating plugin actually cares about: a registered model can
    hold a credential, with no change to `PLUGINS_CONFIG`.

    `dcim.site` stands in for a plugin-owned model. It is a real content type
    that is deliberately *not* in the default allowlist, so the test proves the
    registration did the work rather than the default.
    """

    def setUp(self):
        super().setUp()
        self.site = Site.objects.create(name='Site 1', slug='site-1')
        self.site_ct = ContentType.objects.get_for_model(Site)
        self.credential = self.make_credential()
        self.credential.save()

    def _assignment(self):
        return CredentialAssignment(
            credential=self.credential,
            assigned_object_type=self.site_ct,
            assigned_object_id=self.site.pk,
        )

    def test_unregistered_type_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            self._assignment().full_clean()
        self.assertIn('assigned_object_type', ctx.exception.message_dict)

    def test_registered_type_is_accepted(self):
        self.register('dcim.site')
        assignment = self._assignment()
        assignment.full_clean()
        assignment.save()
        self.assertEqual(assignment.assigned_object, self.site)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {
        'assignable_models': ['dcim.device'],
        'assignable_models_deny': ['dcim.site'],
    }})
    def test_denied_type_is_rejected_even_when_registered(self):
        self.register('dcim.site')
        with self.assertRaises(ValidationError) as ctx:
            self._assignment().full_clean()
        self.assertIn('assigned_object_type', ctx.exception.message_dict)

    def test_rejection_message_names_the_permitted_types(self):
        """
        An operator who hits this error has no other way to discover what the
        resolved allowlist is — it is the union of a settings key they may not
        have set and a registry populated by code they did not write.
        """
        with self.assertRaises(ValidationError) as ctx:
            self._assignment().full_clean()
        message = ' '.join(ctx.exception.message_dict['assigned_object_type'])
        self.assertIn('dcim.device', message)


class MalformedRegistrationTest(RegistryCleanupMixin, TestCase):
    """
    A plugin's typo must be findable, and must not take NetBox down.

    Both halves matter. Silently dropping `my_plguin.endpoint` leaves a broken
    integration indistinguishable from one that was never configured, and the
    operator discovers it later through an assignment that will not save.
    Raising instead would be worse: this runs inside `AppConfig.ready()`, where
    an exception does not fail one integration but takes the whole instance
    down at startup — including the UI needed to diagnose it.
    """

    def test_a_malformed_label_never_reaches_the_allowlist(self):
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR'):
            self.register('not-a-label', 'dcim.rack')

        labels = assignable_model_labels()
        self.assertIn('dcim.rack', labels)
        self.assertNotIn('not-a-label', labels)

    def test_a_rejection_is_logged_with_the_offending_value(self):
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR') as logs:
            self.register('MyPlugin::Endpoint')

        self.assertIn('MyPlugin::Endpoint', '\n'.join(logs.output))

    def test_rejections_are_retrievable_for_a_diagnostic(self):
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR'):
            self.register('nodot', 'dcim.rack')

        self.assertIn('nodot', registry.rejected_assignable_models())

    def test_non_strings_and_blanks_are_rejected_not_silently_dropped(self):
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR') as logs:
            self.register('', '   ', None, 42)

        self.assertEqual(registry.registered_assignable_models(), set())
        self.assertIn('ignored 4 invalid', '\n'.join(logs.output))

    def test_a_well_formed_typo_is_rejected(self):
        """
        The case shape validation cannot catch, and the reason the app-registry
        lookup exists. `dcim.rakc` is a perfectly good `app_label.model` string
        and names nothing — accepted, it would leave a broken integration
        indistinguishable from one nobody configured.
        """
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR') as logs:
            self.register('dcim.rakc')

        self.assertNotIn('dcim.rakc', assignable_model_labels())
        self.assertIn('dcim.rakc', registry.rejected_assignable_models())
        self.assertIn('dcim.rakc', '\n'.join(logs.output))

    def test_an_unknown_app_is_rejected(self):
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR'):
            self.register('no_such_plugin.endpoint')

        self.assertNotIn('no_such_plugin.endpoint', assignable_model_labels())

    def test_registration_never_raises(self):
        """`ready()` must survive whatever a plugin hands it."""
        with self.assertLogs('netbox.plugins.netbox_openbao', level='ERROR'):
            self.register(None, 42, '', 'Bad.Label!', ['nested'])

    def test_a_valid_registration_logs_nothing(self):
        with self.assertNoLogs('netbox.plugins.netbox_openbao', level='ERROR'):
            self.register('dcim.rack')


class SiteProxy(Site):
    """
    A proxy of an allowed concrete model, for the panel's label resolution.

    Defined at module scope on purpose. Django registers a model with the app
    registry when its class body executes, so defining this inside a test method
    raises `RuntimeError: Conflicting 'siteproxy' models in application 'dcim'`
    the second time the module is imported in one process — which is every
    re-run under a runner that does not fork.
    """

    class Meta:
        proxy = True
        app_label = 'dcim'


class PanelRegistrationTest(TestCase):
    """
    The panel must not be scoped from a startup snapshot of the allowlist.

    NetBox's `register_template_extensions()` reads `models` exactly once,
    during the owning plugin's `ready()`. A panel built from
    `assignable_model_labels()` at import time therefore froze the list — and a
    model registered by a plugin that initialized later was permitted to hold
    assignments while getting no panel, purely because of where `netbox_openbao`
    sat in `PLUGINS`. Same configuration, different UI, no error.
    """

    def test_the_panel_is_registered_globally(self):
        from netbox_openbao.template_content import CredentialsPanel, template_extensions

        self.assertEqual(template_extensions, [CredentialsPanel])
        self.assertFalse(
            getattr(CredentialsPanel, 'models', None),
            'A `models` list would be read once at ready() and freeze the allowlist, '
            'which is the ordering bug this registration shape exists to avoid.',
        )

    def test_a_proxy_model_uses_its_concrete_content_type(self):
        """
        The render gate and the assignment query must agree.

        `ContentType.objects.get_for_model()` resolves a proxy to its concrete
        model by default, so a proxy's assignments are filed under the concrete
        label while `obj._meta` reports the proxy's own. Gating on `_meta` meant
        a proxy of an allowed model had valid assignments and never rendered a
        panel.
        """
        from netbox_openbao.template_content import CredentialsPanel

        site = Site.objects.create(name='Proxy Site', slug='proxy-site')
        proxied = SiteProxy.objects.get(pk=site.pk)

        self.assertEqual(
            CredentialsPanel._canonical_label(proxied),
            CredentialsPanel._canonical_label(site),
            'A proxy must resolve to the same label as its concrete model, or the '
            'panel gate and the assignment query disagree.',
        )
        self.assertEqual(CredentialsPanel._canonical_label(proxied), 'dcim.site')

    def test_the_panel_consults_the_live_allowlist(self):
        """
        The property that actually matters: scoping is decided per render, so a
        late registration still gets a panel.
        """
        from netbox_openbao.template_content import CredentialsPanel

        site = Site.objects.create(name='Panel Site', slug='panel-site')
        panel = CredentialsPanel({'object': site, 'request': None})

        self.assertFalse(panel._is_assignable())

        before = registry.registered_assignable_models()
        self.addCleanup(RegistryCleanupMixin._restore, before)
        registry.register_assignable_models('dcim.site')

        self.assertTrue(panel._is_assignable())
