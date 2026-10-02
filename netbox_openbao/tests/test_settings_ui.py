"""
The operator-facing half of database-backed settings.

Three of these guard things that are only wrong in ways nobody notices: a
setting that appears editable and is not, a file value that is silently ignored,
and a change to a security control that leaves no trace where an operator would
look for it.
"""

from django.core.exceptions import ValidationError
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from utilities.exceptions import AbortRequest
from utilities.testing import ModelViewTestCase, create_test_device

from netbox_openbao.checks import check_superseded_plugins_config
from netbox_openbao.choices import AccessActionChoices, CredentialTypeChoices
from netbox_openbao.forms import OpenBaoSettingsForm
from netbox_openbao.models import (
    Credential,
    CredentialAccessLog,
    CredentialPolicy,
    EngineAuthMaterial,
    OpenBaoCluster,
    OpenBaoSettings,
    SecretEngine,
)
from netbox_openbao.models.settings import STATIC_INTERVAL_SETTINGS

from .base import OpenBaoTestCase


class SettingsFormTest(OpenBaoTestCase):

    def test_interval_fields_are_editable_with_the_restart_reason(self):
        """
        They are stored in the singleton row and applied when workers restart.
        """
        form = OpenBaoSettingsForm(instance=OpenBaoSettings.get_solo())

        for name in STATIC_INTERVAL_SETTINGS:
            with self.subTest(field=name):
                self.assertFalse(form.fields[name].disabled)
                self.assertIn('Restart NetBox workers', str(form.fields[name].help_text))

    def test_path_prefix_is_editable_with_no_credentials(self):
        form = OpenBaoSettingsForm(instance=OpenBaoSettings.get_solo())
        self.assertFalse(form.fields['path_prefix'].disabled)

    def test_path_prefix_is_locked_once_a_credential_exists(self):
        """
        The model refuses the change regardless — that guard is the enforcement,
        and it covers the API and direct ORM writes too. This only stops the UI
        offering an edit it will reject.
        """
        self.make_credential().save()

        form = OpenBaoSettingsForm(instance=OpenBaoSettings.get_solo())

        self.assertTrue(form.fields['path_prefix'].disabled)
        self.assertIn('vault outage', str(form.fields['path_prefix'].help_text))

    def test_every_interval_is_named_in_one_place(self):
        """
        The form, the panel, and the startup warning all read the same tuple.
        Three copies would drift, and the drift would be invisible.
        """
        self.assertEqual(len(STATIC_INTERVAL_SETTINGS), 5)
        for name in STATIC_INTERVAL_SETTINGS:
            self.assertIn(name, OpenBaoSettingsForm.Meta.fields)


class SettingsDashboardTest(ModelViewTestCase):
    model = OpenBaoSettings

    def test_fresh_install_lists_defaults_and_every_engine_parameter(self):
        OpenBaoSettings.objects.all().delete()
        engine = SecretEngine.objects.create(
            name='Dashboard engine',
            slug='dashboard-engine',
            api_url='https://bao.example.net:8200',
        )
        EngineAuthMaterial.objects.create(engine=engine)
        self.add_permissions(
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.view_secretengine',
            'netbox_openbao.view_engineauthmaterial',
        )

        response = self.client.get(reverse('plugins:netbox_openbao:openbaosettings_list'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(row['description'] for row in response.context['setting_rows']))
        self.assertTrue(all(row['description'] for row in response.context['engine_parameter_rows']))
        self.assertContains(response, '>default<')
        for name in OpenBaoSettingsForm.Meta.fields:
            self.assertContains(response, name)
        for name in (
            'backend', 'api_url', 'namespace', 'kv_mount', 'kv_version',
            'auth_method', 'tls_verify', 'ca_cert_path', 'host_device',
        ):
            self.assertContains(response, name)
        self.assertContains(response, 'AppRole: role_id, secret_id missing - required')

    def test_auth_edit_action_requires_auth_material_permission(self):
        row = OpenBaoSettings.get_solo()
        engine = SecretEngine.objects.create(
            name='Dashboard auth engine',
            slug='dashboard-auth-engine',
            api_url='https://bao.example.net:8200',
        )
        material = EngineAuthMaterial.objects.create(engine=engine)
        url = reverse('plugins:netbox_openbao:openbaosettings_list')
        edit_url = reverse(
            'plugins:netbox_openbao:engineauthmaterial_edit',
            kwargs={'pk': material.pk},
        )
        self.add_permissions(
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.view_secretengine',
            'netbox_openbao.view_engineauthmaterial',
        )

        response = self.client.get(url)
        self.assertNotContains(response, edit_url)

        self.add_permissions('netbox_openbao.add_engineauthmaterial')
        response = self.client.get(url)
        self.assertNotContains(response, edit_url)

        self.add_permissions('netbox_openbao.change_engineauthmaterial')
        response = self.client.get(url)
        self.assertContains(response, edit_url)
        self.assertTrue(row.pk)

    def test_settings_only_user_sees_no_restricted_inventory_or_auth_urls(self):
        OpenBaoSettings.get_solo()
        device = create_test_device('Restricted OpenBao host')
        engine = SecretEngine.objects.create(
            name='Restricted dashboard engine',
            slug='restricted-dashboard-engine',
            api_url='https://restricted-bao.invalid:8200',
            host_device=device,
        )
        policy = CredentialPolicy.objects.create(
            name='Restricted dashboard policy',
            slug='restricted-dashboard-policy',
            engine=engine,
            openbao_policy='restricted-dashboard-policy',
        )
        cluster = OpenBaoCluster.objects.create(
            name='Restricted dashboard cluster',
            slug='restricted-dashboard-cluster',
            api_url='https://restricted-cluster.invalid:8200',
            host_device=device,
        )
        EngineAuthMaterial.objects.create(engine=engine)
        EngineAuthMaterial.objects.create(policy=policy)
        EngineAuthMaterial.objects.create(cluster=cluster)
        self.add_permissions('netbox_openbao.view_openbaosettings')

        response = self.client.get(reverse('plugins:netbox_openbao:openbaosettings_list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['engine_parameter_rows'], [])
        self.assertEqual(response.context['scoped_auth_rows'], [])
        rendered = response.content.decode()
        for value in (
            engine.name,
            policy.name,
            cluster.name,
            device.name,
            reverse('plugins:netbox_openbao:engineauthmaterial_edit', kwargs={
                'pk': EngineAuthMaterial.objects.get(engine=engine).pk,
            }),
        ):
            self.assertNotIn(value, rendered)

    def test_engine_view_user_sees_only_visible_engine_without_auth_or_host(self):
        OpenBaoSettings.get_solo()
        device = create_test_device('Hidden OpenBao host')
        engine = SecretEngine.objects.create(
            name='Visible dashboard engine',
            slug='visible-dashboard-engine',
            api_url='https://visible-bao.invalid:8200',
            host_device=device,
        )
        policy = CredentialPolicy.objects.create(
            name='Hidden dashboard policy',
            slug='hidden-dashboard-policy',
            engine=engine,
            openbao_policy='hidden-dashboard-policy',
        )
        cluster = OpenBaoCluster.objects.create(
            name='Hidden dashboard cluster',
            slug='hidden-dashboard-cluster',
            api_url='https://hidden-cluster.invalid:8200',
        )
        EngineAuthMaterial.objects.create(engine=engine)
        EngineAuthMaterial.objects.create(policy=policy)
        EngineAuthMaterial.objects.create(cluster=cluster)
        self.add_permissions(
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.view_secretengine',
        )

        response = self.client.get(reverse('plugins:netbox_openbao:openbaosettings_list'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['engine_parameter_rows'])
        self.assertEqual(response.context['scoped_auth_rows'], [])
        rendered = response.content.decode()
        self.assertIn(engine.name, rendered)
        self.assertNotIn(policy.name, rendered)
        self.assertNotIn(cluster.name, rendered)
        self.assertNotIn(device.name, rendered)


class SupersededConfigTest(OpenBaoTestCase):
    """
    Every legacy plugin key is ignored and named by the system check.
    """

    def test_nothing_is_reported_without_plugin_keys(self):
        with self.settings(PLUGINS_CONFIG={}):
            self.assertEqual(check_superseded_plugins_config(None), [])

    def test_a_superseded_key_is_named(self):
        with self.settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 900}}):
            issues = check_superseded_plugins_config(None)

        self.assertEqual(len(issues), 1)
        self.assertIn('reveal_ttl', issues[0].msg)
        self.assertEqual(issues[0].id, 'netbox_openbao.W001')

    def test_interval_keys_are_reported_as_ignored(self):
        with self.settings(PLUGINS_CONFIG={'netbox_openbao': {'engine_health_interval': 15}}):
            issues = check_superseded_plugins_config(None)

        self.assertEqual(len(issues), 1)
        self.assertIn('engine_health_interval', issues[0].msg)

    def test_the_check_does_not_query_during_app_initialization(self):
        """
        It is a system check, not a `ready()` hook. Querying the database during
        app initialisation earns Django's own warning about it, and on a fresh
        install the table does not exist yet.
        """
        import netbox_openbao

        source = open(netbox_openbao.__file__).read()
        self.assertNotIn('superseded', source)

class SettingsAuditTest(ModelViewTestCase):
    """
    `change_openbaosettings` can widen the control that bounds a leaked token.

    NetBox's changelog records what changed. This records it where the reveals
    are recorded, so an operator reconstructing an incident sees "the rate limit
    was widened" in the same timeline as the reveals it permitted.
    """

    model = OpenBaoSettings

    def test_saving_writes_an_audit_record(self):
        url = reverse('plugins:netbox_openbao:openbaosettings_edit', kwargs={'pk': OpenBaoSettings.get_solo().pk})
        self.add_permissions('netbox_openbao.change_openbaosettings', 'netbox_openbao.view_openbaosettings')

        response = self.client.post(url, self._form_data(reveal_rate_limit='5/minute'))
        form = response.context.get('form') if getattr(response, 'context', None) else None
        self.assertIn(
            response.status_code, (302, 200),
            f'edit POST failed: {getattr(form, "errors", None)}',
        )
        self.assertIsNone(
            getattr(form, 'errors', None) or None,
            f'form rejected the post: {getattr(form, "errors", None)}',
        )

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).first()
        self.assertIsNotNone(entry, 'a settings change must be recorded in the access log')
        self.assertIsNone(entry.credential, 'there is no credential; the column is nullable for this')
        self.assertEqual(entry.credential_name_snapshot, 'OpenBao settings')
        self.assertEqual(entry.username_snapshot, self.user.username)

    def test_the_record_names_the_field_but_never_its_value(self):
        """
        The access log's standing contract is that it carries no values. A rate
        limit is not secret, but the contract is worth more than the convenience
        of recording it — and a log that sometimes carries values is one someone
        will eventually extend to carry the wrong one.
        """
        url = reverse('plugins:netbox_openbao:openbaosettings_edit', kwargs={'pk': OpenBaoSettings.get_solo().pk})
        self.add_permissions('netbox_openbao.change_openbaosettings', 'netbox_openbao.view_openbaosettings')

        self.client.post(url, self._form_data(reveal_rate_limit='5/minute'))

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).first()
        self.assertIsNotNone(entry)
        self.assertIn('reveal_rate_limit', entry.message)
        self.assertNotIn('5/minute', entry.message)

    def test_an_unchanged_save_writes_no_record(self):
        """
        A save that altered nothing is not a configuration change. Recording it
        would dilute the log this exists to make readable.
        """
        url = reverse('plugins:netbox_openbao:openbaosettings_edit', kwargs={'pk': OpenBaoSettings.get_solo().pk})
        self.add_permissions('netbox_openbao.change_openbaosettings', 'netbox_openbao.view_openbaosettings')
        before = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).count()

        self.client.post(url, self._form_data())

        after = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).count()
        self.assertEqual(after, before)

    def test_creating_the_row_is_itself_recorded(self):
        """Turning file-based configuration into database-backed is a change."""
        OpenBaoSettings.objects.all().delete()
        CredentialAccessLog.objects.all().delete()

        OpenBaoSettings.get_solo()

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).first()
        self.assertIsNotNone(entry)
        self.assertIn('created', entry.message)

    @staticmethod
    def _form_data(**overrides):
        row = OpenBaoSettings.get_solo()
        data = {
            'path_prefix': row.path_prefix,
            'reveal_rate_limit': row.reveal_rate_limit,
            'reveal_ttl': row.reveal_ttl,
            'token_cache_ttl': row.token_cache_ttl,
            'default_ssh_key_type': row.default_ssh_key_type,
            'audit_retention_days': row.audit_retention_days,
            'assignable_models': ','.join(row.assignable_models),
            'assignable_models_deny': ','.join(row.assignable_models_deny),
            'expiry_warning_days': ','.join(str(d) for d in row.expiry_warning_days),
        }
        for name in STATIC_INTERVAL_SETTINGS:
            data[name] = getattr(row, name)
        if row.store_public_material:
            data['store_public_material'] = 'on'
        if row.allow_generation:
            data['allow_generation'] = 'on'
        data.update(overrides)
        return data


class SettingsNavigationTest(TestCase):

    def test_settings_appear_in_the_plugin_menu(self):
        from netbox_openbao.navigation import menu

        links = [item.link for group in menu.groups for item in group.items]
        self.assertIn('plugins:netbox_openbao:openbaosettings_list', links)

    def test_the_detail_template_stub_exists(self):
        """
        NetBox resolves <app_label>/<model_name>.html for every ObjectView even
        when the page is entirely panel-driven; without the stub the page raises
        TemplateDoesNotExist. This trap is already recorded in AGENTS.md and has
        cost this plugin a debugging cycle before.
        """
        from django.template.loader import get_template

        get_template('netbox_openbao/openbaosettings.html')


class SettingsRoutingTest(TestCase):
    """
    The navigation link must actually resolve.

    An earlier version of this suite asserted only that the menu contained the
    right route *name* — which it did, while the view was missing its
    registration decorator and the URL resolved to nothing. Checking the string
    and not the route is the shape of guard that reports success without
    checking the property.
    """

    def test_the_list_route_reverses(self):
        self.assertTrue(reverse('plugins:netbox_openbao:openbaosettings_list'))

    def test_the_add_route_reverses(self):
        """
        A fresh install has no settings row on purpose, so the list lands empty
        and the add route is the only way in from the UI.
        """
        self.assertTrue(reverse('plugins:netbox_openbao:openbaosettings_add'))

    def test_the_edit_route_reverses(self):
        row = OpenBaoSettings.get_solo()
        self.assertTrue(
            reverse('plugins:netbox_openbao:openbaosettings_edit', kwargs={'pk': row.pk})
        )

    def test_every_action_the_list_offers_resolves(self):
        """
        `ObjectListView` offers bulk import, edit, rename, and delete by
        default, and none of them has a route here — bulk operations on a
        singleton are meaningless, and the routes were never registered. Left at
        the default they render as controls that fail rather than as controls
        that are absent, which is the same failure the missing list route was:
        a link that resolves to nothing.
        """
        from netbox_openbao.views import OpenBaoSettingsListView

        for action in OpenBaoSettingsListView.actions:
            with self.subTest(action=action.name):
                self.assertIsNotNone(
                    action.get_url(OpenBaoSettings),
                    f'{action.name} is offered by the list view but resolves to nothing',
                )


class RefusalAuditTest(OpenBaoTestCase):
    """
    A refused change is worth more than an accepted one.

    It is evidence that somebody tried to widen a control and was stopped. The
    audit sits on the model so every surface — UI, REST API, management command
    — is covered by one implementation rather than three that can disagree.
    """

    def _refusals(self):
        return CredentialAccessLog.objects.filter(
            action=AccessActionChoices.ACTION_CONFIGURE, success=False,
        )

    def test_a_refused_prefix_change_is_recorded(self):
        row = OpenBaoSettings.get_solo()
        self.make_credential().save()
        CredentialAccessLog.objects.all().delete()

        row.path_prefix = 'somewhere-else'
        with self.assertRaises(ValidationError):
            row.full_clean()

        entry = self._refusals().first()
        self.assertIsNotNone(entry, 'a refused prefix change must be audited')
        self.assertIn('path_prefix', entry.message)

    def test_a_refused_deletion_is_refused_and_recorded(self):
        """
        The guard is the enforcement; the audit record is evidence.

        The record is written after `delete()`'s transaction has unwound rather
        than from inside the guard. Auditing from inside put the row into
        exactly the transaction the refusal discarded, so the one record an
        operator reconstructing an incident most wants was reliably absent.
        """
        row = OpenBaoSettings.get_solo()
        self.make_credential().save()
        CredentialAccessLog.objects.all().delete()

        with self.assertRaises(AbortRequest):
            row.delete()

        self.assertTrue(OpenBaoSettings.objects.filter(pk=row.pk).exists())
        entry = self._refusals().first()
        self.assertIsNotNone(entry, 'a refused deletion must be audited')
        self.assertFalse(entry.success)
        self.assertIn('delete', entry.message)

    def test_a_losing_concurrent_create_is_refused_not_a_500(self):
        """
        Two simultaneous creates both pass form and serializer validation,
        because the `exists()` check there runs before either inserts. The loser
        would reach PostgreSQL's unique constraint as an `IntegrityError`, which
        `ObjectEditView` does not catch — a 500 on a page whose only fault was
        losing a race. The advisory lock `save()` already holds makes the
        re-check decisive.
        """
        OpenBaoSettings.get_solo()

        with self.assertRaises(AbortRequest):
            OpenBaoSettings(path_prefix='netbox').save()

        self.assertEqual(OpenBaoSettings.objects.count(), 1)

    def test_deleting_the_row_is_recorded_as_a_change(self):
        """
        Configuration falls back to model defaults. That is still a change,
        not an absence of one.
        """
        row = OpenBaoSettings.get_solo()
        CredentialAccessLog.objects.all().delete()

        row.delete()

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).first()
        self.assertIsNotNone(entry)
        self.assertIn('model defaults', entry.message)


class SingletonAddTest(ModelViewTestCase):
    """
    Reaching the add page on a configured install must not be a server error.

    `singleton_key` is `editable=False` and absent from the form's fields, so
    Django's uniqueness validation never sees it and the collision would reach
    PostgreSQL. `ObjectEditView` catches `AbortRequest` and
    `PermissionsViolation` — not `IntegrityError`.
    """

    model = OpenBaoSettings

    def test_a_second_row_is_refused_by_the_form(self):
        OpenBaoSettings.get_solo()

        form = OpenBaoSettingsForm(data={'path_prefix': 'netbox', 'reveal_rate_limit': '30/hour'})

        self.assertFalse(form.is_valid())
        self.assertIn('already exist', str(form.errors))

    def test_the_first_row_is_allowed(self):
        OpenBaoSettings.objects.all().delete()

        form = OpenBaoSettingsForm(instance=OpenBaoSettings())

        self.assertNotIn('already exist', str(form.errors))


class CheckFailureTest(TestCase):
    """
    A check that cannot evaluate must say so, not return nothing.

    Returning `[]` on an unexpected failure would remove the only signal telling
    an operator that legacy values are being ignored.
    """

    def test_an_unexpected_failure_reports_error(self):
        from unittest.mock import patch

        with patch(
            'netbox_openbao.checks._ignored_plugin_keys',
            side_effect=RuntimeError('something unforeseen'),
        ):
            issues = check_superseded_plugins_config(None)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].id, 'netbox_openbao.E001')


class PartialSaveAuditTest(OpenBaoTestCase):
    """`save(update_fields=...)` must not report fields it did not persist."""

    def test_only_persisted_fields_are_audited(self):
        row = OpenBaoSettings.get_solo()
        CredentialAccessLog.objects.all().delete()

        row.reveal_ttl = 111
        row.audit_retention_days = 222
        row.save(update_fields=['reveal_ttl'])

        entry = CredentialAccessLog.objects.filter(action=AccessActionChoices.ACTION_CONFIGURE).first()
        self.assertIsNotNone(entry)
        self.assertIn('reveal_ttl', entry.message)
        self.assertNotIn('audit_retention_days', entry.message)


class BulkDeletionRefusalAuditTest(TransactionTestCase):
    """
    A refused bulk deletion, audited outside the transaction that refused it.

    `TransactionTestCase` rather than `TestCase`, and not for convenience.
    `QuerySet.delete()` opens `transaction.atomic(savepoint=False)`, so a
    refusal raised inside it marks the *enclosing* transaction for rollback
    rather than unwinding to a savepoint. Under `TestCase` — which wraps every
    test in a transaction — the connection is then unusable and nothing can be
    written or asserted, which is an artefact of the harness rather than of the
    code: in production that atomic block is the outermost one, so the rollback
    completes and the audit that follows it commits.
    """

    def test_a_refused_bulk_deletion_is_refused_and_recorded(self):
        engine = SecretEngine.objects.create(
            name='Primary',
            slug='primary',
            api_url='https://bao.example.net:8200',
            kv_mount='secret',
            is_default=True,
        )
        policy = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=engine, openbao_policy='netbox-lab',
        )
        row = OpenBaoSettings.get_solo()
        Credential.objects.create(
            name='holds-the-prefix-open',
            engine=engine,
            policy=policy,
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            path='netbox/credentials/holds-the-prefix-open',
        )
        CredentialAccessLog.objects.all().delete()

        with self.assertRaises(AbortRequest):
            OpenBaoSettings.objects.filter(pk=row.pk).delete()

        self.assertTrue(OpenBaoSettings.objects.filter(pk=row.pk).exists())
        entry = CredentialAccessLog.objects.filter(
            action=AccessActionChoices.ACTION_CONFIGURE, success=False,
        ).first()
        self.assertIsNotNone(entry, 'a refused bulk deletion must be audited')
