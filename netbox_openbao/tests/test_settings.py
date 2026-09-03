"""
The settings row, and the read path that resolves it.

The whole point of this layer is that it changes *where* configuration comes
from without changing what any of the seventeen callers observe. So most of
these tests are about the fallback chain and about what must **not** happen: a
read must not create a row, a missing row must not become a query per key, and a
saved change must not be invisible to the thread that did not save it.
"""

import importlib
from datetime import timedelta
from queue import Queue
from threading import Barrier, Event, Thread
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dcim.models import Site
from django.apps import apps
from django.core.exceptions import FieldDoesNotExist
from django.db import close_old_connections, transaction
from django.db.utils import IntegrityError
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient
from utilities.exceptions import AbortRequest
from utilities.testing import APITestCase

from netbox_openbao import config as config_module
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.config import (
    MODEL_BACKED_SETTINGS,
    assignable_model_labels,
    clear_config,
    get_config,
)
from netbox_openbao.middleware import SettingsCacheMiddleware
from netbox_openbao.models import Credential, CredentialPolicy, OpenBaoSettings, SecretEngine

from .base import OpenBaoTestCase


class SettingsTestCase(TestCase):
    """Every test starts without a thread-local settings snapshot."""

    def setUp(self):
        super().setUp()
        self._reset()
        self.addCleanup(self._reset)

    @staticmethod
    def _reset():
        clear_config()


class SettingsTransactionTestCase(TransactionTestCase):
    """Run transaction-boundary tests without TestCase's implicit outer transaction."""

    def setUp(self):
        super().setUp()
        clear_config()

    def tearDown(self):
        clear_config()
        super().tearDown()


class FallbackChainTest(SettingsTestCase):
    """
    No row means the deployment's `PLUGINS_CONFIG` still decides.

    This is the compatibility guarantee. Nineteen existing tests across six
    files use `override_settings` to configure this plugin, and they are
    expected to keep passing untouched — if this chain breaks they do not fail,
    they quietly start asserting against defaults.
    """

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 900}})
    def test_plugins_config_is_used_when_no_row_exists(self):
        self.assertEqual(get_config('reveal_ttl'), 900)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {}})
    def test_default_is_used_when_neither_row_nor_config_has_the_key(self):
        self.assertEqual(get_config('reveal_ttl', 300), 300)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': None}})
    def test_a_null_resolves_to_the_default(self):
        """
        Preserved from the previous implementation, and load-bearing.
        `get_plugin_config()` returns None rather than raising for a key absent
        from the merged result, which once turned `store_public_material` off
        silently and looked exactly like the extractors failing.
        """
        self.assertEqual(get_config('reveal_ttl', 300), 300)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 900}})
    def test_the_row_wins_over_plugins_config(self):
        OpenBaoSettings.get_solo()
        OpenBaoSettings.objects.update(reveal_ttl=1200)
        clear_config()

        self.assertEqual(get_config('reveal_ttl'), 1200)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {}})
    def test_the_row_supplies_every_non_interval_setting(self):
        values = {
            'path_prefix': 'database',
            'assignable_models': ['dcim.site'],
            'assignable_models_deny': ['dcim.rack'],
            'store_public_material': False,
            'reveal_rate_limit': '7/minute',
            'reveal_ttl': 601,
            'token_cache_ttl': 602,
            'audit_retention_days': 603,
            'allow_generation': False,
            'default_ssh_key_type': 'rsa-4096',
            'expiry_warning_days': [45, 10],
        }
        OpenBaoSettings.objects.create(**values)

        for key, expected in values.items():
            self.assertEqual(get_config(key), expected, key)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'engine_health_interval': 17}})
    def test_job_intervals_deliberately_remain_static(self):
        from netbox_openbao.jobs import _static_job_interval

        OpenBaoSettings.objects.create(engine_health_interval=999)
        self.assertEqual(_static_job_interval('engine_health_interval', 5), 17)


class ReadNeverCreatesTest(SettingsTestCase):
    """
    A read must leave a missing row missing.

    If a read created it, that row would win from then on, `PLUGINS_CONFIG`
    would be unreachable, and every `override_settings` test in this suite would
    pass while testing nothing. Creation belongs to the migration and to an
    explicit save.
    """

    def test_reading_does_not_create_the_row(self):
        get_config('reveal_ttl')
        get_config('path_prefix')
        assignable_model_labels()

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_get_solo_does_create_it(self):
        """The explicit write path is allowed to, and is the only one that is."""
        OpenBaoSettings.get_solo()
        self.assertEqual(OpenBaoSettings.objects.count(), 1)

    def test_get_solo_is_idempotent(self):
        first = OpenBaoSettings.get_solo()
        second = OpenBaoSettings.get_solo()

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(OpenBaoSettings.objects.count(), 1)


class QueryCountTest(SettingsTestCase):
    """
    Reading configuration must not scale with the number of keys read.

    `assignable_model_labels()` runs on every object detail page in NetBox — the
    credentials panel is registered globally and scoped per render — plus every
    assignment save and every reveal. One query per key would put several extra
    queries on every page in the estate.
    """

    def test_many_reads_cost_at_most_one_query(self):
        with self.assertNumQueries(1):
            get_config('reveal_ttl')
            get_config('path_prefix')
            get_config('store_public_material')
            get_config('allow_generation')
            assignable_model_labels()

    def test_a_missing_row_costs_one_query_for_all_keys_in_a_request(self):
        """
        The `_MISSING` sentinel exists for this: an empty result is a real
        answer, and confusing it with an uninitialised memo would re-query on every
        single page render — the exact cost this layer is meant to avoid.
        """
        with self.assertNumQueries(1):
            get_config('reveal_ttl')
            get_config('path_prefix')
            get_config('allow_generation')

    def test_two_requests_each_load_the_row_once(self):
        with self.assertNumQueries(2):
            get_config('reveal_ttl')
            clear_config()
            get_config('reveal_ttl')

    def test_the_panel_render_check_does_not_query_per_key(self):
        """The globally registered panel is the hot path behind the limit."""
        from netbox_openbao.template_content import CredentialsPanel

        site = Site.objects.create(name='Settings Query Site', slug='settings-query-site')
        panel = CredentialsPanel({'object': site, 'request': None})
        # Warm Django's independent ContentType cache so this assertion measures
        # only the settings layer used by the panel's per-render allowlist gate.
        panel._canonical_label(site)

        with self.assertNumQueries(1):
            panel._is_assignable()
            panel._is_assignable()


class CacheInvalidationTest(SettingsTransactionTestCase):

    def test_a_writer_sees_its_own_uncommitted_change(self):
        """
        A `post_save` receiver fires before its transaction commits, so the
        writing thread must not be left reading the old value for the rest of
        the request.
        """
        settings_row = OpenBaoSettings.get_solo()
        clear_config()
        self.assertEqual(get_config('reveal_ttl'), 300)

        with transaction.atomic():
            settings_row.reveal_ttl = 1500
            settings_row.save()
            self.assertEqual(get_config('reveal_ttl'), 1500)

        self.assertEqual(get_config('reveal_ttl'), 1500)

    def test_a_rolled_back_write_is_not_left_memoised(self):
        """
        The case there is no Django hook for. A write inside a transaction that
        later rolls back must not leave its value memoised on this thread —
        `on_commit` simply never runs, so nothing would clear it.

        Deliberately does not clear the memo by hand before asserting: doing so
        is exactly the state under test, and an earlier version of this test hid
        the defect that way.
        """
        settings_row = OpenBaoSettings.get_solo()
        clear_config()
        self.assertEqual(get_config('reveal_ttl'), 300)

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                settings_row.reveal_ttl = 1500
                settings_row.save()
                self.assertEqual(get_config('reveal_ttl'), 1500)
                raise RuntimeError('roll back the settings write')

        self.assertEqual(get_config('reveal_ttl'), 300)

    def test_saving_makes_the_new_value_visible(self):
        settings_row = OpenBaoSettings.get_solo()
        get_config('reveal_ttl')

        settings_row.reveal_ttl = 1500
        settings_row.save()

        self.assertEqual(get_config('reveal_ttl'), 1500)

    def test_deleting_restores_the_fallback(self):
        settings_row = OpenBaoSettings.get_solo()
        settings_row.reveal_ttl = 1500
        settings_row.save()
        self.assertEqual(get_config('reveal_ttl'), 1500)

        settings_row.delete()

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 42}}):
            self.assertEqual(get_config('reveal_ttl'), 42)


class MiddlewareTest(SettingsTestCase):
    """
    The thread-local memo must not outlive the request that made it.

    Without this the memo lives for the life of the worker thread. An operator
    changing a setting would see it applied on whichever thread served the save
    and stale on every other one, forever, with nothing logged and nothing to
    suggest the save had not taken.
    """

    def test_the_memo_is_discarded_after_a_response(self):
        get_config('reveal_ttl')
        self.assertTrue(hasattr(config_module._thread_locals, 'config'))

        SettingsCacheMiddleware(lambda request: 'response')(RequestFactory().get('/'))

        self.assertFalse(hasattr(config_module._thread_locals, 'config'))

    def test_the_memo_is_discarded_even_when_the_view_raises(self):
        """
        A `finally`, not a call after `get_response`. A raising view is the case
        where a stale read afterwards is most likely to be blamed on something
        else entirely.
        """
        def boom(request):
            raise ValueError('view failed')

        get_config('reveal_ttl')
        with self.assertRaises(ValueError):
            SettingsCacheMiddleware(boom)(RequestFactory().get('/'))

        self.assertFalse(hasattr(config_module._thread_locals, 'config'))

    def test_the_middleware_is_declared_on_the_plugin_config(self):
        """
        Declared rather than documented. `PluginConfig.middleware` is appended
        to `MIDDLEWARE` by NetBox at startup, so an operator installs nothing —
        and a change that drops the declaration would otherwise reintroduce the
        staleness silently.
        """
        from netbox_openbao import NetBoxOpenBaoConfig

        self.assertIn(
            'netbox_openbao.middleware.SettingsCacheMiddleware',
            NetBoxOpenBaoConfig.middleware,
        )


class RateLimitValidationTest(SettingsTestCase):
    """
    An unparseable rate must be refused at save, not at the next reveal.

    The throttle reads this on the reveal path. A bad value stored here would
    surface as a failed credential reveal — at which point the rate limit is the
    last place anyone looks.
    """

    def test_a_valid_rate_is_accepted(self):
        row = OpenBaoSettings.get_solo()
        row.reveal_rate_limit = '10/minute'
        row.full_clean()

    def test_an_unparseable_rate_is_refused(self):
        from django.core.exceptions import ValidationError

        row = OpenBaoSettings.get_solo()
        row.reveal_rate_limit = 'thirty per hour'
        with self.assertRaises(ValidationError) as ctx:
            row.full_clean()
        self.assertIn('reveal_rate_limit', ctx.exception.message_dict)


class ModelShapeTest(SettingsTestCase):

    def test_database_enforces_the_singleton(self):
        OpenBaoSettings.objects.create()
        with self.assertRaises(IntegrityError):
            OpenBaoSettings.objects.create()

    def test_model_backed_defaults_match_plugin_defaults(self):
        from netbox_openbao import NetBoxOpenBaoConfig

        row = OpenBaoSettings()
        for key in MODEL_BACKED_SETTINGS:
            self.assertEqual(
                getattr(row, key),
                NetBoxOpenBaoConfig.default_settings[key],
                key,
            )

    def test_dead_path_alias_template_is_not_model_backed(self):
        self.assertNotIn('path_alias_template', MODEL_BACKED_SETTINGS)
        with self.assertRaises(FieldDoesNotExist):
            OpenBaoSettings._meta.get_field('path_alias_template')


class PathPrefixValidationTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        clear_config()
        self.addCleanup(clear_config)

    def test_path_prefix_can_change_when_no_credentials_exist(self):
        row = OpenBaoSettings.objects.create()
        row.path_prefix = 'estate/netbox'

        row.full_clean()
        row.save()

        self.assertEqual(OpenBaoSettings.objects.get().path_prefix, 'estate/netbox')

    def test_path_prefix_cannot_change_when_a_credential_exists(self):
        row = OpenBaoSettings.objects.create()
        self.make_credential().save()
        row.path_prefix = 'moved'

        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError) as ctx:
            row.full_clean()

        message = ctx.exception.message_dict['path_prefix'][0]
        self.assertIn('secret/data/netbox/credentials/*', message)
        self.assertIn('permission error that looks like a vault outage', message)
        self.assertIn('every existing credential keeps working', message)

    def test_save_rechecks_after_validation_before_a_credential_create(self):
        row = OpenBaoSettings.objects.create()
        row.path_prefix = 'moved'
        row.full_clean()

        self.make_credential().save()

        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            row.save()
        self.assertEqual(OpenBaoSettings.objects.get().path_prefix, 'netbox')

    def test_new_row_rechecks_after_validation_before_a_credential_create(self):
        row = OpenBaoSettings(path_prefix='moved')
        row.full_clean()

        self.make_credential().save()

        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            row.save()
        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_a_stale_instance_cannot_recreate_a_deleted_settings_row(self):
        row = OpenBaoSettings.objects.create(path_prefix='estate/netbox')
        stale = OpenBaoSettings.objects.get(pk=row.pk)
        row.delete()
        self.make_credential().save()

        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError) as ctx:
            stale.save()

        self.assertIn('row no longer exists', ctx.exception.messages[0])
        self.assertFalse(OpenBaoSettings.objects.exists())

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'path_prefix': 'legacy'}})
    def test_first_row_must_match_paths_stamped_under_an_older_fallback(self):
        credential = self.make_credential()
        credential.save()
        self.assertEqual(credential.path, f'legacy/credentials/{credential.uuid}')

        from django.core.exceptions import ValidationError

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': {'path_prefix': 'replacement'}}):
            clear_config()
            row = OpenBaoSettings(path_prefix='replacement')
            with self.assertRaises(ValidationError) as ctx:
                row.full_clean()
            with self.assertRaises(ValidationError):
                row.save()

        message = ctx.exception.message_dict['path_prefix'][0]
        self.assertIn('existing Credential rows are stamped under a different path prefix', message)
        self.assertIn('prefix already encoded in their stored paths', message)
        self.assertFalse(OpenBaoSettings.objects.exists())

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'path_prefix': 'legacy'}})
    def test_first_row_accepts_the_prefix_stamped_on_existing_credentials(self):
        self.make_credential().save()

        row = OpenBaoSettings(path_prefix='legacy')
        row.save()

        self.assertEqual(OpenBaoSettings.objects.get().path_prefix, 'legacy')

    def test_unsafe_legacy_fallback_cannot_derive_or_save_a_credential_path(self):
        from django.core.exceptions import ValidationError

        for prefix in ('../netbox', 'estate//netbox', 'net box', 42):
            with self.subTest(prefix=prefix):
                with override_settings(PLUGINS_CONFIG={'netbox_openbao': {'path_prefix': prefix}}):
                    clear_config()
                    credential = self.make_credential()
                    with self.assertRaises(ValidationError) as ctx:
                        self.assertIsInstance(credential.derived_path, str)
                    with self.assertRaises(ValidationError):
                        credential.save()

                message = ctx.exception.message_dict['path_prefix'][0]
                self.assertIn('effective netbox_openbao path_prefix configuration', message)
                self.assertIsNone(credential.pk)

    def test_settings_cannot_be_deleted_while_a_credential_exists(self):
        row = OpenBaoSettings.objects.create(path_prefix='estate/netbox')
        self.make_credential().save()

        with self.assertRaises(AbortRequest) as ctx:
            row.delete()

        self.assertIn('secret/data/estate/netbox/credentials/*', ctx.exception.message)
        self.assertIn('permission error that looks like a vault outage', ctx.exception.message)
        self.assertTrue(OpenBaoSettings.objects.filter(pk=row.pk).exists())

    def test_settings_can_be_deleted_when_no_credentials_exist(self):
        row = OpenBaoSettings.objects.create()

        row.delete()

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_queryset_delete_cannot_bypass_the_credential_guard(self):
        """
        `QuerySet.delete()` never calls `Model.delete()`, so the guard lives in a
        `pre_delete` receiver as well — otherwise a bulk delete walks straight
        past it.

        The inner `atomic()` is required, not decorative: the refusal raises
        inside this test's own transaction, and PostgreSQL marks a transaction
        broken once a statement in it fails. Without a savepoint to roll back to,
        the assertion below cannot issue its query at all and the test errors on
        the wrong thing entirely.
        """
        row = OpenBaoSettings.objects.create()
        self.make_credential().save()

        with self.assertRaises(AbortRequest), transaction.atomic():
            OpenBaoSettings.objects.all().delete()

        self.assertTrue(OpenBaoSettings.objects.filter(pk=row.pk).exists())

    def test_empty_and_structurally_unsafe_prefixes_are_rejected(self):
        from django.core.exceptions import ValidationError

        for prefix in ('', '/netbox', 'netbox/', 'estate//netbox', '../netbox', 'netbox/../other', 'net box'):
            with self.subTest(prefix=prefix):
                row = OpenBaoSettings(path_prefix=prefix)
                with self.assertRaises(ValidationError) as ctx:
                    row.full_clean()
                self.assertIn('path_prefix', ctx.exception.message_dict)


class DatabaseUnavailableTest(SettingsTestCase):
    """
    A read must never take the process down.

    This runs from `AppConfig.ready()` by way of the modules imported there, and
    from management commands that run before `migrate` has created the table.
    An exception on that path does not fail one plugin; it fails NetBox.
    """

    def test_a_database_error_falls_back_instead_of_raising(self):
        from unittest.mock import patch

        from django.db.utils import DatabaseError

        with patch.object(
            OpenBaoSettings.objects.__class__, 'values', side_effect=DatabaseError('no such table'),
        ):
            with override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 77}}):
                self.assertEqual(get_config('reveal_ttl'), 77)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'reveal_ttl': 77}})
    def test_the_next_request_retries_after_a_transient_failure(self):
        """
        A database failure may live for one request, but the next request must
        retry instead of pinning the fallback for the life of the process.
        """
        from unittest.mock import patch

        from django.db.utils import DatabaseError

        with patch.object(
            OpenBaoSettings.objects.__class__, 'values', side_effect=DatabaseError('database unavailable'),
        ):
            self.assertEqual(get_config('reveal_ttl'), 77)

        clear_config()
        with self.assertNumQueries(1):
            self.assertEqual(get_config('reveal_ttl'), 77)


class SettingsMigrationTest(SettingsTestCase):

    def setUp(self):
        super().setUp()
        self.migration = importlib.import_module(
            'netbox_openbao.migrations.0008_openbaosettings'
        )

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'path_prefix': 'estate'}})
    def test_seed_copies_configuration_and_is_idempotent(self):
        self.migration.seed_settings(apps, None)
        self.migration.seed_settings(apps, None)

        self.assertEqual(OpenBaoSettings.objects.count(), 1)
        self.assertEqual(OpenBaoSettings.objects.get().path_prefix, 'estate')

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {}})
    def test_seed_succeeds_without_operator_configuration(self):
        self.migration.seed_settings(apps, None)
        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_seed_ignores_reordered_set_like_defaults(self):
        configured = dict(self.migration.MODEL_DEFAULTS)
        for key in self.migration.ORDER_INSENSITIVE_SETTINGS:
            configured[key] = list(reversed(configured[key]))

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_seed_normalizes_tuple_defaults_to_lists(self):
        configured = dict(self.migration.MODEL_DEFAULTS)
        configured['assignable_models'] = tuple(configured['assignable_models'])
        configured['expiry_warning_days'] = tuple(configured['expiry_warning_days'])

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_seed_normalizes_labels_like_the_runtime(self):
        configured = dict(self.migration.MODEL_DEFAULTS)
        configured['assignable_models'] = [
            f' {label.upper()} ' for label in configured['assignable_models']
        ]

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_seed_stores_custom_labels_in_runtime_canonical_form(self):
        configured = dict(self.migration.MODEL_DEFAULTS)
        configured['assignable_models'] = [' DCIM.Site ', 'dcim.site', '', None]

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertEqual(OpenBaoSettings.objects.get().assignable_models, ['dcim.site'])

    def test_seed_skips_an_unsafe_legacy_path_prefix(self):
        configured = dict(self.migration.MODEL_DEFAULTS)
        configured['path_prefix'] = '../netbox'

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertFalse(OpenBaoSettings.objects.exists())

    def test_seed_ignores_the_complete_merged_defaults(self):
        from netbox_openbao import NetBoxOpenBaoConfig

        configured = dict(NetBoxOpenBaoConfig.default_settings)

        with override_settings(PLUGINS_CONFIG={'netbox_openbao': configured}):
            self.migration.seed_settings(apps, None)

        self.assertFalse(OpenBaoSettings.objects.exists())


class SettingsAPITest(APITestCase):

    def setUp(self):
        super().setUp()
        clear_config()
        self.addCleanup(clear_config)

    def test_settings_are_readable_and_writable(self):
        self.add_permissions(
            'netbox_openbao.add_openbaosettings',
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.change_openbaosettings',
        )
        list_url = reverse('plugins-api:netbox_openbao-api:openbaosettings-list')
        created = self.client.post(
            list_url,
            {'path_prefix': 'api-managed'},
            format='json',
            **self.header,
        )
        self.assertEqual(created.status_code, 201, created.content)

        detail_url = reverse(
            'plugins-api:netbox_openbao-api:openbaosettings-detail',
            kwargs={'pk': created.data['id']},
        )
        updated = self.client.patch(
            detail_url,
            {'reveal_rate_limit': '7/minute'},
            format='json',
            **self.header,
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(get_config('reveal_rate_limit'), '7/minute')

        fetched = self.client.get(detail_url, **self.header)
        self.assertEqual(fetched.status_code, 200, fetched.content)
        self.assertEqual(fetched.data['path_prefix'], 'api-managed')

    def test_api_rejects_an_unparseable_reveal_rate(self):
        row = OpenBaoSettings.objects.create()
        self.add_permissions(
            'netbox_openbao.view_openbaosettings',
            'netbox_openbao.change_openbaosettings',
        )
        detail_url = reverse(
            'plugins-api:netbox_openbao-api:openbaosettings-detail',
            kwargs={'pk': row.pk},
        )

        response = self.client.patch(
            detail_url,
            {'reveal_rate_limit': 'unlimited'},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn('reveal_rate_limit', response.data)

    def test_api_rejects_a_second_settings_row(self):
        OpenBaoSettings.objects.create()
        self.add_permissions('netbox_openbao.add_openbaosettings')

        response = self.client.post(
            reverse('plugins-api:netbox_openbao-api:openbaosettings-list'),
            {'path_prefix': 'second'},
            format='json',
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(OpenBaoSettings.objects.count(), 1)

    def test_api_refuses_settings_deletion_while_credentials_exist(self):
        row = OpenBaoSettings.objects.create(path_prefix='estate/netbox')
        engine = SecretEngine.objects.create(
            name='Settings deletion engine',
            slug='settings-deletion-engine',
            api_url='https://bao.example.net:8200',
            kv_mount='secret',
        )
        policy = CredentialPolicy.objects.create(
            name='Settings deletion policy',
            slug='settings-deletion-policy',
            engine=engine,
            openbao_policy='settings-deletion-policy',
        )
        Credential.objects.create(
            name='Settings deletion credential',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=policy,
            engine=engine,
        )
        self.add_permissions('netbox_openbao.delete_openbaosettings')

        response = self.client.delete(
            reverse(
                'plugins-api:netbox_openbao-api:openbaosettings-detail',
                kwargs={'pk': row.pk},
            ),
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn('secret/data/estate/netbox/credentials/*', response.data['detail'])
        self.assertTrue(OpenBaoSettings.objects.filter(pk=row.pk).exists())


class SettingsSingletonConcurrencyTest(SettingsTransactionTestCase):
    """Exercise the unique-key loser against a separately committed winner."""

    def setUp(self):
        super().setUp()
        from users.models import User

        self.user = User.objects.create_user(username='settings-race-user', is_superuser=True)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def tearDown(self):
        close_old_connections()
        super().tearDown()

    def test_concurrent_singleton_create_returns_400_and_keeps_the_winner(self):
        from netbox_openbao.api.serializers import OpenBaoSettingsSerializer

        barrier = Barrier(2)
        winner_committed = Event()
        winner_errors = Queue()
        original_create = OpenBaoSettingsSerializer.create

        def create_winner():
            try:
                close_old_connections()
                barrier.wait(timeout=10)
                OpenBaoSettings.objects.create(path_prefix='winner')
            except BaseException as exc:
                winner_errors.put(exc)
            finally:
                winner_committed.set()
                close_old_connections()

        def create_loser(serializer, validated_data):
            barrier.wait(timeout=10)
            if not winner_committed.wait(timeout=10):
                raise RuntimeError('The concurrent settings winner did not commit')
            return original_create(serializer, validated_data)

        winner = Thread(target=create_winner)
        winner.start()
        try:
            with patch.object(OpenBaoSettingsSerializer, 'create', new=create_loser):
                response = self.client.post(
                    reverse('plugins-api:netbox_openbao-api:openbaosettings-list'),
                    {'path_prefix': 'loser'},
                    format='json',
                )
        finally:
            winner.join(timeout=10)

        self.assertFalse(winner.is_alive())
        if not winner_errors.empty():
            raise winner_errors.get()
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(
            response.data['non_field_errors'],
            ['The OpenBao settings row already exists.'],
        )
        self.assertEqual(OpenBaoSettings.objects.count(), 1)
        self.assertEqual(OpenBaoSettings.objects.get().path_prefix, 'winner')


class JobSettingsMemoTest(SettingsTestCase):

    def test_a_second_job_run_observes_a_changed_setting(self):
        from netbox_openbao.jobs import AccessLogPruneJob
        from netbox_openbao.models import CredentialAccessLog

        row = OpenBaoSettings.objects.create(audit_retention_days=1)
        runner = object.__new__(AccessLogPruneJob)
        runner.logger = Mock()
        queryset = Mock()
        queryset.delete.return_value = (0, {})

        from django.utils import timezone

        now = timezone.now()
        with (
            patch('netbox_openbao.jobs.timezone.now', return_value=now),
            patch.object(CredentialAccessLog.objects, 'filter', return_value=queryset) as filter_mock,
        ):
            runner.run()

            row.audit_retention_days = 2
            row.save(update_fields=('audit_retention_days',))
            runner.run()

        self.assertEqual(filter_mock.call_args_list[0].kwargs['timestamp__lt'], now - timedelta(days=1))
        self.assertEqual(filter_mock.call_args_list[1].kwargs['timestamp__lt'], now - timedelta(days=2))


class RPCSettingsReadTest(SettingsTestCase):

    def test_provision_params_read_path_prefix_by_key(self):
        from netbox_openbao.rpc import build_procedure_params

        OpenBaoSettings.objects.create(path_prefix='rpc-managed')
        params = build_procedure_params(
            SimpleNamespace(kv_mount='secret', slug='primary'),
            'service.openbao.1.provision_netbox_approle',
        )

        self.assertEqual(params['path_prefix'], 'rpc-managed')
