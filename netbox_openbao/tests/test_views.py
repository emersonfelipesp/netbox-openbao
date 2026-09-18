"""
UI view behaviour.

Worth testing separately from the API because the UI takes a different path to
the same material: a Django form rather than a serializer, and NetBox's generic
`ObjectEditView` rather than a DRF viewset. A regression in one is invisible to
tests of the other — this suite exists because an earlier revision reimplemented
`ObjectEditView.post()` and silently dropped `restrict_form_fields()` with it.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from utilities.testing import TestCase as NetBoxTestCase
from utilities.testing.views import ModelViewTestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialPolicy, SecretEngine
from netbox_openbao.services import write_material

from .base import MaterialTransactionTestMixin
from .fakes import FakeBackend

User = get_user_model()


class OpenBaoViewTestCase(MaterialTransactionTestMixin, ModelViewTestCase):
    model = Credential

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.policy = CredentialPolicy.objects.create(
            name='Lab', slug='lab', engine=self.engine, openbao_policy='netbox-lab',
        )
        self.credential = Credential(
            name='switch-login',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
            engine=self.engine,
            username='admin',
        )
        write_material(self.credential, {'password': 'hunter2'})


class CredentialCreateViewTest(OpenBaoViewTestCase):

    def test_create_writes_material(self):
        """
        The form path must persist the row and the material together. If the
        row were saved without the write, the credential's path would resolve
        to nothing for every consumer.
        """
        # restrict_form_fields() limits the policy/engine selectors to objects the
        # user may view, so those permissions are genuinely required to submit
        # the form — not incidental test setup.
        self.add_permissions(
            'netbox_openbao.add_credential', 'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy', 'netbox_openbao.view_secretengine',
        )

        response = self.client.post(
            reverse('plugins:netbox_openbao:credential_add'),
            data={
                'name': 'new-from-ui',
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
                'username': 'root',
                'status': 'active',
                'password': 'ui-secret',
            },
        )
        self.assertIn(response.status_code, (200, 302), getattr(response, 'content', b'')[:500])

        created = Credential.objects.filter(name='new-from-ui').first()
        self.assertIsNotNone(created, 'The credential row was not created.')
        self.assertEqual(FakeBackend.store[created.path], [{'password': 'ui-secret'}])

    def test_create_without_material_is_rejected(self):
        # restrict_form_fields() limits the policy/engine selectors to objects the
        # user may view, so those permissions are genuinely required to submit
        # the form — not incidental test setup.
        self.add_permissions(
            'netbox_openbao.add_credential', 'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy', 'netbox_openbao.view_secretengine',
        )

        response = self.client.post(
            reverse('plugins:netbox_openbao:credential_add'),
            data={
                'name': 'no-material',
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
                'status': 'active',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Credential.objects.filter(name='no-material').exists())

    def test_generated_keypair_is_written(self):
        # restrict_form_fields() limits the policy/engine selectors to objects the
        # user may view, so those permissions are genuinely required to submit
        # the form — not incidental test setup.
        self.add_permissions(
            'netbox_openbao.add_credential', 'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy', 'netbox_openbao.view_secretengine',
        )

        self.client.post(
            reverse('plugins:netbox_openbao:credential_add'),
            data={
                'name': 'generated',
                'credential_type': CredentialTypeChoices.TYPE_SSH_KEYPAIR,
                'policy': self.policy.pk,
                'status': 'active',
                'generate_key': 'on',
                'generate_key_type': 'ed25519',
            },
        )
        created = Credential.objects.filter(name='generated').first()
        self.assertIsNotNone(created)
        # The public half is persisted in NetBox; the private half is not.
        self.assertTrue(created.public_key.startswith('ssh-ed25519 '))
        self.assertTrue(created.fingerprint.startswith('SHA256:'))
        self.assertIn('private_key', FakeBackend.store[created.path][0])

    def test_material_is_not_echoed_back_on_a_validation_error(self):
        """
        A rejected form must not re-render the secret the user pasted; it would
        land in the back/forward cache and in any saved page or screenshot.
        """
        # restrict_form_fields() limits the policy/engine selectors to objects the
        # user may view, so those permissions are genuinely required to submit
        # the form — not incidental test setup.
        self.add_permissions(
            'netbox_openbao.add_credential', 'netbox_openbao.view_credential',
            'netbox_openbao.view_credentialpolicy', 'netbox_openbao.view_secretengine',
        )

        response = self.client.post(
            reverse('plugins:netbox_openbao:credential_add'),
            data={
                # No name: forces a validation failure with material present.
                'credential_type': CredentialTypeChoices.TYPE_PASSWORD,
                'policy': self.policy.pk,
                'status': 'active',
                'password': 'should-not-be-echoed',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'should-not-be-echoed', response.content)


class CredentialRevealViewTest(OpenBaoViewTestCase):

    def reveal_url(self):
        return reverse('plugins:netbox_openbao:credential_reveal', kwargs={'pk': self.credential.pk})

    def test_get_is_not_allowed(self):
        """
        POST-only. A GET-reachable reveal could be prefetched, bookmarked, or
        replayed from history — fetching a secret with nobody deciding to.
        """
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.get(self.reveal_url())

        self.assertEqual(response.status_code, 405)
        self.assertNotIn(b'hunter2', response.content)

    def test_view_permission_alone_cannot_reveal(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.post(self.reveal_url(), data={})

        self.assertIn(response.status_code, (403, 302, 404))
        self.assertNotIn(b'hunter2', response.content)

    def test_reveal_permission_renders_material_once(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.post(self.reveal_url(), data={'reason': 'CHG-1'})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'hunter2', response.content)

    def test_reveal_response_is_not_storable(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.post(self.reveal_url(), data={})

        self.assertIn('no-store', response['Cache-Control'])

    def test_reveal_is_audited(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        self.client.post(self.reveal_url(), data={'reason': 'CHG-2'})

        entry = CredentialAccessLog.objects.filter(action='reveal', success=True).first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.reason, 'CHG-2')
        # The source IP must be a string the field can store; a netaddr object
        # silently fails the insert and loses the record.
        self.assertIsInstance(entry.source_ip, str)

    def test_policy_required_reason_is_enforced(self):
        self.policy.require_reason = True
        self.policy.save()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        response = self.client.post(self.reveal_url(), data={})
        self.assertNotIn(b'hunter2', getattr(response, 'content', b''))


class StagedRotationViewTest(OpenBaoViewTestCase):

    def setUp(self):
        super().setUp()
        from netbox_openbao.services import stage_material
        stage_material(self.credential, {'password': 'candidate'})
        self.credential.refresh_from_db()

    def url(self, name):
        return reverse(f'plugins:netbox_openbao:credential_{name}', kwargs={'pk': self.credential.pk})

    def test_promote_and_discard_reject_get(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        for name in ('promote', 'discard'):
            self.assertEqual(self.client.get(self.url(name)).status_code, 405, name)

    def test_promote_requires_rotate_permission(self):
        self.add_permissions('netbox_openbao.view_credential')
        self.client.post(self.url('promote'), data={})

        self.credential.refresh_from_db()
        self.assertTrue(self.credential.has_staged_version, 'Promotion happened without permission.')

    def test_promote_switches_the_live_version(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        self.client.post(self.url('promote'), data={'verified': '1', 'note': 'checked'})

        self.credential.refresh_from_db()
        self.assertFalse(self.credential.has_staged_version)
        self.assertEqual(self.credential.live_kv_version, 2)

    def test_discard_keeps_the_live_version(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        self.client.post(self.url('discard'), data={})

        self.credential.refresh_from_db()
        self.assertFalse(self.credential.has_staged_version)
        self.assertEqual(self.credential.live_kv_version, 1)
        self.assertEqual(FakeBackend.store[self.credential.path][0], {'password': 'hunter2'})

    def test_detail_page_renders_the_rotation_panel_without_material(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.rotate_credential')
        response = self.client.get(self.credential.get_absolute_url())

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'candidate', response.content)
        self.assertNotIn(b'hunter2', response.content)


class HTMXRevealTest(OpenBaoViewTestCase):
    """
    The HTMX partial must be exactly as guarded as the full-page view. Two
    paths to the same secret is how the permission check, the policy gate, and
    the no-store headers drift apart.
    """

    def url(self):
        return reverse('plugins:netbox_openbao:credential_reveal-partial', kwargs={'pk': self.credential.pk})

    def test_rejects_get(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.get(self.url())

        self.assertEqual(response.status_code, 405)
        self.assertNotIn(b'hunter2', response.content)

    def test_view_permission_alone_cannot_reveal(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.post(self.url(), data={})

        self.assertIn(response.status_code, (403, 302, 404))
        self.assertNotIn(b'hunter2', response.content)

    def test_returns_the_material_fragment(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.post(self.url(), data={'reason': 'CHG-5'})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'hunter2', response.content)
        # A fragment, not a page.
        self.assertNotIn(b'<html', response.content.lower())

    def test_fragment_is_not_storable(self):
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')
        response = self.client.post(self.url(), data={})

        self.assertIn('no-store', response['Cache-Control'])

    def test_fragment_carries_the_policy_capped_ttl(self):
        self.policy.max_reveal_ttl = 45
        self.policy.save()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        response = self.client.post(self.url(), data={})
        self.assertIn(b'data-ttl="45"', response.content)

    def test_policy_required_reason_is_enforced_and_leaks_nothing(self):
        self.policy.require_reason = True
        self.policy.save()
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        response = self.client.post(self.url(), data={})

        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b'hunter2', response.content)

    def test_backend_failure_renders_an_error_without_material(self):
        FakeBackend.reset()  # the path no longer exists
        self.add_permissions('netbox_openbao.view_credential', 'netbox_openbao.reveal_credential')

        response = self.client.post(self.url(), data={})

        self.assertEqual(response.status_code, 502)
        self.assertNotIn(b'hunter2', response.content)
        self.assertIn('no-store', response['Cache-Control'])

    def test_fragment_uses_no_innerhtml(self):
        """
        The fragment ships inline script. It must not build markup from values
        — the material would be parsed as HTML, and a value containing markup
        would execute in the operator's session.
        """
        from django.template.loader import get_template

        source = get_template('netbox_openbao/partials/reveal_fragment.html').template.source
        for forbidden in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval('):
            self.assertNotIn(forbidden, source, f'{forbidden} must not appear in the reveal fragment')


class CredentialListViewTest(OpenBaoViewTestCase):

    def test_list_renders_without_material(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.get(reverse('plugins:netbox_openbao:credential_list'))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'hunter2', response.content)

    def test_detail_renders_without_material(self):
        self.add_permissions('netbox_openbao.view_credential')
        response = self.client.get(self.credential.get_absolute_url())

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'hunter2', response.content)

    def test_access_log_list_renders(self):
        self.add_permissions('netbox_openbao.view_credentialaccesslog')
        response = self.client.get(reverse('plugins:netbox_openbao:credentialaccesslog_list'))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'hunter2', response.content)

    def test_engine_detail_renders(self):
        self.add_permissions('netbox_openbao.view_secretengine')
        response = self.client.get(self.engine.get_absolute_url())

        self.assertEqual(response.status_code, 200)

    def test_policy_detail_renders(self):
        self.add_permissions('netbox_openbao.view_credentialpolicy')
        response = self.client.get(self.policy.get_absolute_url())

        self.assertEqual(response.status_code, 200)


class FilterFormDeclarationTest(TestCase):
    """Every filter form names its model as a class attribute.

    ``NetBoxModelFilterSetForm`` reads ``model`` from the class. A form that
    instead hands ``model`` to the constructor reaches Django's ``BaseForm``
    and raises ``TypeError`` on the list view, which is how the procedure-run
    list broke (#111). Instantiating each form here catches that whole class of
    copy-paste error, not just the one occurrence.
    """

    def test_every_filter_form_declares_a_model_and_instantiates(self):
        from django.db.models import Model
        from netbox.forms import NetBoxModelFilterSetForm

        from netbox_openbao import forms as openbao_forms

        seen = 0
        for name in openbao_forms.__all__:
            form_class = getattr(openbao_forms, name)
            if not (isinstance(form_class, type) and issubclass(form_class, NetBoxModelFilterSetForm)):
                continue
            seen += 1
            with self.subTest(form=name):
                self.assertTrue(
                    isinstance(form_class.model, type) and issubclass(form_class.model, Model),
                    f'{name}.model must be a model class, got {form_class.model!r}',
                )
                form = form_class({})
                self.assertIs(form.model, form_class.model)
        self.assertGreaterEqual(seen, 5, 'expected the module to export its filter forms')


class OpenBaoProcedureRunViewTest(NetBoxTestCase):
    """The procedure-run list and detail pages render for a permitted user."""

    def setUp(self):
        super().setUp()
        from django.contrib.contenttypes.models import ContentType
        from netbox_rpc.models import RPCExecution

        from netbox_openbao.models import OpenBaoProcedureRun

        from .test_rpc import _make_device, _make_procedure

        self.engine = SecretEngine.objects.create(
            name='Primary', slug='primary', api_url='https://bao.example.net:8200', is_default=True,
        )
        self.other_engine = SecretEngine.objects.create(
            name='Secondary', slug='secondary', api_url='https://bao-2.example.net:8200',
        )
        self.other_user = User.objects.create_user('openbao-other', password='test')
        device = _make_device()
        device_ct = ContentType.objects.get(app_label='dcim', model='device')
        # Each run differs from the others in every filterable attribute, so a
        # filter that silently ignores its input cannot pass by coincidence.
        self.runs = {}
        for procedure_name, engine, user in (
            ('service.openbao.1.health', self.engine, self.user),
            ('service.openbao.1.status', self.other_engine, self.other_user),
        ):
            execution = RPCExecution.objects.create(
                procedure=_make_procedure(procedure_name),
                assigned_object_type=device_ct,
                assigned_object_id=device.pk,
                requested_by=user,
            )
            self.runs[procedure_name] = OpenBaoProcedureRun.objects.create(
                engine=engine,
                rpc_execution=execution,
                procedure_name=procedure_name,
                initiated_by=user,
            )
        self.list_url = reverse('plugins:netbox_openbao:openbaoprocedurerun_list')

    def _listed(self, **params):
        self.add_permissions('netbox_openbao.view_openbaoprocedurerun')
        response = self.client.get(self.list_url, params)
        self.assertHttpStatus(response, 200)
        content = response.content.decode()
        return {name for name, run in self.runs.items() if run.get_absolute_url() in content}

    def test_list_requires_view_permission(self):
        response = self.client.get(self.list_url)
        self.assertHttpStatus(response, 403)

    def test_list_renders_with_every_filter_applied(self):
        listed = self._listed(
            engine_id=[self.engine.pk],
            procedure_name=['service.openbao.1.health'],
            initiated_by_id=[self.user.pk],
        )
        self.assertEqual(listed, {'service.openbao.1.health'})

    def test_list_filters_by_engine(self):
        self.assertEqual(self._listed(engine_id=[self.other_engine.pk]), {'service.openbao.1.status'})

    def test_list_filters_by_procedure(self):
        self.assertEqual(self._listed(procedure_name=['service.openbao.1.status']), {'service.openbao.1.status'})

    def test_list_filters_by_initiator_and_accepts_several_users(self):
        self.assertEqual(self._listed(initiated_by_id=[self.other_user.pk]), {'service.openbao.1.status'})
        self.assertEqual(
            self._listed(initiated_by_id=[self.user.pk, self.other_user.pk]),
            {'service.openbao.1.health', 'service.openbao.1.status'},
        )

    def test_list_renders_unfiltered(self):
        self.assertEqual(self._listed(), set(self.runs))

    def test_detail_renders(self):
        self.add_permissions('netbox_openbao.view_openbaoprocedurerun')
        run = self.runs['service.openbao.1.health']
        response = self.client.get(run.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertIn('service.openbao.1.health', response.content.decode())
