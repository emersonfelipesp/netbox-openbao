"""
UI view behaviour.

Worth testing separately from the API because the UI takes a different path to
the same material: a Django form rather than a serializer, and NetBox's generic
`ObjectEditView` rather than a DRF viewset. A regression in one is invisible to
tests of the other — this suite exists because an earlier revision reimplemented
`ObjectEditView.post()` and silently dropped `restrict_form_fields()` with it.
"""

from django.contrib.auth import get_user_model
from django.urls import reverse
from utilities.testing.views import ModelViewTestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAccessLog, CredentialPolicy, SecretEngine
from netbox_openbao.services import write_material

from .fakes import FakeBackend

User = get_user_model()


class OpenBaoViewTestCase(ModelViewTestCase):
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
