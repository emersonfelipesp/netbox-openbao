from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError

from netbox_openbao.backends import get_backend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, EngineAuthMaterial, SecretEngine

from .base import OpenBaoTestCase


class SecretEngineTest(OpenBaoTestCase):

    def test_only_one_engine_may_be_default(self):
        with self.assertRaises(IntegrityError):
            SecretEngine.objects.create(
                name='Second', slug='second', api_url='https://bao2.example.net:8200',
                is_default=True,
            )

    def test_no_auth_material_fields_exist(self):
        """The engine inventory row must never hold plaintext auth material."""
        names = {f.name for f in SecretEngine._meta.get_fields()}
        for forbidden in ('role_id', 'secret_id', 'token', 'password'):
            self.assertNotIn(forbidden, names)


class CredentialPathTest(OpenBaoTestCase):

    def test_path_is_derived_from_uuid(self):
        credential = self.make_credential()
        credential.save()
        self.assertEqual(credential.path, f'netbox/credentials/{credential.uuid}')

    def test_path_is_stable_across_renames(self):
        """
        A path derived from the object graph would break on the first rename
        and orphan the material. It must survive.
        """
        credential = self.make_credential()
        credential.save()
        original = credential.path

        credential.name = 'renamed'
        credential.save()
        credential.refresh_from_db()
        self.assertEqual(credential.path, original)

    def test_engine_defaults_from_policy(self):
        credential = Credential(
            name='no-engine',
            credential_type=CredentialTypeChoices.TYPE_PASSWORD,
            policy=self.policy,
        )
        credential.save()
        self.assertEqual(credential.engine_id, self.policy.engine_id)

    def test_engine_must_match_policy_engine(self):
        """
        A tier's AppRole is scoped to its engine. If the credential could sit
        on a different engine, the per-tier AppRole would guard nothing.
        """
        other = SecretEngine.objects.create(
            name='Other', slug='other', api_url='https://bao3.example.net:8200',
        )
        credential = self.make_credential(engine=other)
        with self.assertRaises(ValidationError) as ctx:
            credential.full_clean()
        self.assertIn('engine', ctx.exception.message_dict)

    def test_inverted_validity_window_is_rejected(self):
        from datetime import timedelta

        from django.utils import timezone

        now = timezone.now()
        credential = self.make_credential(valid_from=now, valid_until=now - timedelta(days=1))
        with self.assertRaises(ValidationError):
            credential.full_clean()

    def test_is_expired_reflects_valid_until(self):
        from datetime import timedelta

        from django.utils import timezone

        past = self.make_credential(valid_until=timezone.now() - timedelta(days=1))
        future = self.make_credential(valid_until=timezone.now() + timedelta(days=1))
        undated = self.make_credential()

        self.assertTrue(past.is_expired)
        self.assertFalse(future.is_expired)
        self.assertFalse(undated.is_expired)


class CredentialPolicyTest(OpenBaoTestCase):

    def test_auth_material_falls_back_to_engine(self):
        material = EngineAuthMaterial(engine=self.engine)
        material.set_secret('role_id', 'engine-role')
        material.save()
        self.assertEqual(get_backend(self.engine, self.policy).auth_material, material)

    def test_policy_auth_material_overrides_engine(self):
        engine_material = EngineAuthMaterial.objects.create(engine=self.engine)
        policy_material = EngineAuthMaterial.objects.create(policy=self.policy)
        self.assertNotEqual(engine_material, policy_material)
        self.assertEqual(get_backend(self.engine, self.policy).auth_material, policy_material)
