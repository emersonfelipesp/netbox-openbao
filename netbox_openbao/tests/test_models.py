from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

from .base import OpenBaoTestCase


class SecretEngineTest(OpenBaoTestCase):

    def test_env_prefix_is_derived_from_slug(self):
        """
        The prefix is the deployment contract: operators must export
        <prefix>_ROLE_ID and <prefix>_SECRET_ID, so its derivation must be
        stable and obvious.
        """
        engine = SecretEngine(slug='prod-core')
        self.assertEqual(engine.env_prefix, 'NETBOX_BAO_PROD_CORE')

    def test_only_one_engine_may_be_default(self):
        with self.assertRaises(IntegrityError):
            SecretEngine.objects.create(
                name='Second', slug='second', api_url='https://bao2.example.net:8200',
                is_default=True,
            )

    def test_no_auth_material_fields_exist(self):
        """Auth material must come from the environment, never the database."""
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

    def test_env_prefix_falls_back_to_engine(self):
        self.assertEqual(self.policy.env_prefix, self.engine.env_prefix)

    def test_env_prefix_override(self):
        policy = CredentialPolicy(
            name='Prod', slug='prod', engine=self.engine,
            openbao_policy='netbox-prod', approle_env_prefix='NETBOX_BAO_PROD_CORE',
        )
        self.assertEqual(policy.env_prefix, 'NETBOX_BAO_PROD_CORE')
