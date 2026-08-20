"""Shared fixtures."""

from django.test import TestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

from .fakes import FakeBackend

__all__ = ('OpenBaoTestCase',)


class OpenBaoTestCase(TestCase):
    """Base case wiring the fake backend in and building a minimal estate."""

    def setUp(self):
        super().setUp()
        backends.BACKENDS['openbao'] = FakeBackend
        FakeBackend.reset()
        self.addCleanup(lambda: backends.BACKENDS.__setitem__('openbao', OpenBaoBackend))

        self.engine = SecretEngine.objects.create(
            name='Primary',
            slug='primary',
            api_url='https://bao.example.net:8200',
            kv_mount='secret',
            is_default=True,
        )
        self.policy = CredentialPolicy.objects.create(
            name='Lab',
            slug='lab',
            engine=self.engine,
            openbao_policy='netbox-lab',
        )

    def make_credential(self, **kwargs):
        kwargs.setdefault('name', 'test-credential')
        kwargs.setdefault('credential_type', CredentialTypeChoices.TYPE_PASSWORD)
        kwargs.setdefault('policy', self.policy)
        kwargs.setdefault('engine', self.engine)
        return Credential(**kwargs)
