"""Shared fixtures."""

import importlib

from django.db import connection
from django.test import TestCase, TransactionTestCase

from netbox_openbao import backends
from netbox_openbao.backends.openbao import OpenBaoBackend
from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

from .fakes import FakeBackend

__all__ = (
    'MaterialTransactionTestMixin',
    'OpenBaoTestCase',
    'OpenBaoTransactionTestCase',
    'seed_nms_credential_schemas',
)


def seed_nms_credential_schemas():
    """Create the `CredentialTypeSchema` rows the NMS import command's
    non-built-in credential types (`ssh_password`, `ssh_key`, ...) depend on.

    Migration `0021_service_endpoints_and_credential_schemas` seeds these once
    when the test database is built, but a `TransactionTestCase` — required
    for anything exercising real commit/rollback semantics, which the import
    command does — flushes all data after every test, seed rows included.
    Only the first such test to run after `migrate` sees them; every other
    one fails with "Unknown credential type" for a slug the migration was
    supposed to guarantee.

    This reuses migration 0021's own `SCHEMAS` and `_seeded_fields` rather
    than restating the field lists, so the two cannot drift apart.
    """
    from netbox_openbao.models import CredentialTypeSchema

    migration = importlib.import_module(
        'netbox_openbao.migrations.0021_service_endpoints_and_credential_schemas',
    )
    existing = set(
        CredentialTypeSchema.objects.filter(slug__in=migration.SCHEMAS).values_list('slug', flat=True)
    )
    for slug, spec in migration.SCHEMAS.items():
        if slug in existing:
            continue
        CredentialTypeSchema.objects.create(slug=slug, **migration._seeded_fields(*spec))


class MaterialTransactionTestMixin:
    """Use real commit/flush lifecycle while retaining NetBox test helpers.

    Apply only to fixtures that write material. NetBox's API/view helper
    classes derive from TestCase; call TransactionTestCase lifecycle methods
    explicitly so no artificial atomic wrapper is created. Rebuild class data
    for every test, and retain normal Django fixture loading and database flush.
    No backend capability, autocommit result or commit witness is mocked.
    """

    @classmethod
    def setUpClass(cls):
        TransactionTestCase.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TransactionTestCase.tearDownClass.__func__(cls)

    @classmethod
    def _fixture_setup(cls):
        TransactionTestCase._fixture_setup.__func__(cls)
        cls.setUpTestData()
        if not connection.get_autocommit() or connection.in_atomic_block:
            raise AssertionError('Material test fixtures require real autocommit.')

    def _fixture_teardown(self):
        TransactionTestCase._fixture_teardown(self)

    def _should_reload_connections(self):
        return True


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


class OpenBaoTransactionTestCase(MaterialTransactionTestMixin, OpenBaoTestCase):
    """Material-writing estate fixture with real outer transaction ownership."""
