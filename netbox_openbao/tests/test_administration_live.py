"""Opt-in administration discovery test against a live OpenBao instance."""

import os
import unittest

from django.test import TransactionTestCase

from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.models import OpenBaoCluster

TEST_ADDR = os.getenv('NETBOX_OPENBAO_TEST_ADDR')
TEST_TOKEN = os.getenv('NETBOX_OPENBAO_TEST_TOKEN')


@unittest.skipUnless(
    TEST_ADDR and TEST_TOKEN,
    'Set NETBOX_OPENBAO_TEST_ADDR and NETBOX_OPENBAO_TEST_TOKEN to run OpenBao administration integration tests',
)
class OpenBaoAdministrationIntegrationTest(TransactionTestCase):

    def setUp(self):
        super().setUp()
        self.cluster = OpenBaoCluster.objects.create(
            name='Administration integration test',
            slug='itest-admin',
            api_url=TEST_ADDR,
            auth_method='token',
            tls_verify=False,
        )
        self.token_variable = 'NETBOX_BAO_ITEST_ADMIN_TOKEN'
        self.previous_token = os.environ.get(self.token_variable)
        os.environ[self.token_variable] = TEST_TOKEN

    def tearDown(self):
        if self.previous_token is None:
            os.environ.pop(self.token_variable, None)
        else:
            os.environ[self.token_variable] = self.previous_token
        super().tearDown()

    def test_live_openapi_document_is_bounded_and_non_executable(self):
        document = DirectAdministrationBackend(self.cluster).discover_capabilities()

        self.assertRegex(document.openapi_version, r'^3\.\d+(?:\.\d+)?$')
        self.assertTrue(document.product_version)
        self.assertRegex(document.digest, r'^[0-9a-f]{64}$')
        self.assertGreater(len(document.operations), 0)
        self.assertTrue(all(not operation.executable for operation in document.operations))
