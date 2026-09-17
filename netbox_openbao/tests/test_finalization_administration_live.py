"""Opt-in final parity flows against OpenBao 2.6.2."""

import os
import time
import unittest
from types import SimpleNamespace
from uuid import uuid4

from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.finalization import FINAL_RESOURCES, conformance_report
from netbox_openbao.api.finalization_views import FinalizationAdministrationMixin, _digest
from netbox_openbao.backends.exceptions import OpenBaoConflict

TEST_ADDR = os.getenv("NETBOX_OPENBAO_TEST_ADDR")
TEST_TOKEN = os.getenv("NETBOX_OPENBAO_TEST_TOKEN")


@unittest.skipUnless(
    TEST_ADDR and TEST_TOKEN,
    "Set NETBOX_OPENBAO_TEST_ADDR and NETBOX_OPENBAO_TEST_TOKEN to run finalization integration tests",
)
class FinalizationAdministrationIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.token_variable = "NETBOX_BAO_FINAL_ADMIN_LIVE_TOKEN"
        cls.previous_token = os.environ.get(cls.token_variable)
        os.environ[cls.token_variable] = TEST_TOKEN
        cluster = SimpleNamespace(
            api_url=TEST_ADDR,
            ca_cert_path="",
            tls_verify=False,
            namespace="",
            env_prefix="NETBOX_BAO_FINAL_ADMIN_LIVE",
            slug="final-admin-live",
            auth_method="token",
        )
        cls.backend = DirectAdministrationBackend(cluster)

    @classmethod
    def tearDownClass(cls):
        if cls.previous_token is None:
            os.environ.pop(cls.token_variable, None)
        else:
            os.environ[cls.token_variable] = cls.previous_token
        super().tearDownClass()

    def execute(self, resource, operation, *, identifier="", payload=None, material=False):
        specification = FINAL_RESOURCES[resource]
        contract = specification.operations[operation]
        return self.backend.execute_final_operation(
            contract.method,
            specification.path(operation, identifier),
            payload=payload or {},
            material=material,
        )

    def test_runtime_contract_matches_the_pinned_openbao_2_6_2_fixture(self):
        report = conformance_report(self.backend.discover_capabilities())
        self.assertTrue(report["conformant"], report)
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["unclassified"], [])

    def test_wrapping_hash_random_token_and_ui_header_flows(self):
        random_data = self.execute("random", "generate", identifier="all", payload={"bytes": 8}, material=True)
        self.assertTrue(random_data["data"]["random_bytes"])
        digest = self.execute("hash", "run", identifier="sha2-256", payload={"input": "Y2FuYXJ5"}, material=True)
        self.assertTrue(digest["data"]["sum"])

        wrapped = self.execute(
            "wrapping", "wrap", payload={"data": {"owner": "issue70-live"}, "ttl": "5m"}, material=True
        )
        token = wrapped["wrap_info"]["token"]
        self.assertEqual(
            self.execute("wrapping", "lookup", payload={"token": token})["data"]["creation_path"], "sys/wrapping/wrap"
        )
        rewrapped = self.execute("wrapping", "rewrap", payload={"token": token}, material=True)
        replacement = rewrapped["wrap_info"]["token"]
        unwrapped = self.execute("wrapping", "unwrap", payload={"token": replacement}, material=True)
        self.assertEqual(unwrapped["data"]["owner"], "issue70-live")

        token_lookup = self.execute("token-tools", "lookup", payload={"token": TEST_TOKEN})
        self.assertEqual(token_lookup["data"]["display_name"], "token")

        header = f"X-Issue70-{uuid4().hex[:10]}"
        self.execute("ui-headers", "write", identifier=header, payload={"values": ["one", "two"]})
        try:
            self.assertEqual(self.execute("ui-headers", "read", identifier=header)["data"]["values"], ["one", "two"])
            self.assertIn(
                header.lower(), {value.lower() for value in self.execute("ui-headers", "list")["data"]["keys"]}
            )
        finally:
            self.execute("ui-headers", "delete", identifier=header)

    def test_dynamic_lease_lookup_list_renewal_refusal_and_revocation(self):
        mount = f"issue70-ssh-{uuid4().hex[:10]}"
        response = self.backend._request(
            "POST", f"/sys/mounts/{mount}", authenticated=True, expected=(200, 204), json={"type": "ssh"}
        )
        response.close()
        try:
            response = self.backend._request(
                "POST",
                f"/{mount}/roles/otp",
                authenticated=True,
                expected=(200, 204),
                json={"key_type": "otp", "default_user": "testuser", "cidr_list": "127.0.0.1/32"},
            )
            response.close()
            first = self.backend._request_json(
                "POST", f"/{mount}/creds/otp", authenticated=True, json={"ip": "127.0.0.1"}
            )["lease_id"]
            self.assertIn(f"{mount}/", self.execute("leases", "list")["data"]["keys"])
            prefix = f"{mount}/creds/otp/"
            self.assertIn(first.rsplit("/", 1)[-1], self.execute("leases", "list", identifier=prefix)["data"]["keys"])
            def revoke_impact():
                return FinalizationAdministrationMixin._impact(
                    self.backend,
                    FINAL_RESOURCES["leases"],
                    "revoke",
                    "",
                    {"lease_id": first},
                )
            first_impact = revoke_impact()
            time.sleep(2)
            second_impact = revoke_impact()
            self.assertEqual(_digest(first_impact), _digest(second_impact))
            self.assertNotIn("ttl", first_impact["current"])
            self.assertIn(first, FinalizationAdministrationMixin._lease_set(self.backend, mount))
            self.assertEqual(self.execute("leases", "lookup", payload={"lease_id": first})["data"]["id"], first)
            with self.assertRaises(OpenBaoConflict):
                self.execute("leases", "renew", payload={"lease_id": first, "increment": 60})
            self.execute("leases", "revoke", payload={"lease_id": first, "sync": True})

            self.backend._request_json("POST", f"/{mount}/creds/otp", authenticated=True, json={"ip": "127.0.0.1"})
            self.execute("leases", "revoke-prefix", identifier=prefix, payload={"sync": True})
            self.assertEqual(self.execute("leases", "list", identifier=prefix)["data"]["keys"], [])

            self.backend._request_json("POST", f"/{mount}/creds/otp", authenticated=True, json={"ip": "127.0.0.1"})
            self.execute("leases", "force-revoke", identifier=prefix)
            self.assertEqual(self.execute("leases", "list", identifier=prefix)["data"]["keys"], [])
        finally:
            response = self.backend._request("DELETE", f"/sys/mounts/{mount}", authenticated=True, expected=(200, 204))
            response.close()
