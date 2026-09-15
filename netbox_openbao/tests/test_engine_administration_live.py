"""Opt-in representative secrets-engine administration flows against OpenBao 2.6.2."""

import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.engines import classify_explorer_operations

TEST_ADDR = os.getenv("NETBOX_OPENBAO_TEST_ADDR")
TEST_TOKEN = os.getenv("NETBOX_OPENBAO_TEST_TOKEN")


@unittest.skipUnless(
    TEST_ADDR and TEST_TOKEN,
    "Set NETBOX_OPENBAO_TEST_ADDR and NETBOX_OPENBAO_TEST_TOKEN to run secrets-engine integration tests",
)
class SecretEngineAdministrationIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.token_variable = "NETBOX_BAO_ENGINE_ADMIN_LIVE_TOKEN"
        cls.previous_token = os.environ.get(cls.token_variable)
        os.environ[cls.token_variable] = TEST_TOKEN
        cluster = SimpleNamespace(
            api_url=TEST_ADDR,
            ca_cert_path="",
            tls_verify=False,
            namespace="",
            env_prefix="NETBOX_BAO_ENGINE_ADMIN_LIVE",
            slug="engine-admin-live",
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

    def test_kv_mount_lifecycle_and_mounted_operations(self):
        mount = f"live-{uuid4().hex[:12]}"
        transit_mount = f"transit-{uuid4().hex[:12]}"
        transit_enabled = False
        self.backend.enable_secret_engine(mount, {"type": "kv", "options": {"version": "2"}})
        try:
            self.backend.enable_secret_engine(transit_mount, {"type": "transit"})
            transit_enabled = True
            mounts = {item.path: item for item in self.backend.list_secret_engines()}
            self.assertEqual(mounts[mount].engine_type, "kv")
            self.assertEqual(mounts[transit_mount].engine_type, "transit")
            self.assertEqual(self.backend.read_secret_engine(mount)["type"], "kv")

            self.backend.tune_secret_engine(mount, {"description": "NetBox OpenBao integration test"})
            tuning = self.backend.read_secret_engine_tuning(mount)
            self.assertEqual(tuning["description"], "NetBox OpenBao integration test")

            written = self.backend.execute_mounted_operation(
                "POST",
                f"/{mount}/data/sample",
                query={},
                body={"data": {"canary": "live-engine-value"}},
            )
            self.assertEqual(written["data"]["version"], 1)
            patched = self.backend.execute_mounted_operation(
                "PATCH",
                f"/{mount}/data/sample",
                query={},
                body={"data": {"rotated": True}, "options": {"cas": 1}},
            )
            self.assertEqual(patched["data"]["version"], 2)
            self.backend.execute_mounted_operation(
                "PATCH",
                f"/{mount}/metadata/sample",
                query={},
                body={"custom_metadata": {"owner": "netbox-openbao-live-test"}},
            )
            read = self.backend.execute_mounted_operation("GET", f"/{mount}/data/sample", query={}, body={})
            self.assertEqual(
                read["data"]["data"],
                {"canary": "live-engine-value", "rotated": True},
            )
            metadata = self.backend.execute_mounted_operation(
                "GET", f"/{mount}/metadata/sample", query={}, body={}
            )
            self.assertEqual(metadata["data"]["custom_metadata"]["owner"], "netbox-openbao-live-test")

            document = self.backend.discover_capabilities()
            operations = classify_explorer_operations(document)
            keys = {item.operation_key for item in operations if item.executable}
            self.assertIn(
                f"{mount.replace('-', '_')}_mount_path :: kv-read-data-path :: "
                "GET /{secret_mount_path}/data/{path}",
                keys,
            )
            self.assertIn(
                f"{mount.replace('-', '_')}_mount_path :: kv-write-destroy-path :: "
                "POST /{secret_mount_path}/destroy/{path}",
                keys,
            )
            self.assertIn(
                f"{transit_mount.replace('-', '_')}_mount_path :: transit-list-keys :: "
                "GET /{secret_mount_path}/keys",
                keys,
            )
            self.assertIn(
                f"{transit_mount.replace('-', '_')}_mount_path :: transit-encrypt :: "
                "POST /{secret_mount_path}/encrypt/{name}",
                keys,
            )
            transit_list = next(item for item in operations if item.operation_id == "transit-list-keys")
            self.assertEqual(transit_list.mount_parameter, f"{transit_mount.replace('-', '_')}_mount_path")

            self.backend.execute_mounted_operation(
                "POST", f"/{transit_mount}/keys/integration-key", query={}, body={}
            )
            listed = self.backend.execute_mounted_operation(
                "GET", f"/{transit_mount}/keys", query={"list": "true"}, body={}
            )
            self.assertIn("integration-key", listed["data"]["keys"])
        finally:
            if transit_enabled:
                self.backend.disable_secret_engine(transit_mount)
            self.backend.disable_secret_engine(mount)
