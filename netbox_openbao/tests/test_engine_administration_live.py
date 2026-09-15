"""Opt-in representative secrets-engine administration flows against OpenBao 2.6.2."""

import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.engine_journeys import (
    ENGINE_JOURNEYS,
    engine_journey_catalog,
    resolve_engine_journey,
)
from netbox_openbao.administration.engines import classify_explorer_operations
from netbox_openbao.administration.schema import CapabilitySchemaError

TEST_ADDR = os.getenv("NETBOX_OPENBAO_TEST_ADDR")
TEST_TOKEN = os.getenv("NETBOX_OPENBAO_TEST_TOKEN")
TEST_DATABASE_URL = os.getenv("NETBOX_OPENBAO_TEST_DATABASE_URL")
TEST_DATABASE_USERNAME = os.getenv("NETBOX_OPENBAO_TEST_DATABASE_USERNAME")
TEST_DATABASE_PASSWORD = os.getenv("NETBOX_OPENBAO_TEST_DATABASE_PASSWORD")

SSH_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnYVUD6yQQ1tWiqqEdDkhOtoWdsFP/a+d/WKQ0i17vj issue67-live"


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
            metadata = self.backend.execute_mounted_operation("GET", f"/{mount}/metadata/sample", query={}, body={})
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
                f"{transit_mount.replace('-', '_')}_mount_path :: transit-list-keys :: GET /{{secret_mount_path}}/keys",
                keys,
            )
            self.assertIn(
                f"{transit_mount.replace('-', '_')}_mount_path :: transit-encrypt :: "
                "POST /{secret_mount_path}/encrypt/{name}",
                keys,
            )
            transit_list = next(item for item in operations if item.operation_id == "transit-list-keys")
            self.assertEqual(transit_list.mount_parameter, f"{transit_mount.replace('-', '_')}_mount_path")

            self.backend.execute_mounted_operation("POST", f"/{transit_mount}/keys/integration-key", query={}, body={})
            listed = self.backend.execute_mounted_operation(
                "GET", f"/{transit_mount}/keys", query={"list": "true"}, body={}
            )
            self.assertIn("integration-key", listed["data"]["keys"])
        finally:
            if transit_enabled:
                self.backend.disable_secret_engine(transit_mount)
            self.backend.disable_secret_engine(mount)

    @unittest.skipUnless(
        TEST_DATABASE_URL and TEST_DATABASE_USERNAME and TEST_DATABASE_PASSWORD,
        "Set the disposable database integration variables to test every first-class engine family",
    )
    def test_first_class_engine_journeys_against_live_openbao(self):
        suffix = uuid4().hex[:10]
        mounts = {
            "kv1": f"journey-kv1-{suffix}",
            "kv": f"journey-kv-{suffix}",
            "transit": f"journey-transit-{suffix}",
            "database": f"journey-database-{suffix}",
            "ssh": f"journey-ssh-{suffix}",
            "totp": f"journey-totp-{suffix}",
        }
        enabled = []
        try:
            for engine_type, mount in mounts.items():
                configuration = {"type": "kv" if engine_type == "kv1" else engine_type}
                if engine_type in {"kv", "kv1"}:
                    configuration["options"] = {"version": "1" if engine_type == "kv1" else "2"}
                self.backend.enable_secret_engine(mount, configuration)
                enabled.append(mount)

            document = self.backend.discover_capabilities()
            live_mounts = self.backend.list_secret_engines()
            catalog = engine_journey_catalog(document, live_mounts)
            available = {(item["mount_path"], item["journey_id"]) for item in catalog}
            expected = {
                (mounts["kv"], "kv2.diff"),
                (mounts["transit"], "transit.encrypt"),
                (mounts["database"], "database.credentials"),
                (mounts["ssh"], "ssh.sign"),
                (mounts["totp"], "totp.code"),
            }
            self.assertTrue(expected <= available)
            task_mounts = set(mounts.values())
            live_journey_ids = {item["journey_id"] for item in catalog if item["mount_path"] in task_mounts}
            self.assertEqual(live_journey_ids, {journey.journey_id for journey in ENGINE_JOURNEYS})
            with self.assertRaises(CapabilitySchemaError):
                resolve_engine_journey(document, live_mounts, mounts["transit"], "kv2.read")

            kv_path = f"/{mounts['kv']}/data/application"
            for version in ("one", "two"):
                self.backend.execute_mounted_operation("POST", kv_path, query={}, body={"data": {"version": version}})
            before = self.backend.execute_mounted_operation("GET", kv_path, query={"version": 1}, body={})
            after = self.backend.execute_mounted_operation("GET", kv_path, query={"version": 2}, body={})
            self.assertEqual((before["data"]["data"]["version"], after["data"]["data"]["version"]), ("one", "two"))

            transit = mounts["transit"]
            self.backend.execute_mounted_operation("POST", f"/{transit}/keys/payments", query={}, body={})
            encrypted = self.backend.execute_mounted_operation(
                "POST", f"/{transit}/encrypt/payments", query={}, body={"plaintext": "aXNzdWU2Nw=="}
            )
            decrypted = self.backend.execute_mounted_operation(
                "POST", f"/{transit}/decrypt/payments", query={}, body={"ciphertext": encrypted["data"]["ciphertext"]}
            )
            self.assertEqual(decrypted["data"]["plaintext"], "aXNzdWU2Nw==")

            database = mounts["database"]
            self.backend.execute_mounted_operation(
                "POST",
                f"/{database}/config/postgres",
                query={},
                body={
                    "plugin_name": "postgresql-database-plugin",
                    "allowed_roles": ["readonly"],
                    "connection_url": TEST_DATABASE_URL,
                    "username": TEST_DATABASE_USERNAME,
                    "password": TEST_DATABASE_PASSWORD,
                },
            )
            self.backend.execute_mounted_operation(
                "POST",
                f"/{database}/roles/readonly",
                query={},
                body={
                    "db_name": "postgres",
                    "creation_statements": [
                        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
                    ],
                    "default_ttl": "5m",
                    "max_ttl": "10m",
                },
            )
            credentials = self.backend.execute_mounted_operation(
                "GET", f"/{database}/creds/readonly", query={}, body={}
            )
            self.assertTrue(credentials["data"]["username"])
            self.assertTrue(credentials["data"]["password"])

            ssh = mounts["ssh"]
            self.backend.execute_mounted_operation(
                "POST", f"/{ssh}/config/ca", query={}, body={"generate_signing_key": True}
            )
            self.backend.execute_mounted_operation(
                "POST",
                f"/{ssh}/roles/operator",
                query={},
                body={"key_type": "ca", "allowed_users": "*", "allow_user_certificates": True},
            )
            certificate = self.backend.execute_mounted_operation(
                "POST", f"/{ssh}/sign/operator", query={}, body={"public_key": SSH_PUBLIC_KEY}
            )
            self.assertTrue(certificate["data"]["signed_key"].startswith("ssh-ed25519-cert-v01@openssh.com"))

            totp = mounts["totp"]
            self.backend.execute_mounted_operation(
                "POST",
                f"/{totp}/keys/deploy",
                query={},
                body={"generate": True, "issuer": "netbox-openbao", "account_name": "issue67"},
            )
            generated = self.backend.execute_mounted_operation("GET", f"/{totp}/code/deploy", query={}, body={})
            validated = self.backend.execute_mounted_operation(
                "POST", f"/{totp}/code/deploy", query={}, body={"code": generated["data"]["code"]}
            )
            self.assertTrue(validated["data"]["valid"])
        finally:
            for mount in reversed(enabled):
                self.backend.disable_secret_engine(mount)
