"""Opt-in representative secrets-engine administration flows against OpenBao 2.6.2."""

import base64
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

# Pinned independently from ENGINE_JOURNEYS. This list mirrors the OpenBao
# 2.6.2 PKI and Kubernetes UI adapters reviewed for issue #68 so an omitted
# registry entry fails live completeness instead of disappearing from both
# sides of the assertion.
REQUIRED_PKI_KUBERNETES_UI_JOURNEYS = {
    "pki.cluster-read", "pki.cluster-write", "pki.crl-read", "pki.crl-write",
    "pki.issuers-config-read", "pki.issuers-config-write", "pki.keys-config-read",
    "pki.keys-config-write", "pki.urls-read", "pki.urls-write", "pki.acme-read",
    "pki.acme-write", "pki.issuers", "pki.issuer-read", "pki.issuer-write",
    "pki.issuer-delete", "pki.issuer-import-cert", "pki.issuer-import-bundle",
    "pki.keys", "pki.key-read", "pki.key-write", "pki.key-delete",
    "pki.key-generate-internal", "pki.key-generate-exported", "pki.key-generate-kms",
    "pki.key-import", "pki.roles", "pki.role-read", "pki.role-write", "pki.role-patch",
    "pki.role-delete", "pki.certificates", "pki.revoked-certificates",
    "pki.certificate-read", "pki.issue", "pki.sign", "pki.issuer-issue",
    "pki.issuer-sign", "pki.revoke", "pki.root-generate", "pki.issuers-root-generate",
    "pki.root-rotate", "pki.intermediate-generate", "pki.issuers-intermediate-generate",
    "pki.intermediate-set-signed", "pki.intermediate-cross-sign",
    "pki.issuer-sign-intermediate", "pki.root-delete", "pki.tidy", "pki.tidy-status",
    "pki.tidy-cancel", "pki.auto-tidy-read", "pki.auto-tidy-write",
    "kubernetes.check", "kubernetes.config-read", "kubernetes.config-write",
    "kubernetes.config-delete", "kubernetes.roles", "kubernetes.role-read",
    "kubernetes.role-write", "kubernetes.role-delete", "kubernetes.credentials",
}


def _token(issued_at, expiration):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{encode({'alg': 'RS256', 'typ': 'JWT'})}.{encode({'iat': issued_at, 'exp': expiration})}.c2lnbmF0dXJl"


class KubernetesTokenHandler(BaseHTTPRequestHandler):
    token_requests = []

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is not None:
            return self.rfile.read(int(length))
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return b""
        chunks = []
        while True:
            chunk_length = int(self.rfile.readline().split(b";", 1)[0], 16)
            if chunk_length == 0:
                self.rfile.readline()
                break
            chunks.append(self.rfile.read(chunk_length))
            self.rfile.read(2)
        return b"".join(chunks)

    def do_POST(self):
        if self.path != "/api/v1/namespaces/default/serviceaccounts/operator/token":
            self.send_error(404)
            return
        self.__class__.token_requests.append(self._read_body())
        issued_at = int(time.time())
        expiration = issued_at + 120
        payload = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "status": {
                "token": _token(issued_at, expiration),
                "expirationTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expiration)),
            },
        }
        body = json.dumps(payload).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


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

    def test_pki_and_kubernetes_journeys_against_live_openbao(self):
        suffix = uuid4().hex[:10]
        pki = f"journey-pki-{suffix}"
        kubernetes = f"journey-kubernetes-{suffix}"
        enabled = []
        KubernetesTokenHandler.token_requests = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), KubernetesTokenHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for engine_type, mount in (("pki", pki), ("kubernetes", kubernetes)):
                self.backend.enable_secret_engine(mount, {"type": engine_type})
                enabled.append(mount)

            document = self.backend.discover_capabilities()
            mounts = self.backend.list_secret_engines()
            catalog = engine_journey_catalog(document, mounts)
            actual = {item["journey_id"] for item in catalog if item["mount_path"] in {pki, kubernetes}}
            self.assertEqual(actual, REQUIRED_PKI_KUBERNETES_UI_JOURNEYS)

            root = self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/root/generate/internal",
                query={},
                body={"common_name": "Issue 68 Root", "ttl": "24h"},
            )
            self.assertTrue(root["data"]["certificate"].startswith("-----BEGIN CERTIFICATE-----"))
            self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/roles/application",
                query={},
                body={"allowed_domains": ["example.test"], "allow_subdomains": True, "max_ttl": "1h"},
            )
            certificate = self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/issue/application",
                query={},
                body={"common_name": "service.example.test", "ttl": "5m"},
            )
            self.assertTrue(certificate["data"]["private_key"].startswith("-----BEGIN"))
            serial = certificate["data"]["serial_number"].replace(":", "-")
            fetched = self.backend.execute_mounted_operation("GET", f"/{pki}/cert/{serial}", query={}, body={})
            self.assertEqual(fetched["data"]["certificate"], certificate["data"]["certificate"])
            self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/config/auto-tidy",
                query={},
                body={"enabled": False, "tidy_cert_store": True},
            )
            self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/config/acme",
                query={},
                body={"enabled": False},
            )
            acme = self.backend.execute_mounted_operation("GET", f"/{pki}/config/acme", query={}, body={})
            self.assertFalse(acme["data"]["enabled"])
            modern_root = self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/issuers/generate/root/internal",
                query={},
                body={"common_name": "Issue 68 Multi-Issuer Root", "ttl": "24h"},
            )
            self.assertTrue(modern_root["data"]["issuer_id"])
            intermediate = self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/issuers/generate/intermediate/internal",
                query={},
                body={"common_name": "Issue 68 Intermediate"},
            )
            signed_intermediate = self.backend.execute_mounted_operation(
                "POST",
                f"/{pki}/issuer/{modern_root['data']['issuer_id']}/sign-intermediate",
                query={},
                body={"csr": intermediate["data"]["csr"], "ttl": "12h"},
            )
            self.assertTrue(signed_intermediate["data"]["certificate"].startswith("-----BEGIN CERTIFICATE-----"))

            self.backend.execute_mounted_operation(
                "POST",
                f"/{kubernetes}/config",
                query={},
                body={
                    "kubernetes_host": f"http://127.0.0.1:{server.server_port}",
                    "service_account_jwt": "disposable-reviewer-token",
                    "disable_local_ca_jwt": True,
                },
            )
            self.backend.execute_mounted_operation(
                "POST",
                f"/{kubernetes}/roles/operator",
                query={},
                body={
                    "allowed_kubernetes_namespaces": ["default"],
                    "service_account_name": "operator",
                    "token_default_ttl": 60,
                    "token_max_ttl": 120,
                },
            )
            credentials = self.backend.execute_mounted_operation(
                "POST",
                f"/{kubernetes}/creds/operator",
                query={},
                body={"kubernetes_namespace": "default", "ttl": 60},
            )
            self.assertTrue(credentials["data"]["service_account_token"])
            self.assertEqual(credentials["data"]["service_account_name"], "operator")
            self.assertEqual(len(KubernetesTokenHandler.token_requests), 1)
            self.backend.execute_mounted_operation("DELETE", f"/{pki}/root", query={}, body={})
        finally:
            for mount in reversed(enabled):
                self.backend.disable_secret_engine(mount)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

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
