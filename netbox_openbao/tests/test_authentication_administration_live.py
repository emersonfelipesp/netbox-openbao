"""Opt-in representative authentication administration flows against OpenBao 2.6.2."""

import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

from netbox_openbao.administration.authentication import resource_spec
from netbox_openbao.administration.backends import DirectAdministrationBackend

TEST_ADDR = os.getenv("NETBOX_OPENBAO_TEST_ADDR")
TEST_TOKEN = os.getenv("NETBOX_OPENBAO_TEST_TOKEN")


@unittest.skipUnless(
    TEST_ADDR and TEST_TOKEN,
    "Set NETBOX_OPENBAO_TEST_ADDR and NETBOX_OPENBAO_TEST_TOKEN to run authentication integration tests",
)
class AuthenticationAdministrationIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.token_variable = "NETBOX_BAO_AUTH_ADMIN_LIVE_TOKEN"
        cls.previous_token = os.environ.get(cls.token_variable)
        os.environ[cls.token_variable] = TEST_TOKEN
        cluster = SimpleNamespace(
            api_url=TEST_ADDR,
            ca_cert_path="",
            tls_verify=False,
            namespace="",
            env_prefix="NETBOX_BAO_AUTH_ADMIN_LIVE",
            slug="auth-admin-live",
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

    def test_userpass_login_lookup_renew_revoke_and_cleanup(self):
        name = f"live-{uuid4().hex[:12]}"
        policy_name = f"live-totp-self-{uuid4().hex[:12]}"
        write = resource_spec("userpass-users", "userpass", "write")
        delete = resource_spec("userpass-users", "userpass", "delete")
        policy_response = self.backend._request(
            "PUT",
            f"/sys/policies/acl/{policy_name}",
            authenticated=True,
            expected=(200, 204),
            json={"policy": 'path "identity/mfa/method/totp/generate" { capabilities = ["update"] }'},
        )
        policy_response.close()
        try:
            self.backend.run_auth_resource(
                "userpass",
                write,
                "write",
                name=name,
                payload={"password": "live-test-password", "policies": [policy_name]},
            )
            try:
                login = self.backend.authenticate(
                    "userpass", "userpass", {"username": name, "password": "live-test-password"}
                )
                try:
                    lookup = self.backend.token_operation("lookup-self", {"token": login.client_token})
                    renewed = self.backend.token_operation("renew-self", {"token": login.client_token, "increment": 30})
                    self.assertTrue(lookup["id"])
                    self.assertTrue(renewed.client_token)
                    method = self.backend.write_mfa_method(
                        "totp",
                        {"method_name": f"self-{uuid4().hex[:12]}", "issuer": "NetBox test"},
                    )
                    try:
                        setup = self.backend.setup_totp(method["method_id"], token=login.client_token)
                        self.assertTrue(setup.url.startswith("otpauth://"))
                        self.assertTrue(setup.barcode)
                        self.assertEqual(
                            self.backend.reset_totp_setup(method["method_id"], login.client_token),
                            {"reset": True},
                        )
                        replacement = self.backend.setup_totp(method["method_id"], token=login.client_token)
                        self.assertTrue(replacement.url.startswith("otpauth://"))
                    finally:
                        if login.entity_id:
                            self.backend.destroy_totp_setup(method["method_id"], login.entity_id)
                        self.backend.delete_mfa_method("totp", method["method_id"])
                finally:
                    self.backend.token_operation("revoke-self", {"token": login.client_token})
            finally:
                self.backend.run_auth_resource("userpass", delete, "delete", name=name)
        finally:
            policy_response = self.backend._request(
                "DELETE",
                f"/sys/policies/acl/{policy_name}",
                authenticated=True,
                expected=(200, 204),
            )
            policy_response.close()

    def test_approle_secret_id_and_totp_method_crud_cleanup(self):
        role_name = f"live-{uuid4().hex[:12]}"
        self.backend.run_auth_resource(
            "approle",
            resource_spec("approle-roles", "approle", "write"),
            "write",
            name=role_name,
            payload={"policies": ["default"]},
        )
        try:
            replacement_role_id = f"live-role-{uuid4().hex}"
            self.backend.write_approle_role_id("approle", role_name, replacement_role_id)
            role = self.backend.read_approle_role_id("approle", role_name)
            self.assertEqual(role["role_id"], replacement_role_id)
            secret = self.backend.issue_approle_secret_id("approle", role_name, {})
            try:
                login = self.backend.authenticate(
                    "approle",
                    "approle",
                    {"role_id": role["role_id"], "secret_id": secret.secret_id},
                )
                self.assertIn("default", login.policies)
                lookup = self.backend.lookup_approle_secret_id("approle", role_name, secret.accessor)
                self.assertEqual(lookup["secret_id_accessor"], secret.accessor)
                self.backend.token_operation("revoke-self", {"token": login.client_token})
            finally:
                self.backend.destroy_approle_secret_id("approle", role_name, secret.accessor)
        finally:
            self.backend.run_auth_resource(
                "approle",
                resource_spec("approle-roles", "approle", "delete"),
                "delete",
                name=role_name,
            )

        method_name = f"live-{uuid4().hex[:12]}"
        created = self.backend.write_mfa_method("totp", {"method_name": method_name, "issuer": "NetBox test"})
        method_id = created["method_id"]
        try:
            self.assertEqual(self.backend.read_mfa_method(method_id)["type"], "totp")
            self.assertIn(method_id, self.backend.list_mfa_methods()["keys"])
        finally:
            self.backend.delete_mfa_method("totp", method_id)

    def test_direct_oidc_role_configuration_is_readable_and_cleanup_is_bounded(self):
        role_name = f"live-{uuid4().hex[:12]}"
        write = resource_spec("jwt-roles", "jwt", "write")
        delete = resource_spec("jwt-roles", "jwt", "delete")
        self.backend.run_auth_resource(
            "jwt",
            write,
            "write",
            name=role_name,
            payload={
                "role_type": "oidc",
                "user_claim": "sub",
                "callback_mode": "direct",
                "allowed_redirect_uris": [f"{TEST_ADDR}/v1/auth/jwt/oidc/callback"],
            },
        )
        try:
            role = self.backend.read_direct_oidc_role("jwt", role_name)
            self.assertEqual(role["role_type"], "oidc")
            self.assertEqual(role["callback_mode"], "direct")
        finally:
            self.backend.run_auth_resource("jwt", delete, "delete", name=role_name)

    def test_radius_configuration_and_user_crud_use_reviewed_openbao_2_6_2_paths(self):
        name = f"live-{uuid4().hex[:12]}"
        self.backend.write_auth_config(
            "radius",
            {
                "host": "127.0.0.1",
                "secret": f"live-secret-{uuid4().hex}",
                "port": 1812,
                "dial_timeout": 2,
                "read_timeout": 2,
                "nas_port": 10,
                "nas_identifier": "netbox-openbao-live-test",
                "unregistered_user_policies": "default",
            },
        )
        configuration = self.backend.read_auth_config("radius")
        self.assertEqual(configuration["host"], "127.0.0.1")
        self.assertNotIn("secret", configuration)
        write = resource_spec("radius-users", "radius", "write")
        read = resource_spec("radius-users", "radius", "read")
        delete = resource_spec("radius-users", "radius", "delete")
        self.backend.run_auth_resource("radius", write, "write", name=name, payload={"policies": ["default"]})
        try:
            user = self.backend.run_auth_resource("radius", read, "read", name=name)
            self.assertEqual(user["policies"], ["default"])
        finally:
            self.backend.run_auth_resource("radius", delete, "delete", name=name)

    def test_runtime_contract_is_exact_openbao_2_6_2(self):
        document = self.backend.discover_capabilities()
        operation_ids = {operation.operation_id for operation in document.operations}

        self.assertEqual(document.product_version, "2.6.2")
        self.assertTrue(
            {
                "auth-list-enabled-methods",
                "userpass-login",
                "app-role-write-secret-id",
                "jwt-oidc-request-authorization-url",
                "mfa-validate",
                "radius-configure",
                "radius-list-users",
                "radius-login-with-username",
            }
            <= operation_ids
        )
