"""Opt-in policy, identity, OIDC, and namespace flows against OpenBao 2.6.2."""

import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

from netbox_openbao.administration.access import ACCESS_RESOURCES, runtime_advertises
from netbox_openbao.administration.backends import DirectAdministrationBackend

TEST_ADDR = os.getenv("NETBOX_OPENBAO_TEST_ADDR")
TEST_TOKEN = os.getenv("NETBOX_OPENBAO_TEST_TOKEN")


@unittest.skipUnless(
    TEST_ADDR and TEST_TOKEN,
    "Set NETBOX_OPENBAO_TEST_ADDR and NETBOX_OPENBAO_TEST_TOKEN to run access administration integration tests",
)
class AccessAdministrationIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.token_variable = "NETBOX_BAO_ACCESS_ADMIN_LIVE_TOKEN"
        cls.previous_token = os.environ.get(cls.token_variable)
        os.environ[cls.token_variable] = TEST_TOKEN
        cluster = SimpleNamespace(
            api_url=TEST_ADDR,
            ca_cert_path="",
            tls_verify=False,
            namespace="",
            env_prefix="NETBOX_BAO_ACCESS_ADMIN_LIVE",
            slug="access-admin-live",
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
        specification = ACCESS_RESOURCES[resource]
        contract = specification.operations[operation]
        return self.backend.execute_access_operation(
            contract.method,
            specification.path(operation, identifier),
            payload=payload or {},
            material=material,
        )

    def test_runtime_contract_advertises_every_reviewed_openbao_2_6_2_operation(self):
        document = self.backend.discover_capabilities()

        self.assertEqual(document.product_version, "2.6.2")
        missing = {
            f"{resource.key}.{name}"
            for resource in ACCESS_RESOURCES.values()
            for name, operation in resource.operations.items()
            if not runtime_advertises(document, operation)
        }
        self.assertEqual(missing, set())

    def test_acl_and_password_policy_lifecycle(self):
        suffix = uuid4().hex[:12]
        acl_name = f"live-acl-{suffix}"
        password_name = f"live-password-{suffix}"
        self.execute(
            "acl-policies",
            "write",
            identifier=acl_name,
            payload={"policy": 'path "secret/data/live" { capabilities = ["read"] }'},
        )
        self.execute(
            "password-policies",
            "write",
            identifier=password_name,
            payload={
                "policy": 'length = 24\nrule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }'
            },
        )
        try:
            self.assertEqual(self.execute("acl-policies", "read", identifier=acl_name)["data"]["name"], acl_name)
            self.assertIn(acl_name, self.execute("acl-policies", "list")["data"]["keys"])
            generated = self.execute(
                "password-policies", "generate", identifier=password_name, material=True
            )
            self.assertEqual(len(generated["data"]["password"]), 24)
            redacted = self.execute("password-policies", "generate", identifier=password_name)
            self.assertNotIn("password", redacted["data"])
        finally:
            self.execute("password-policies", "delete", identifier=password_name)
            self.execute("acl-policies", "delete", identifier=acl_name)

    def test_identity_entities_groups_aliases_membership_and_merge(self):
        suffix = uuid4().hex[:12]
        auth_mount = f"live-userpass-{suffix}"
        self.backend.enable_auth_method(auth_mount, {"type": "userpass"})
        destination_id = source_id = entity_alias_id = internal_group_id = external_group_id = group_alias_id = ""
        try:
            accessor = next(method.accessor for method in self.backend.list_auth_methods() if method.path == auth_mount)
            destination_id = self.execute(
                "entities", "write", payload={"name": f"destination-{suffix}", "metadata": {"owner": "live-test"}}
            )["data"]["id"]
            source_id = self.execute(
                "entities", "write", payload={"name": f"source-{suffix}", "policies": ["default"]}
            )["data"]["id"]
            entity_alias_id = self.execute(
                "entity-aliases",
                "write",
                payload={
                    "name": f"entity-alias-{suffix}",
                    "canonical_id": destination_id,
                    "mount_accessor": accessor,
                },
            )["data"]["id"]
            internal_group_id = self.execute(
                "groups",
                "write",
                payload={
                    "name": f"internal-{suffix}",
                    "type": "internal",
                    "member_entity_ids": [destination_id, source_id],
                },
            )["data"]["id"]
            external_group_id = self.execute(
                "groups", "write", payload={"name": f"external-{suffix}", "type": "external"}
            )["data"]["id"]
            group_alias_id = self.execute(
                "group-aliases",
                "write",
                payload={
                    "name": f"group-alias-{suffix}",
                    "canonical_id": external_group_id,
                    "mount_accessor": accessor,
                },
            )["data"]["id"]

            group = self.execute("groups", "read", identifier=internal_group_id)
            self.assertEqual(set(group["data"]["member_entity_ids"]), {destination_id, source_id})
            self.assertIn(entity_alias_id, self.execute("entity-aliases", "list")["data"]["keys"])
            self.assertIn(group_alias_id, self.execute("group-aliases", "list")["data"]["keys"])
            self.execute(
                "entities",
                "merge",
                payload={"from_entity_ids": [source_id], "to_entity_id": destination_id},
            )
            source_id = ""
            self.assertEqual(self.execute("entities", "read", identifier=destination_id)["data"]["id"], destination_id)
        finally:
            if group_alias_id:
                self.execute("group-aliases", "delete", identifier=group_alias_id)
            if external_group_id:
                self.execute("groups", "delete", identifier=external_group_id)
            if internal_group_id:
                self.execute("groups", "delete", identifier=internal_group_id)
            if entity_alias_id:
                self.execute("entity-aliases", "delete", identifier=entity_alias_id)
            if source_id:
                self.execute("entities", "delete", identifier=source_id)
            if destination_id:
                self.execute("entities", "delete", identifier=destination_id)
            self.backend.disable_auth_method(auth_mount)

    def test_oidc_resource_lifecycle_and_material_classification(self):
        suffix = uuid4().hex[:12]
        entity_id = self.execute("entities", "write", payload={"name": f"oidc-entity-{suffix}"})["data"]["id"]
        group_id = self.execute("groups", "write", payload={"name": f"oidc-group-{suffix}"})["data"]["id"]
        key_name = f"key-{suffix}"
        assignment_name = f"assignment-{suffix}"
        scope_name = f"scope-{suffix}"
        client_name = f"client-{suffix}"
        provider_name = f"provider-{suffix}"
        created = []
        try:
            self.execute(
                "oidc-keys",
                "write",
                identifier=key_name,
                payload={"algorithm": "RS256", "allowed_client_ids": ["*"]},
            )
            created.append(("oidc-keys", key_name))
            self.execute(
                "oidc-assignments",
                "write",
                identifier=assignment_name,
                payload={"entity_ids": [entity_id], "group_ids": [group_id]},
            )
            created.append(("oidc-assignments", assignment_name))
            self.execute(
                "oidc-scopes",
                "write",
                identifier=scope_name,
                payload={"description": "Live test scope", "template": '{"username": {{identity.entity.name}}}'},
            )
            created.append(("oidc-scopes", scope_name))
            client = self.execute(
                "oidc-clients",
                "write",
                identifier=client_name,
                payload={
                    "key": key_name,
                    "assignments": [assignment_name],
                    "redirect_uris": ["https://client.example.test/callback"],
                    "client_type": "confidential",
                    "authorization_code": True,
                },
                material=True,
            )
            created.append(("oidc-clients", client_name))
            client = self.execute("oidc-clients", "read", identifier=client_name, material=True)
            client_id = client["data"]["client_id"]
            self.assertTrue(client["data"]["client_secret"])
            self.assertNotIn(
                "client_secret",
                self.execute("oidc-clients", "read", identifier=client_name)["data"],
            )
            self.execute(
                "oidc-providers",
                "write",
                identifier=provider_name,
                payload={"allowed_client_ids": [client_id], "scopes_supported": [scope_name]},
            )
            created.append(("oidc-providers", provider_name))
            self.execute("oidc-keys", "rotate", identifier=key_name)
            self.assertIn(provider_name, self.execute("oidc-providers", "list")["data"]["keys"])
        finally:
            for resource, identifier in reversed(created):
                self.execute(resource, "delete", identifier=identifier)
            self.execute("groups", "delete", identifier=group_id)
            self.execute("entities", "delete", identifier=entity_id)

    def test_namespace_lifecycle_preserves_canonical_path(self):
        namespace = f"live-{uuid4().hex[:12]}"
        self.execute(
            "namespaces",
            "write",
            identifier=namespace,
            payload={"custom_metadata": {"owner": "netbox-openbao-live-test"}},
        )
        try:
            read = self.execute("namespaces", "read", identifier=namespace)
            self.assertEqual(read["data"]["path"], f"{namespace}/")
            listed = self.execute("namespaces", "list")
            self.assertIn(namespace.split("/", 1)[0] + "/", listed["data"]["key_info"])
        finally:
            self.execute("namespaces", "delete", identifier=namespace)
