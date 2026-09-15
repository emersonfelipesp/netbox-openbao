"""Authentication, OIDC, token, MFA, and mounted-resource administration tests."""

import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.test import Client
from django.urls import reverse

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.authentication import (
    AUTH_CONFIG_FIELDS,
    MFA_METHOD_FIELDS,
    AuthenticationResult,
    AuthMount,
    OIDCStartResult,
    TOTPSetupResult,
    normalize_auth_mounts,
    normalize_authentication_result,
    normalize_oidc_start,
    normalize_public_auth_data,
    normalize_totp_setup_result,
    resource_spec,
    validate_auth_resource_payload,
    validate_authorization_url,
    validate_direct_oidc_role,
    validate_reviewed_payload,
)
from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.cluster import SealStatus
from netbox_openbao.administration.schema import (
    CapabilityDocument,
    CapabilitySchemaError,
    DiscoveredOperation,
)
from netbox_openbao.api import authentication_views
from netbox_openbao.api.authentication_serializers import EnableAuthMethodSerializer, TuneAuthMethodSerializer
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoMutationUnknown
from netbox_openbao.models import OpenBaoAdministrationLog
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase, _Response


def capability_document(*operation_ids):
    operations = tuple(
        DiscoveredOperation(
            operation_id=operation_id,
            method="POST",
            path_template="/reviewed/{path}",
            summary="Reviewed test operation",
            tags=("auth",),
            family="authentication",
            risk_level="write",
            response_class="unreviewed",
            required_permission="netbox_openbao.operate_openbaocluster",
            classified=True,
        )
        for operation_id in operation_ids
    )
    return CapabilityDocument(
        openapi_version="3.0.2",
        product_version="2.6.2",
        digest="b" * 64,
        operations=operations,
    )


class AuthenticationSchemaTest(TestCase):
    BARCODE = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

    def test_auth_mounts_are_typed_sorted_and_unknown_methods_are_ignored(self):
        mounts = normalize_auth_mounts(
            {
                "data": {
                    "userpass/": {
                        "type": "userpass",
                        "accessor": "auth_userpass_1",
                        "description": "People",
                        "local": False,
                        "seal_wrap": False,
                        "config": {"default_lease_ttl": 30, "max_lease_ttl": 60},
                    },
                    "radius/": {
                        "type": "radius",
                        "accessor": "auth_radius_1",
                        "local": False,
                        "seal_wrap": False,
                    },
                    "unsupported/": {
                        "type": "future-auth",
                        "local": False,
                        "seal_wrap": False,
                    },
                }
            }
        )

        self.assertEqual([mount.path for mount in mounts], ["radius", "userpass"])
        self.assertEqual(mounts[1].default_lease_ttl, 30)

    def test_reviewed_config_rejects_unknown_fields_without_echoing_values(self):
        canary = "password-canary-never-echo"

        with self.assertRaises(CapabilitySchemaError) as raised:
            validate_reviewed_payload({"bindpass": canary, "future_field": canary}, AUTH_CONFIG_FIELDS["ldap"])

        self.assertNotIn(canary, str(raised.exception))

    def test_public_metadata_recursively_removes_material_fields(self):
        normalized = normalize_public_auth_data(
            {
                "data": {
                    "url": "ldaps://directory.example.net",
                    "nested": {
                        "token": "token-canary",
                        "bindpass": "password-canary",
                        "name": "directory",
                    },
                }
            }
        )

        self.assertEqual(normalized["url"], "ldaps://directory.example.net")
        self.assertEqual(normalized["nested"], {"name": "directory"})

    def test_totp_barcode_must_be_a_bounded_base64_png(self):
        accepted = normalize_totp_setup_result({"data": {"url": "otpauth://totp/example", "barcode": self.BARCODE}})
        self.assertEqual(accepted.barcode, self.BARCODE)
        for barcode in ("not-base64", "dGV4dA=="):
            with self.subTest(barcode=barcode), self.assertRaises(CapabilitySchemaError):
                normalize_totp_setup_result({"data": {"url": "otpauth://totp/example", "barcode": barcode}})

    def test_authentication_result_is_redacted_but_returns_one_shot_material(self):
        result = normalize_authentication_result(
            {
                "auth": {
                    "client_token": "token-canary",
                    "accessor": "accessor",
                    "policies": ["default"],
                    "identity_policies": [],
                    "metadata": {"username": "alice", "token": "metadata-canary"},
                    "lease_duration": 60,
                    "renewable": True,
                    "entity_id": "entity",
                    "token_type": "service",
                }
            }
        )

        self.assertEqual(repr(result), "<AuthenticationResult redacted>")
        self.assertEqual(result.as_dict()["client_token"], "token-canary")
        self.assertEqual(result.metadata, {"username": "alice"})

    def test_requested_oidc_material_metadata_is_returned_once_but_redacted_from_repr(self):
        result = normalize_authentication_result(
            {
                "auth": {
                    "client_token": "token-canary",
                    "metadata": {
                        "username": "alice",
                        "access_token": "access-token-canary",
                        "id_token": "id-token-canary",
                        "refresh_token": "refresh-token-canary",
                    },
                }
            }
        )

        self.assertEqual(result.metadata, {"username": "alice"})
        self.assertEqual(
            result.as_dict()["metadata"],
            {
                "username": "alice",
                "access_token": "access-token-canary",
                "id_token": "id-token-canary",
                "refresh_token": "refresh-token-canary",
            },
        )
        self.assertNotIn("token-canary", repr(result))

    def test_oidc_start_rejects_insecure_and_mismatched_authorization_urls(self):
        with self.assertRaisesRegex(CapabilitySchemaError, "insecure"):
            normalize_oidc_start({"data": {"auth_url": "http://idp.example.net/auth?state=state", "state": "state"}})
        with self.assertRaisesRegex(CapabilitySchemaError, "mismatched"):
            normalize_oidc_start({"data": {"auth_url": "https://idp.example.net/auth?state=other", "state": "state"}})

    def test_oidc_role_writes_and_login_require_direct_callback_mode(self):
        base = {"role_type": "oidc", "user_claim": "sub"}

        with self.assertRaisesRegex(CapabilitySchemaError, "direct"):
            validate_auth_resource_payload("jwt-roles", "oidc", "write", base)
        with self.assertRaisesRegex(CapabilitySchemaError, "direct"):
            validate_auth_resource_payload("jwt-roles", "oidc", "write", {**base, "callback_mode": "client"})
        accepted = validate_auth_resource_payload("jwt-roles", "oidc", "write", {**base, "callback_mode": "direct"})
        self.assertEqual(accepted["callback_mode"], "direct")
        self.assertIs(accepted["oidc_disable_confirmation"], False)
        self.assertIs(accepted["verbose_oidc_logging"], False)
        with self.assertRaisesRegex(CapabilitySchemaError, "direct"):
            validate_direct_oidc_role({"data": {**base, "callback_mode": "device"}})

    def test_oidc_role_rejects_confirmation_bypass_and_verbose_material_logging(self):
        base = {"role_type": "oidc", "user_claim": "sub", "callback_mode": "direct"}

        for forbidden in ("oidc_disable_confirmation", "verbose_oidc_logging"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(CapabilitySchemaError, "unsupported"):
                    validate_auth_resource_payload("jwt-roles", "oidc", "write", {**base, forbidden: True})
                with self.assertRaisesRegex(CapabilitySchemaError, "forbidden"):
                    validate_direct_oidc_role({"data": {**base, forbidden: True}})

    def test_mfa_method_fields_match_openbao_2_6_2_boundaries(self):
        valid = validate_reviewed_payload(
            {"issuer": "N-MultiCloud", "digits": 8, "skew": 1, "period": 30, "key_size": 20},
            MFA_METHOD_FIELDS["totp"],
        )
        self.assertEqual(valid["digits"], 8)
        invalid_cases = (
            ("totp", {"issuer": "N-MultiCloud", "digits": 7}),
            ("totp", {"issuer": "N-MultiCloud", "skew": 2}),
            ("totp", {"issuer": "N-MultiCloud", "period": 0}),
            ("totp", {"issuer": "N-MultiCloud", "key_size": 0}),
            ("totp", {"digits": 6}),
            ("duo", {"api_hostname": "api.example", "integration_key": "key"}),
            ("okta", {"org_name": "example"}),
            ("pingid", {}),
            ("pingid", {"settings_file_base64": "not-base64"}),
        )
        for method_type, payload in invalid_cases:
            with self.subTest(method_type=method_type, payload=payload):
                with self.assertRaises(CapabilitySchemaError):
                    validate_reviewed_payload(payload, MFA_METHOD_FIELDS[method_type])

    def test_oidc_authorization_url_hostile_branches(self):
        rejected = (
            "https://user@idp.example/auth?state=expected",
            "https://idp.example/auth?state=expected#fragment",
            "https:///auth?state=expected",
            "ftp://idp.example/auth?state=expected",
            "http://idp.example/auth?state=expected",
            "https://idp.example/auth",
            "https://idp.example/auth?state=expected&state=expected",
            "https://idp.example/auth?state=",
            "https://idp.example/auth?state=wrong",
            "https://[::1/auth?state=expected",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(CapabilitySchemaError):
                validate_authorization_url(url, "expected")
        for url in (
            "https://idp.example/auth?state=expected",
            "http://127.0.0.1/auth?state=expected",
            "http://localhost/auth?state=expected",
            "https://idp.example/auth?state=expected,ns=parent",
        ):
            with self.subTest(url=url):
                validate_authorization_url(url, "expected")

    def test_mfa_requirement_hostile_branches(self):
        valid_method = {
            "id": "11111111-1111-4111-8111-111111111111",
            "type": "totp",
            "uses_passcode": True,
        }
        rejected = (
            None,
            {},
            {"mfa_request_id": "request", "mfa_constraints": []},
            {"mfa_request_id": "request", "mfa_constraints": {"primary": []}},
            {"mfa_request_id": "request", "mfa_constraints": {"primary": {}}},
            {"mfa_request_id": "request", "mfa_constraints": {"primary": {"any": []}}},
            {"mfa_request_id": "request", "mfa_constraints": {"primary": {"any": [None]}}},
            {
                "mfa_request_id": "request",
                "mfa_constraints": {f"constraint-{index}": {"any": [valid_method]} for index in range(33)},
            },
            {
                "mfa_request_id": "request",
                "mfa_constraints": {"primary": {"any": [valid_method] * 17}},
            },
            {
                "mfa_request_id": "request",
                "mfa_constraints": {"primary": {"any": [{**valid_method, "type": "future"}]}},
            },
            {
                "mfa_request_id": "request",
                "mfa_constraints": {"primary": {"any": [{**valid_method, "id": "not-a-uuid"}]}},
            },
            {
                "mfa_request_id": "request",
                "mfa_constraints": {"primary": {"any": [{**valid_method, "uses_passcode": "yes"}]}},
            },
        )
        for requirement in rejected:
            with self.subTest(requirement=requirement), self.assertRaises(CapabilitySchemaError):
                normalize_authentication_result({"auth": {"mfa_requirement": requirement}})
        result = normalize_authentication_result(
            {
                "auth": {
                    "mfa_requirement": {
                        "mfa_request_id": "request",
                        "mfa_constraints": {"primary": {"any": [valid_method]}},
                    }
                }
            }
        )
        self.assertEqual(result.mfa_requirement.constraints["primary"][0].method_type, "totp")


class AuthenticationBackendTest(TestCase):
    def setUp(self):
        super().setUp()
        self.cluster = SimpleNamespace(
            api_url="https://bao.example.net:8200",
            ca_cert_path="",
            tls_verify=True,
            namespace="",
            env_prefix="NETBOX_BAO_TEST",
        )
        self.backend = DirectAdministrationBackend(self.cluster)
        self.client = Mock(token="cluster-service-token")
        self.session = Mock()

    def patch_transport(self):
        return (
            patch.object(self.backend.backend, "_get_client", return_value=self.client),
            patch.object(self.backend.backend, "_get_session", return_value=self.session),
        )

    def test_submitted_token_is_request_scoped_and_does_not_replace_service_token(self):
        self.session.request.return_value = _Response(json.dumps({"data": {"id": "root"}}).encode())
        client_patch, session_patch = self.patch_transport()

        with client_patch as get_client, session_patch:
            result = self.backend.token_operation("lookup-self", {"token": "submitted-token-canary"})

        self.assertEqual(result, {"id": "root"})
        get_client.assert_not_called()
        headers = self.session.request.call_args.kwargs["headers"]
        self.assertEqual(headers["X-Vault-Token"], "submitted-token-canary")
        self.assertNotIn("cluster-service-token", str(self.session.request.call_args))

    def test_totp_self_setup_uses_only_the_submitted_request_token(self):
        self.session.request.return_value = _Response(
            json.dumps(
                {"data": {"url": "otpauth://totp/example", "barcode": AuthenticationSchemaTest.BARCODE}}
            ).encode()
        )
        client_patch, session_patch = self.patch_transport()

        with client_patch as get_client, session_patch:
            result = self.backend.setup_totp(
                "11111111-1111-4111-8111-111111111111",
                token="submitted-token-canary",
            )

        self.assertEqual(result.url, "otpauth://totp/example")
        get_client.assert_not_called()
        request = self.session.request.call_args
        self.assertEqual(
            request.args[:2], ("POST", "https://bao.example.net:8200/v1/identity/mfa/method/totp/generate")
        )
        self.assertEqual(request.kwargs["headers"]["X-Vault-Token"], "submitted-token-canary")
        self.assertNotIn("cluster-service-token", str(request))

    def test_resource_write_accepts_empty_204_without_json_parsing(self):
        self.session.request.return_value = _Response(b"", status_code=204)
        client_patch, session_patch = self.patch_transport()
        from netbox_openbao.administration.authentication import resource_spec

        spec = resource_spec("userpass-users", "userpass", "write")
        with client_patch, session_patch:
            result = self.backend.run_auth_resource(
                "userpass", spec, "write", name="alice", payload={"password": "password-canary"}
            )

        self.assertEqual(result, {})
        self.assertEqual(self.session.request.call_args.args[0], "POST")
        self.assertTrue(self.session.request.return_value.closed)

    def test_approle_role_id_uses_its_dedicated_read_and_write_paths(self):
        self.session.request.side_effect = (
            _Response(json.dumps({"data": {"role_id": "role-id"}}).encode()),
            _Response(b"", status_code=204),
        )
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch:
            result = self.backend.read_approle_role_id("approle", "automation")
            self.backend.write_approle_role_id("approle", "automation", "replacement-role-id")

        self.assertEqual(result, {"role_id": "role-id"})
        first, second = self.session.request.call_args_list
        self.assertEqual(
            first.args[:2], ("GET", "https://bao.example.net:8200/v1/auth/approle/role/automation/role-id")
        )
        self.assertEqual(
            second.args[:2], ("POST", "https://bao.example.net:8200/v1/auth/approle/role/automation/role-id")
        )
        self.assertEqual(second.kwargs["json"], {"role_id": "replacement-role-id"})

    def test_empty_mfa_list_404_becomes_an_empty_bounded_collection(self):
        self.session.request.return_value = _Response(b"", status_code=404)
        client_patch, session_patch = self.patch_transport()

        with client_patch, session_patch:
            result = self.backend.list_mfa_methods()

        self.assertEqual(result, {"keys": [], "key_info": {}})
        self.assertEqual(self.session.request.call_args.args[0], "LIST")

    def test_radius_uses_reviewed_config_user_and_login_paths(self):
        self.session.request.side_effect = (
            _Response(b"", status_code=204),
            _Response(b"", status_code=204),
            _Response(json.dumps({"auth": {"client_token": "radius-token"}}).encode()),
        )
        client_patch, session_patch = self.patch_transport()
        with client_patch, session_patch:
            self.backend.write_auth_config("radius", {"host": "127.0.0.1", "secret": "shared-secret"})
            self.backend.run_auth_resource(
                "radius",
                resource_spec("radius-users", "radius", "write"),
                "write",
                name="alice",
                payload={"policies": ["default"]},
            )
            result = self.backend.authenticate("radius", "radius", {"username": "alice", "password": "password"})
        paths = [call.args[1] for call in self.session.request.call_args_list]
        self.assertEqual(
            paths,
            [
                "https://bao.example.net:8200/v1/auth/radius/config",
                "https://bao.example.net:8200/v1/auth/radius/users/alice",
                "https://bao.example.net:8200/v1/auth/radius/login/alice",
            ],
        )
        self.assertEqual(result.client_token, "radius-token")

    def test_mutation_transport_and_parse_uncertainty_are_explicit(self):
        client_patch, session_patch = self.patch_transport()
        self.session.request.side_effect = TimeoutError("after dispatch")
        with client_patch, session_patch, self.assertRaises(OpenBaoMutationUnknown):
            self.backend.write_auth_config("radius", {"host": "127.0.0.1", "secret": "shared-secret"})
        self.assertEqual(self.session.request.call_count, 1)

        self.session.reset_mock()
        self.session.request.side_effect = None
        self.session.request.return_value = _Response(b"not-json")
        client_patch, session_patch = self.patch_transport()
        with client_patch, session_patch, self.assertRaises(OpenBaoMutationUnknown):
            self.backend.write_mfa_method("totp", {"issuer": "N-MultiCloud"})
        self.assertEqual(self.session.request.call_count, 1)

        self.session.reset_mock()
        self.session.request.return_value = _Response(json.dumps({"data": {}}).encode())
        client_patch, session_patch = self.patch_transport()
        with client_patch, session_patch, self.assertRaises(OpenBaoMutationUnknown):
            self.backend.issue_approle_secret_id("approle", "automation", {})
        self.assertEqual(self.session.request.call_count, 1)

        self.session.reset_mock()
        self.session.request.side_effect = TimeoutError("after destructive dispatch")
        client_patch, session_patch = self.patch_transport()
        with client_patch, session_patch, self.assertRaises(OpenBaoMutationUnknown):
            self.backend.destroy_totp_setup(
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            )
        self.assertEqual(self.session.request.call_count, 1)

    def test_totp_self_reset_looks_up_the_token_entity_before_admin_destroy(self):
        self.session.request.side_effect = (
            _Response(json.dumps({"data": {"entity_id": "11111111-1111-4111-8111-111111111111"}}).encode()),
            _Response(b"", status_code=204),
        )
        client_patch, session_patch = self.patch_transport()
        with client_patch, session_patch:
            result = self.backend.reset_totp_setup(
                "22222222-2222-4222-8222-222222222222",
                "submitted-token-canary",
            )
        first, second = self.session.request.call_args_list
        self.assertEqual(first.args[:2], ("GET", "https://bao.example.net:8200/v1/auth/token/lookup-self"))
        self.assertEqual(first.kwargs["headers"]["X-Vault-Token"], "submitted-token-canary")
        self.assertEqual(
            second.args[:2],
            ("POST", "https://bao.example.net:8200/v1/identity/mfa/method/totp/admin-destroy"),
        )
        self.assertEqual(
            second.kwargs["json"],
            {
                "method_id": "22222222-2222-4222-8222-222222222222",
                "entity_id": "11111111-1111-4111-8111-111111111111",
            },
        )
        self.assertEqual(result, {"reset": True})


class AuthenticationSerializerTest(TestCase):
    def test_enable_groups_reviewed_tuning_fields_under_config(self):
        serializer = EnableAuthMethodSerializer(
            data={
                "mount_path": "userpass",
                "method_type": "userpass",
                "description": "People",
                "plugin_version": "v1.2.3",
                "options": {"version": "2"},
                "default_lease_ttl": 60,
                "audit_non_hmac_request_keys": ["username"],
                "user_lockout_config": {"lockout_threshold": "5"},
                "reason": "Enable the reviewed mount.",
            }
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(
            serializer.openbao_payload(),
            {
                "type": "userpass",
                "description": "People",
                "plugin_version": "v1.2.3",
                "options": {"version": "2"},
                "config": {
                    "default_lease_ttl": 60,
                    "audit_non_hmac_request_keys": ["username"],
                    "user_lockout_config": {"lockout_threshold": "5"},
                },
            },
        )

    def test_tuning_rejects_unreviewed_and_oversized_option_maps(self):
        unknown = TuneAuthMethodSerializer(data={"reason": "Tune the mount.", "future": "unsupported"})
        oversized = TuneAuthMethodSerializer(
            data={
                "reason": "Tune the mount.",
                "options": {f"key{index}": "value" for index in range(65)},
            }
        )

        self.assertFalse(unknown.is_valid())
        self.assertFalse(oversized.is_valid())


class FakeAuthenticationBackend:
    def __init__(self, cluster, *operation_ids):
        self.cluster = cluster
        self.calls = []
        self.document = capability_document(*operation_ids)
        self.mounts = tuple(
            AuthMount(
                path=method_type,
                method_type=method_type,
                accessor=f"auth_{method_type}_1",
                description=method_type.title(),
                local=False,
                seal_wrap=False,
                default_lease_ttl=0,
                max_lease_ttl=0,
                token_type="default-service",
                plugin_version="",
                running_plugin_version="",
            )
            for method_type in ("token", "userpass", "approle", "oidc", "radius")
        )
        self.oidc_consumed = False

    def seal_status(self):
        return SealStatus(
            initialized=True,
            sealed=False,
            threshold=3,
            shares=5,
            progress=0,
            version="2.6.2",
            seal_type="shamir",
            migration=False,
            recovery_seal=False,
            storage_type="raft",
            cluster_name="test",
            cluster_id="cluster-id",
        )

    def discover_capabilities(self):
        return self.document

    def list_auth_methods(self):
        return self.mounts

    def write_auth_config(self, mount_path, payload):
        self.calls.append(("write-auth-config", mount_path, payload))

    def read_auth_config(self, mount_path):
        self.calls.append(("read-auth-config", mount_path))
        return {"mount_path": mount_path}

    def authenticate(self, method_type, mount_path, payload):
        self.calls.append(("authenticate", method_type, mount_path, payload))
        return AuthenticationResult(
            client_token="issued-token-canary",
            accessor="accessor-canary",
            policies=("default",),
            lease_duration=60,
            renewable=True,
        )

    def oidc_start(self, mount_path, role, redirect_uri, client_nonce):
        self.calls.append(("oidc-start", mount_path, role, redirect_uri, client_nonce))
        return OIDCStartResult(
            auth_url="https://idp.example.net/authorize?state=state-canary",
            state="state-canary",
            poll_interval=5,
        )

    def read_direct_oidc_role(self, mount_path, role):
        self.calls.append(("oidc-role", mount_path, role))
        return {"role_type": "oidc", "callback_mode": "direct"}

    def oidc_poll(self, mount_path, state, client_nonce):
        if self.oidc_consumed:
            raise OpenBaoConflict("The OIDC result was already consumed.")
        self.oidc_consumed = True
        self.calls.append(("oidc-poll", mount_path, state, client_nonce))
        return AuthenticationResult(client_token="oidc-token-canary", lease_duration=60)

    def disable_auth_method(self, mount_path):
        self.calls.append(("disable", mount_path))

    def token_operation(self, operation, payload):
        self.calls.append(("token", operation, payload))
        if operation.startswith("renew"):
            return AuthenticationResult(client_token="renewed-token-canary", lease_duration=60)
        if operation.startswith("lookup"):
            return {"id": "token-id", "renewable": True}
        return None

    def read_approle_role_id(self, mount_path, role_name):
        self.calls.append(("read-role-id", mount_path, role_name))
        return {"role_id": "role-id"}

    def write_approle_role_id(self, mount_path, role_name, role_id):
        self.calls.append(("write-role-id", mount_path, role_name, role_id))

    def list_mfa_methods(self):
        self.calls.append(("list-mfa-methods",))
        return {"keys": ["method-id"]}

    def write_mfa_method(self, method_type, payload, *, method_id=""):
        self.calls.append(("write-mfa-method", method_type, payload, method_id))
        return {"method_id": method_id or "generated-id"}

    def setup_totp(self, method_id, *, entity_id="", administrator=False, token=""):
        self.calls.append(("setup-totp", method_id, entity_id, administrator, token))
        return TOTPSetupResult(url="otpauth://totp/example", barcode=AuthenticationSchemaTest.BARCODE)

    def reset_totp_setup(self, method_id, token):
        self.calls.append(("reset-totp", method_id, token))
        return {"reset": True}

    def run_auth_resource(self, mount_path, spec, operation, *, name="", payload=None):
        self.calls.append(("resource", mount_path, spec.key, operation, name, payload))
        return {"operation": operation, "name": name}


class AuthenticationAPITest(OpenBaoAdministrationTestCase):
    def url(self, action, **kwargs):
        return reverse(
            f"plugins-api:netbox_openbao-api:openbaocluster-{action}",
            kwargs={"pk": self.cluster.pk, **kwargs},
        )

    @patch.object(authentication_views, "get_administration_backend")
    def test_radius_config_resource_and_login_use_reviewed_contracts(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "radius-configure",
            "radius-write-user",
            "radius-login-with-username",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_auth_methods_openbaocluster",
            "netbox_openbao.manage_auth_resources_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )
        configured = self.client.post(
            self.url("auth-config", mount_path="radius"),
            {
                "payload": {"host": "127.0.0.1", "secret": "radius-secret-canary"},
                "reason": "Configure the reviewed RADIUS mount.",
            },
            format="json",
            **self.header,
        )
        written = self.client.post(
            self.url("auth-resource", mount_path="radius", resource_key="radius-users", name="alice"),
            {"payload": {"policies": ["default"]}, "reason": "Create the RADIUS user."},
            format="json",
            **self.header,
        )
        logged_in = self.client.post(
            self.url("auth-login", mount_path="radius"),
            {
                "method_type": "radius",
                "username": "alice",
                "password": "radius-password-canary",
                "reason": "Exercise RADIUS login.",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(configured.status_code, 200, configured.content)
        self.assertEqual(written.status_code, 200, written.content)
        self.assertEqual(logged_in.status_code, 200, logged_in.content)
        audit_text = " ".join(
            str(value) for entry in OpenBaoAdministrationLog.objects.all().values() for value in entry.values()
        )
        self.assertNotIn("radius-secret-canary", audit_text)
        self.assertNotIn("radius-password-canary", audit_text)

    @patch.object(authentication_views, "get_administration_backend")
    def test_login_requires_dedicated_permission_and_never_audits_material(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )
        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Interactive authentication test.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.data["client_token"], "issued-token-canary")
        audit_text = " ".join(
            str(value) for entry in OpenBaoAdministrationLog.objects.all().values() for value in entry.values()
        )
        self.assertNotIn("password-canary", audit_text)
        self.assertNotIn("issued-token-canary", audit_text)

    @patch.object(authentication_views, "get_administration_backend")
    def test_login_rejects_unknown_fields_before_the_backend_call(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Interactive authentication test.",
                "future_field": "secret-canary",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(backend.calls, [])
        self.assertNotIn("secret-canary", response.content.decode())

    @patch.object(authentication_views, "get_administration_backend")
    def test_login_permission_is_independent_from_cluster_view(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        get_backend.return_value = backend
        self.add_permissions("netbox_openbao.view_openbaocluster")

        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Interactive authentication test.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(backend.calls, [])
        get_backend.assert_not_called()

    @patch.object(authentication_views, "get_administration_backend")
    def test_login_requires_csrf_for_a_session_authenticated_request(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)

        response = csrf_client.post(
            self.url("auth-login", mount_path="userpass"),
            data=json.dumps(
                {
                    "method_type": "userpass",
                    "username": "alice",
                    "password": "password-canary",
                    "reason": "Interactive authentication test.",
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(backend.calls, [])
        get_backend.assert_not_called()

    @patch.object(authentication_views, "log_administration")
    @patch.object(authentication_views, "get_administration_backend")
    def test_completion_audit_failure_returns_material_once_without_retry(self, get_backend, audit):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        get_backend.return_value = backend
        audit.side_effect = (None, None, AdministrationAuditError("database diagnostic"))
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Interactive authentication test.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["outcome"], "accepted-audit-incomplete")
        self.assertEqual(response.data["client_token"], "issued-token-canary")
        self.assertEqual([call[0] for call in backend.calls], ["authenticate"])

    @patch.object(authentication_views, "get_administration_backend")
    def test_token_lookup_renew_and_revoke_use_exact_contracts(self, get_backend):
        operations = (
            "token-look-up-self-get",
            "token-renew-self",
            "token-revoke-self",
        )
        backend = FakeAuthenticationBackend(self.cluster, *operations)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_tokens_openbaocluster",
            "netbox_openbao.revoke_tokens_openbaocluster",
        )
        base = {"token": "submitted-token-canary", "reason": "Manage this request-scoped token."}

        lookup = self.client.post(self.url("auth-token", operation="lookup-self"), base, format="json", **self.header)
        renew = self.client.post(
            self.url("auth-token", operation="renew-self"),
            {**base, "increment": 60},
            format="json",
            **self.header,
        )
        revoke = self.client.post(
            self.url("auth-token", operation="revoke-self"),
            {**base, "confirmation": f"REVOKE TOKEN ON {self.cluster.slug}"},
            format="json",
            **self.header,
        )

        self.assertEqual((lookup.status_code, renew.status_code, revoke.status_code), (200, 200, 200))
        self.assertEqual(renew.data["client_token"], "renewed-token-canary")
        self.assertEqual([call[1] for call in backend.calls], ["lookup-self", "renew-self", "revoke-self"])

    @patch.object(authentication_views, "get_administration_backend")
    def test_login_refuses_a_method_that_does_not_match_the_mount(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "ldap-login")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "ldap",
                "username": "alice",
                "password": "password-canary",
                "reason": "Reject a mismatched login mount.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(backend.calls, [])

    @patch.object(authentication_views, "get_administration_backend")
    def test_oidc_role_write_refuses_client_callback_mode_before_mutation(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "jwt-write-role")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_auth_resources_openbaocluster",
        )

        response = self.client.post(
            self.url(
                "auth-resource",
                mount_path="oidc",
                resource_key="jwt-roles",
                name="people",
            ),
            {
                "payload": {
                    "role_type": "oidc",
                    "user_claim": "sub",
                    "callback_mode": "client",
                },
                "reason": "Reject a browser callback through NetBox.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(backend.calls, [])

    @patch.object(authentication_views, "get_administration_backend")
    def test_oidc_role_write_refuses_unsafe_logging_and_confirmation_fields(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "jwt-write-role")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_auth_resources_openbaocluster",
        )

        for forbidden in ("oidc_disable_confirmation", "verbose_oidc_logging"):
            with self.subTest(forbidden=forbidden):
                response = self.client.post(
                    self.url(
                        "auth-resource",
                        mount_path="oidc",
                        resource_key="jwt-roles",
                        name="people",
                    ),
                    {
                        "payload": {
                            "role_type": "oidc",
                            "user_claim": "sub",
                            "callback_mode": "direct",
                            forbidden: True,
                        },
                        "reason": "Reject unsafe OIDC role settings.",
                    },
                    format="json",
                    **self.header,
                )
                self.assertEqual(response.status_code, 400)
        self.assertEqual(backend.calls, [])

    @patch.object(authentication_views, "get_administration_backend")
    def test_approle_role_id_read_uses_the_dedicated_contract(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "app-role-read-role-id",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_authentication_openbaocluster",
        )

        response = self.client.get(
            self.url("approle-role-id", mount_path="approle", role_name="automation"),
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data, {"role_id": "role-id"})
        self.assertEqual(backend.calls, [("read-role-id", "approle", "automation")])

    @patch.object(authentication_views, "get_administration_backend")
    def test_mfa_list_and_create_are_separately_permissioned(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "mfa-list-methods",
            "mfa-configure-totp-method",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_authentication_openbaocluster",
            "netbox_openbao.manage_mfa_openbaocluster",
        )

        listed = self.client.get(self.url("auth-mfa-methods"), **self.header)
        created = self.client.post(
            self.url("auth-mfa-method-create", method_type="totp"),
            {
                "payload": {"method_name": "Primary TOTP", "issuer": "N-MultiCloud"},
                "reason": "Create the primary TOTP method.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(listed.status_code, 200, listed.content)
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["method_id"], "generated-id")
        self.assertEqual([call[0] for call in backend.calls], ["list-mfa-methods", "write-mfa-method"])

    @patch.object(authentication_views, "get_administration_backend")
    def test_totp_self_setup_uses_authentication_permission_and_returns_material_once(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "mfa-generate-totp-secret",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.post(
            self.url("auth-mfa-totp-self", method_id="11111111-1111-4111-8111-111111111111"),
            {"token": "submitted-token-canary", "reason": "Enroll this token entity in TOTP."},
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["url"], "otpauth://totp/example")
        self.assertEqual(
            backend.calls,
            [
                (
                    "setup-totp",
                    "11111111-1111-4111-8111-111111111111",
                    "",
                    False,
                    "submitted-token-canary",
                )
            ],
        )
        audit_text = " ".join(
            str(value) for entry in OpenBaoAdministrationLog.objects.all().values() for value in entry.values()
        )
        self.assertNotIn("submitted-token-canary", audit_text)

    @patch.object(authentication_views, "get_administration_backend")
    def test_totp_self_reset_derives_entity_from_token_and_requires_exact_confirmation(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "mfa-admin-destroy-totp-secret",
            "token-look-up-self-get",
        )
        get_backend.return_value = backend
        self.add_permissions("netbox_openbao.view_openbaocluster", "netbox_openbao.authenticate_openbaocluster")
        url = self.url("auth-mfa-totp-self-reset", method_id="11111111-1111-4111-8111-111111111111")
        rejected = self.client.post(
            url,
            {"token": "submitted-token-canary", "reason": "Restart enrollment.", "confirmation": "wrong"},
            format="json",
            **self.header,
        )
        response = self.client.post(
            url,
            {
                "token": "submitted-token-canary",
                "reason": "Restart enrollment.",
                "confirmation": f"RESET MY TOTP ON {self.cluster.slug}",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            backend.calls,
            [("reset-totp", "11111111-1111-4111-8111-111111111111", "submitted-token-canary")],
        )
        audit_rows = OpenBaoAdministrationLog.objects.filter(action__startswith="reset-self-totp-setup")
        self.assertEqual(
            set(audit_rows.values_list("path_template", flat=True)),
            {"/identity/mfa/method/totp/admin-destroy"},
        )
        self.assertEqual(
            set(audit_rows.values_list("operation_id", flat=True)),
            {"mfa-admin-destroy-totp-secret"},
        )

    @patch.object(authentication_views, "get_administration_backend")
    def test_unknown_mutation_is_preflight_only_material_free_and_not_retried(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        backend.authenticate = Mock(side_effect=OpenBaoMutationUnknown())
        get_backend.return_value = backend
        self.add_permissions("netbox_openbao.view_openbaocluster", "netbox_openbao.authenticate_openbaocluster")
        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Exercise uncertain mutation reporting.",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.data["outcome"], "unknown")
        self.assertEqual(response.data["audit_status"], "preflight-only")
        self.assertIn("do not retry", response.data["message"].lower())
        backend.authenticate.assert_called_once()
        self.assertEqual(OpenBaoAdministrationLog.objects.filter(outcome="unknown").count(), 1)
        self.assertNotIn("password-canary", response.content.decode())

    @patch.object(authentication_views, "get_administration_backend")
    def test_unknown_issuance_and_destructive_mutations_make_one_upstream_call_each(self, get_backend):
        issuance = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "app-role-write-secret-id",
        )
        issuance.issue_approle_secret_id = Mock(side_effect=OpenBaoMutationUnknown())
        get_backend.return_value = issuance
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.issue_auth_material_openbaocluster",
            "netbox_openbao.delete_mfa_openbaocluster",
        )
        issued = self.client.post(
            self.url("approle-secret-id", mount_path="approle", role_name="automation"),
            {"reason": "Issue a one-shot SecretID."},
            format="json",
            **self.header,
        )

        destructive = FakeAuthenticationBackend(self.cluster, "mfa-admin-destroy-totp-secret")
        destructive.destroy_totp_setup = Mock(side_effect=OpenBaoMutationUnknown())
        get_backend.return_value = destructive
        entity_id = "11111111-1111-4111-8111-111111111111"
        destroyed = self.client.delete(
            self.url(
                "auth-mfa-totp",
                method_id="22222222-2222-4222-8222-222222222222",
                entity_id=entity_id,
            ),
            {
                "reason": "Destroy the entity TOTP setup.",
                "confirmation": f"DESTROY TOTP FOR {entity_id} ON {self.cluster.slug}",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(issued.status_code, 503, issued.content)
        self.assertEqual(destroyed.status_code, 503, destroyed.content)
        self.assertEqual(issued.data["outcome"], "unknown")
        self.assertEqual(destroyed.data["outcome"], "unknown")
        issuance.issue_approle_secret_id.assert_called_once()
        destructive.destroy_totp_setup.assert_called_once()
        self.assertEqual(OpenBaoAdministrationLog.objects.filter(outcome="unknown").count(), 2)

    @patch.object(authentication_views, "get_administration_backend")
    def test_malformed_uuid_routes_return_bounded_400_before_backend_access(self, get_backend):
        get_backend.return_value = FakeAuthenticationBackend(self.cluster)
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_authentication_openbaocluster",
            "netbox_openbao.manage_mfa_openbaocluster",
        )
        malformed = "------------------------------------"

        responses = (
            self.client.get(self.url("auth-remount-status", migration_id=malformed), **self.header),
            self.client.get(
                self.url("auth-mfa-method", method_type="totp", method_id=malformed),
                **self.header,
            ),
            self.client.post(
                self.url("auth-mfa-totp", method_id=malformed, entity_id=malformed),
                {"reason": "Reject malformed UUID route values."},
                format="json",
                **self.header,
            ),
        )

        self.assertEqual([response.status_code for response in responses], [400, 400, 400])
        get_backend.assert_not_called()

    @patch.object(authentication_views, "get_administration_backend")
    def test_unexpected_backend_failure_never_echoes_material(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-list-enabled-methods", "userpass-login")
        backend.authenticate = Mock(side_effect=RuntimeError("password-canary exception"))
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.post(
            self.url("auth-login", mount_path="userpass"),
            {
                "method_type": "userpass",
                "username": "alice",
                "password": "password-canary",
                "reason": "Exercise scrubbed failure reporting.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("password-canary", response.content.decode())
        audit_text = " ".join(
            str(value) for entry in OpenBaoAdministrationLog.objects.all().values() for value in entry.values()
        )
        self.assertNotIn("password-canary", audit_text)

    @patch.object(authentication_views, "get_administration_backend")
    def test_auth_resource_list_read_write_and_delete_branches(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "userpass-list-users",
            "userpass-read-user",
            "userpass-write-user",
            "userpass-delete-user",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_authentication_openbaocluster",
            "netbox_openbao.manage_auth_resources_openbaocluster",
            "netbox_openbao.delete_auth_resources_openbaocluster",
        )
        collection = self.url(
            "auth-resource",
            mount_path="userpass",
            resource_key="userpass-users",
        )
        item = self.url(
            "auth-resource",
            mount_path="userpass",
            resource_key="userpass-users",
            name="alice",
        )

        listed = self.client.get(collection, **self.header)
        read = self.client.get(item, **self.header)
        written = self.client.post(
            item,
            {"payload": {"policies": ["default"]}, "reason": "Update the user policies."},
            format="json",
            **self.header,
        )
        deleted = self.client.delete(
            item,
            {
                "reason": "Retire the obsolete user.",
                "confirmation": f"DELETE AUTH RESOURCE userpass-users/alice ON {self.cluster.slug}",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(
            (listed.status_code, read.status_code, written.status_code, deleted.status_code),
            (200, 200, 200, 200),
        )
        self.assertEqual(
            [call[3] for call in backend.calls],
            ["list", "read", "write", "delete"],
        )
        audits = {
            entry.action: (entry.method, entry.path_template)
            for entry in OpenBaoAdministrationLog.objects.filter(
                action__in={
                    "list-auth-resource",
                    "read-auth-resource",
                    "write-auth-resource",
                    "delete-auth-resource",
                }
            )
        }
        self.assertEqual(audits["list-auth-resource"], ("LIST", "/auth/{mount_path}/users"))
        self.assertEqual(audits["read-auth-resource"], ("GET", "/auth/{mount_path}/users/{name}"))
        self.assertEqual(audits["write-auth-resource"], ("POST", "/auth/{mount_path}/users/{name}"))
        self.assertEqual(audits["delete-auth-resource"], ("DELETE", "/auth/{mount_path}/users/{name}"))


class AuthenticationAdministrationUITest(OpenBaoAdministrationTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def url(self, action, **kwargs):
        return reverse(
            f"plugins-api:netbox_openbao-api:openbaocluster-{action}",
            kwargs={"pk": self.cluster.pk, **kwargs},
        )

    def test_workspace_requires_dedicated_permission_and_is_never_storable(self):
        url = reverse(
            "plugins:netbox_openbao:openbaocluster_authentication",
            kwargs={"pk": self.cluster.pk},
        )
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_authentication_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertContains(response, "Request-scoped login")
        self.assertContains(response, "<option>list</option>", count=3, html=True)
        self.assertContains(response, "<option>read</option>", count=4, html=True)
        self.assertNotContains(response, "<option>write</option>", html=True)
        self.assertNotContains(response, "<option>create</option>", html=True)
        self.assertContains(response, "authentication_administration.js")
        self.assertTrue(OpenBaoAdministrationLog.objects.filter(action="authentication-administration-ui").exists())

    def test_oidc_callback_encodes_root_and_nested_namespaces(self):
        root = SimpleNamespace(api_url="https://bao.example.net:8200", namespace="")
        nested = SimpleNamespace(api_url="https://bao.example.net:8200", namespace="parent/blue team")

        self.assertEqual(
            authentication_views.AuthenticationAdministrationMixin._oidc_callback(root, "oidc"),
            "https://bao.example.net:8200/v1/auth/oidc/oidc/callback",
        )
        self.assertEqual(
            authentication_views.AuthenticationAdministrationMixin._oidc_callback(nested, "oidc"),
            "https://bao.example.net:8200/v1/parent/blue%20team/auth/oidc/oidc/callback",
        )
        trailing = SimpleNamespace(api_url="https://bao.example.net:8200", namespace="/parent/blue team/")
        self.assertEqual(
            authentication_views.AuthenticationAdministrationMixin._oidc_callback(trailing, "oidc"),
            "https://bao.example.net:8200/v1/parent/blue%20team/auth/oidc/oidc/callback",
        )
        with self.assertRaisesRegex(authentication_views.DRFValidationError, "namespace"):
            authentication_views.AuthenticationAdministrationMixin._oidc_callback(
                SimpleNamespace(api_url="https://bao.example.net:8200", namespace="parent//child"),
                "oidc",
            )

    @patch.object(authentication_views, "get_administration_backend")
    def test_oidc_envelope_binds_nonce_user_cluster_and_mount(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "jwt-oidc-request-authorization-url",
            "jwt-read-role",
            "jwt-write-oidc-poll",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )
        start = self.client.post(
            self.url("auth-oidc-start", mount_path="oidc"),
            {"role": "people", "reason": "Authenticate with the corporate IdP."},
            format="json",
            **self.header,
        )
        self.assertEqual(start.status_code, 200, start.content)
        self.assertIn("no-store", start["Cache-Control"])
        self.assertEqual(
            backend.calls[1][3],
            "https://bao.example.net:8200/v1/auth/oidc/oidc/callback",
        )

        poll = self.client.post(
            self.url("auth-oidc-poll", mount_path="oidc"),
            {
                "state": start.data["state"],
                "client_nonce": "A" * 43,
                "envelope": start.data["envelope"],
                "reason": "Authenticate with the corporate IdP.",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(poll.status_code, 400)
        self.assertEqual([call[0] for call in backend.calls], ["oidc-role", "oidc-start"])

    @patch.object(authentication_views, "get_administration_backend")
    def test_oidc_poll_returns_material_once_and_upstream_refuses_replay(self, get_backend):
        backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "jwt-oidc-request-authorization-url",
            "jwt-read-role",
            "jwt-write-oidc-poll",
        )
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.authenticate_openbaocluster",
        )
        start = self.client.post(
            self.url("auth-oidc-start", mount_path="oidc"),
            {"role": "people", "reason": "Authenticate with the corporate IdP."},
            format="json",
            **self.header,
        )
        payload = {
            "state": start.data["state"],
            "client_nonce": start.data["client_nonce"],
            "envelope": start.data["envelope"],
            "reason": "Authenticate with the corporate IdP.",
        }

        accepted = self.client.post(
            self.url("auth-oidc-poll", mount_path="oidc"), payload, format="json", **self.header
        )
        replay = self.client.post(self.url("auth-oidc-poll", mount_path="oidc"), payload, format="json", **self.header)

        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(accepted.data["client_token"], "oidc-token-canary")
        self.assertEqual(replay.status_code, 409)
        self.assertEqual([call[0] for call in backend.calls].count("oidc-poll"), 1)

    @patch.object(authentication_views, "get_administration_backend")
    def test_destructive_auth_disable_requires_exact_confirmation(self, get_backend):
        backend = FakeAuthenticationBackend(self.cluster, "auth-disable-method")
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.disable_auth_methods_openbaocluster",
        )

        response = self.client.delete(
            self.url("auth-method", mount_path="userpass"),
            {"reason": "Retire the obsolete mount.", "confirmation": "wrong"},
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(backend.calls, [])
