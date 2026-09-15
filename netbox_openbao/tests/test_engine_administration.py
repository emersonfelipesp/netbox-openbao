"""Secret-engine lifecycle and fail-closed explorer contract tests."""

from dataclasses import replace
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from django.urls import reverse

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.engines import (
    classify_explorer_operations,
    compile_mounted_path,
    compile_operation_path,
    normalize_secret_engine_mounts,
    resolve_explorer_operation,
    validate_bounded_json,
    validate_declared_field_types,
    validate_enable_payload,
    validate_query,
    validate_tune_payload,
)
from netbox_openbao.administration.schema import (
    CapabilityDocument,
    CapabilitySchemaError,
    DiscoveredOperation,
    normalize_openapi_document,
)
from netbox_openbao.backends.exceptions import OpenBaoMutationUnknown
from netbox_openbao.models import OpenBaoAdministrationLog
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase


def capability_document(*operations):
    return CapabilityDocument(
        openapi_version="3.0.2",
        product_version="2.6.2",
        digest="c" * 64,
        operations=operations,
    )


def operation(
    method="GET",
    path="/{secret_mount_path}/data/{path}",
    operation_id="kv-read-data-path",
    risk_level="read",
    body_fields=(),
    required_body_fields=(),
    body_field_types=(),
    query_parameters=(),
    required_query_parameters=(),
    path_parameters=("secret_mount_path", "path"),
    required_path_parameters=("secret_mount_path", "path"),
    path_parameter_types=(("path", "string"), ("secret_mount_path", "string")),
    mount_parameter="secret_mount_path",
):
    return DiscoveredOperation(
        operation_id=operation_id,
        method=method,
        path_template=path,
        summary="Generic mounted operation",
        tags=("secrets",),
        family="mounted-secrets",
        risk_level=risk_level,
        response_class="unreviewed",
        required_permission="",
        classified=True,
        body_fields=body_fields,
        required_body_fields=required_body_fields,
        body_field_types=body_field_types,
        query_parameters=query_parameters,
        required_query_parameters=required_query_parameters,
        path_parameters=path_parameters,
        required_path_parameters=required_path_parameters,
        path_parameter_types=path_parameter_types,
        mount_parameter=mount_parameter,
    )


class EngineContractTest(TestCase):
    def test_mount_metadata_is_bounded_sorted_and_redacted(self):
        mounts = normalize_secret_engine_mounts({
            "data": {
                "transit/": {"type": "transit", "accessor": "transit_1", "config": {}},
                "secret/": {
                    "type": "kv", "accessor": "kv_1", "description": "Credentials",
                    "config": {"default_lease_ttl": 30, "max_lease_ttl": 60},
                    "options": {"token": "must-not-be-retained"},
                },
            }
        })
        self.assertEqual([mount.path for mount in mounts], ["secret", "transit"])
        self.assertEqual(mounts[0].default_lease_ttl, 30)
        self.assertNotIn("must-not-be-retained", repr(mounts))

    def test_enable_contract_rejects_unknown_type_and_field(self):
        self.assertEqual(validate_enable_payload({"type": "kv", "options": {"version": "2"}})["type"], "kv")
        for payload in ({"type": "future"}, {"type": "kv", "url": "https://attacker.example"}):
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                validate_enable_payload(payload)

    def test_lifecycle_nested_fields_have_fixed_types_and_allowlists(self):
        validate_enable_payload({
            "type": "kv",
            "options": {"version": "2"},
            "config": {
                "default_lease_ttl": "5m",
                "max_lease_ttl": 3600,
                "force_no_cache": True,
                "audit_non_hmac_request_keys": ["request_id"],
                "audit_non_hmac_response_keys": ["request_id"],
                "listing_visibility": "hidden",
                "passthrough_request_headers": ["X-Request-ID"],
                "allowed_response_headers": ["X-Request-ID"],
                "allowed_managed_keys": ["key-a"],
                "token_type": "service",
                "plugin_version": "v1.2.3",
                "plugin_name": "custom-kv",
                "user_lockout_config": {
                    "lockout_threshold": 5,
                    "lockout_duration": "15m",
                    "lockout_counter_reset_duration": "1h",
                    "lockout_disable": False,
                },
            },
        })
        validate_tune_payload({
            "listing_visibility": "unauth",
            "plugin_version": "v1.2.3",
            "default_lease_ttl": "5m",
            "allowed_response_headers": ["X-Request-ID"],
            "options": {"version": "2"},
            "user_lockout_config": {"lockout_threshold": 5, "lockout_disable": False},
        })
        invalid = (
            {"type": "kv", "options": {"version": 2}},
            {"type": "kv", "config": {"redirect": "https://attacker.example"}},
            {"type": "kv", "config": {"force_no_cache": "true"}},
            {"type": "kv", "config": {"default_lease_ttl": -1}},
            {"type": "kv", "config": {"max_lease_ttl": 9_223_372_036_854_775_808}},
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                validate_enable_payload(payload)
        for payload in (
            {"listing_visibility": "public"},
            {"allowed_response_headers": "X-Request-ID"},
            {"user_lockout_config": {"unknown": 1}},
            {"user_lockout_config": {"lockout_threshold": True}},
            {"user_lockout_config": {"lockout_duration": 30}},
            {"user_lockout_config": {"lockout_threshold": 18_446_744_073_709_551_616}},
            {"default_lease_ttl": "-1s"},
            {"max_lease_ttl": 60},
        ):
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                validate_tune_payload(payload)

    def test_json_byte_limit_counts_numeric_boolean_and_null_scalars(self):
        huge_integer = 10 ** 4_000
        with self.assertRaisesRegex(CapabilitySchemaError, "too large"):
            validate_bounded_json({"values": [huge_integer] * 300})

    def test_json_and_query_limits_fail_closed_without_echoing_canary(self):
        canary = "secret-canary"
        with self.assertRaises(CapabilitySchemaError) as raised:
            validate_bounded_json({"bad key": canary})
        self.assertNotIn(canary, str(raised.exception))
        with self.assertRaises(CapabilitySchemaError):
            validate_query({"versions": list(range(101))})
        self.assertEqual(validate_query({"versions": [1, 2], "ratio": 1.5}), {"versions": [1, 2], "ratio": 1.5})
        with self.assertRaises(CapabilitySchemaError):
            validate_query({"nested": [{"secret": "value"}]})
        nested = {}
        cursor = nested
        for _ in range(22):
            cursor["child"] = {}
            cursor = cursor["child"]
        with self.assertRaisesRegex(CapabilitySchemaError, "nested too deeply"):
            validate_bounded_json(nested)
        validate_declared_field_types({"versions": [1]}, (("versions", "array"),))
        with self.assertRaisesRegex(CapabilitySchemaError, "invalid JSON type"):
            validate_declared_field_types({"versions": "1"}, (("versions", "array"),))

    def test_path_compiler_rejects_traversal_encoding_and_absolute_urls(self):
        self.assertEqual(compile_mounted_path("secret", "data/team/db"), "/secret/data/team/db")
        for path in ("../sys/seal", "data/%2f/sys", "//attacker.example/path", "https://attacker.example"):
            with self.subTest(path=path), self.assertRaises(CapabilitySchemaError):
                compile_mounted_path("secret", path)
        self.assertEqual(
            compile_operation_path("/{secret_mount_path}/data/{path}", "secret", "team/db", {}),
            "/secret/data/team/db",
        )
        self.assertEqual(
            compile_operation_path("/{secret_mount_path}/keys/{version}", "transit", "", {"version": 2}),
            "/transit/keys/2",
        )
        with self.assertRaises(CapabilitySchemaError):
            compile_operation_path("/{secret_mount_path}/roles/{name}", "database", "", {})

    def test_runtime_generic_path_is_classified_but_unknown_path_is_display_only(self):
        accepted = operation()
        missing_path_contract = operation(path_parameters=(), required_path_parameters=())
        unknown = operation(path="/plugin/config", operation_id="plugin-config")
        spoofed = operation(operation_id="external-plugin-read")
        classified = classify_explorer_operations(
            capability_document(accepted, unknown, spoofed, missing_path_contract)
        )
        self.assertTrue(classified[0].executable)
        self.assertEqual(sum(item.executable for item in classified), 2)
        self.assertFalse(next(item for item in classified if item.path_template == "/plugin/config").executable)
        self.assertEqual(classified[0].response_class, "sensitive-material")
        self.assertEqual(
            classified[0].required_permission,
            "netbox_openbao.reveal_secret_operations_openbaocluster",
        )
        resolved = resolve_explorer_operation(capability_document(accepted), accepted.operation_key)
        self.assertEqual(resolved.method, "GET")
        with self.assertRaises(CapabilitySchemaError):
            resolve_explorer_operation(capability_document(unknown), unknown.operation_key)

    def test_advertised_plugin_list_put_and_destructive_paths_are_classified(self):
        listed = operation(
            method="LIST",
            path="/{secret_mount_path}/roles/{name}",
            operation_id="plugin-list-roles",
            path_parameters=("name", "secret_mount_path"),
            required_path_parameters=("name", "secret_mount_path"),
            path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
        )
        written = replace(listed, method="PUT", operation_id="plugin-put-role")
        revoked = replace(listed, method="POST", path_template="/{secret_mount_path}/revoke/{name}")
        operations = classify_explorer_operations(capability_document(listed, written, revoked))
        self.assertTrue(all(item.executable for item in operations))
        self.assertEqual([item.risk_level for item in operations], ["read", "destructive", "write"])

    def test_destructive_operation_has_a_separate_resource_permission(self):
        destructive = replace(operation(method="DELETE"), risk_level="destructive")
        classified = classify_explorer_operations(capability_document(destructive))
        self.assertEqual(
            classified[0].required_permission,
            "netbox_openbao.delete_secret_operations_openbaocluster",
        )

    def test_duplicate_operation_keys_fail_closed(self):
        duplicate = operation()
        with self.assertRaises(CapabilitySchemaError):
            resolve_explorer_operation(capability_document(duplicate, duplicate), duplicate.operation_key)

    def test_same_engine_operations_on_distinct_mounts_have_distinct_keys(self):
        first = operation(mount_parameter="transit_team_mount_path", operation_id="transit-list-keys")
        second = operation(mount_parameter="transit_backup_mount_path", operation_id="transit-list-keys")

        self.assertNotEqual(first.operation_key, second.operation_key)

    def test_generic_runtime_path_is_mounted_secrets_even_without_tags(self):
        document = normalize_openapi_document({
            "openapi": "3.0.2",
            "info": {"version": "2.6.2"},
            "paths": {
                "/{secret_mount_path}/^.*$": {
                    "get": {"operationId": "external-plugin-read", "summary": "Read", "tags": []}
                }
            },
        })
        self.assertEqual(document.operations[0].family, "mounted-secrets")

    def test_plugin_specific_mount_placeholder_is_canonicalized(self):
        document = normalize_openapi_document({
            "openapi": "3.0.2",
            "info": {"version": "2.6.2"},
            "paths": {
                "/{transit_team_mount_path}/keys/{name}": {
                    "parameters": [
                        {
                            "in": "path", "name": "transit_team_mount_path", "required": True,
                            "schema": {"type": "string"},
                        },
                        {"in": "path", "name": "name", "required": True, "schema": {"type": "string"}},
                    ],
                    "get": {"operationId": "transit-read-key"},
                }
            },
        })
        discovered = document.operations[0]
        self.assertEqual(discovered.path_template, "/{secret_mount_path}/keys/{name}")
        self.assertEqual(discovered.mount_parameter, "transit_team_mount_path")
        self.assertEqual(discovered.path_parameters, ("name", "secret_mount_path"))
        self.assertTrue(classify_explorer_operations(document)[0].executable)

    def test_discovery_retains_bounded_top_level_request_types(self):
        document = normalize_openapi_document({
            "openapi": "3.0.2",
            "info": {"version": "2.6.2"},
            "paths": {
                "/{secret_mount_path}/destroy/{path}": {
                    "parameters": [
                        {"in": "path", "name": "secret_mount_path", "required": True, "schema": {"type": "string"}},
                        {"in": "path", "name": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "post": {
                        "operationId": "kv-write-destroy-path",
                        "summary": "Destroy versions",
                        "tags": ["secrets"],
                        "parameters": [
                            {
                                "in": "query",
                                "name": "force",
                                "required": True,
                                "schema": {"type": "boolean"},
                            }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"versions": {"type": "array"}},
                                        "required": ["versions"],
                                    }
                                }
                            }
                        },
                    }
                }
            },
        })
        discovered = document.operations[0]
        self.assertEqual(discovered.query_parameter_types, (("force", "boolean"),))
        self.assertEqual(discovered.query_parameters, ("force",))
        self.assertEqual(discovered.required_query_parameters, ("force",))
        self.assertEqual(discovered.path_parameters, ("path", "secret_mount_path"))
        self.assertEqual(discovered.required_path_parameters, ("path", "secret_mount_path"))
        self.assertEqual(discovered.path_parameter_types, (("path", "string"), ("secret_mount_path", "string")))
        self.assertEqual(discovered.body_field_types, (("versions", "array"),))
        self.assertEqual(discovered.required_body_fields, ("versions",))

    def test_operation_parameters_replace_inherited_required_state(self):
        document = normalize_openapi_document({
            "openapi": "3.0.2",
            "info": {"version": "2.6.2"},
            "paths": {
                "/{secret_mount_path}/config": {
                    "parameters": [
                        {"in": "query", "name": "version", "required": True, "schema": {"type": "integer"}},
                        {"in": "query", "name": "optional", "schema": {"type": "string"}},
                    ],
                    "get": {
                        "operationId": "kv-read-config",
                        "parameters": [
                            {"in": "query", "name": "version", "schema": {"type": "string"}},
                            {"in": "query", "name": "optional", "required": True, "schema": {"type": "boolean"}},
                        ],
                    },
                }
            },
        })
        discovered = document.operations[0]
        self.assertEqual(discovered.required_query_parameters, ("optional",))
        self.assertEqual(discovered.query_parameter_types, (("optional", "boolean"), ("version", "string")))


class FakeEngineAdministrationBackend:
    def __init__(self, cluster):
        self.cluster = cluster
        self.calls = []
        self.material_response = "material-canary"
        self.mounts = normalize_secret_engine_mounts({
            "data": {"secret/": {"type": "kv", "accessor": "kv_1", "config": {}}}
        })

    def seal_status(self):
        return SimpleNamespace(initialized=True, sealed=False, version="2.6.2")

    def discover_capabilities(self):
        operations = (
            operation("GET", "/sys/mounts", "mounts-list-secrets-engines"),
            operation("GET", "/sys/mounts/{path}", "mounts-read-configuration"),
            operation("GET", "/sys/mounts/{path}/tune", "mounts-read-tuning-information"),
            operation("POST", "/sys/mounts/{path}", "mounts-enable-secrets-engine"),
            operation("GET", "/{secret_mount_path}/data/{path}", "kv-read-data-path"),
            operation("DELETE", "/{secret_mount_path}/data/{path}", "kv-delete-data-path"),
            operation(
                "POST",
                "/{secret_mount_path}/destroy/{path}",
                "kv-write-destroy-path",
                risk_level="destructive",
                body_fields=("versions",),
                body_field_types=(("versions", "array"),),
            ),
        )
        corrected = tuple(
            DiscoveredOperation(
                operation_id=item.operation_id,
                method=item.method,
                path_template=item.path_template,
                summary=item.summary,
                tags=item.tags,
                family="secret-engine-lifecycle" if item.path_template.startswith("/sys/") else item.family,
                risk_level=item.risk_level,
                response_class=item.response_class,
                required_permission=item.required_permission,
                classified=True,
                query_parameters=item.query_parameters,
                required_query_parameters=item.required_query_parameters,
                path_parameters=item.path_parameters,
                required_path_parameters=item.required_path_parameters,
                path_parameter_types=item.path_parameter_types,
                mount_parameter=item.mount_parameter,
                body_fields=item.body_fields,
                required_body_fields=item.required_body_fields,
                query_parameter_types=item.query_parameter_types,
                body_field_types=item.body_field_types,
            )
            for item in operations
        )
        return capability_document(*corrected)

    def list_secret_engines(self):
        return self.mounts

    def enable_secret_engine(self, mount_path, payload):
        self.calls.append(("enable", mount_path, payload))

    def read_secret_engine(self, mount_path):
        self.calls.append(("read", mount_path))
        return {"type": "kv", "options": {"version": "2"}}

    def read_secret_engine_tuning(self, mount_path):
        self.calls.append(("tuning", mount_path))
        return {"description": "Credentials", "max_lease_ttl": 60}

    def execute_mounted_operation(self, method, path, *, query, body):
        self.calls.append(("execute", method, path, query, body))
        return {"data": {"password": self.material_response}}


class EngineAdministrationAPITest(OpenBaoAdministrationTestCase):
    def url(self, action):
        return reverse(
            f"plugins-api:netbox_openbao-api:openbaocluster-{action}",
            kwargs={"pk": self.cluster.pk},
        )

    def test_disable_only_operator_sees_disable_without_manage_controls(self):
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            "netbox_openbao.disable_secret_engines_openbaocluster",
        )
        self.client.force_login(self.user)
        response = self.client.get(
            reverse(
                "plugins:netbox_openbao:openbaocluster_secret_engines",
                kwargs={"pk": self.cluster.pk},
            ),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, "Disable engine")
        self.assertNotContains(response, "Enable engine")

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_explorer_rejects_operation_advertised_by_a_different_mount(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        transit_operation = operation(
            "GET",
            "/{secret_mount_path}/keys/{name}",
            "transit-read-key",
            path_parameters=("name", "secret_mount_path"),
            required_path_parameters=("name", "secret_mount_path"),
            path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
            mount_parameter="transit_team_mount_path",
        )
        backend.discover_capabilities = lambda: capability_document(transit_operation)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.explore_secret_operations_openbaocluster",
            "netbox_openbao.reveal_secret_operations_openbaocluster",
        )
        response = self.client.post(
            self.url("execute-secret-operation"),
            {
                "operation_key": transit_operation.operation_key,
                "capability_digest": "c" * 64,
                "mount_path": "secret",
                "path_parameters": {"name": "integration-key"},
                "reason": "Cross-mount binding test",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("not advertised by this live mount", str(response.data))

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_explorer_enforces_required_runtime_query_metadata(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        required = operation(
            "GET",
            "/{secret_mount_path}/config",
            "kv-read-config",
            query_parameters=("version",),
            required_query_parameters=("version",),
            path_parameters=("secret_mount_path",),
            required_path_parameters=("secret_mount_path",),
        )
        backend.discover_capabilities = lambda: capability_document(required)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.explore_secret_operations_openbaocluster",
            "netbox_openbao.reveal_secret_operations_openbaocluster",
        )

        response = self.client.post(
            self.url("execute-secret-operation"),
            {
                "operation_key": required.operation_key,
                "capability_digest": "c" * 64,
                "mount_path": "secret",
                "query": {},
                "body": {},
                "reason": "Validate required query handling",
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("required query parameter", str(response.data))

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_mount_list_reads_and_enable_use_reviewed_contracts(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            "netbox_openbao.manage_secret_engines_openbaocluster",
        )

        listed = self.client.get(self.url("secret-engines"), **self.header)
        configuration = self.client.post(
            self.url("secret-engine-configuration"), {"mount_path": "secret"}, format="json", **self.header
        )
        tuning = self.client.post(
            self.url("secret-engine-tuning"), {"mount_path": "secret"}, format="json", **self.header
        )
        enabled = self.client.post(
            self.url("enable-secret-engine"),
            {"mount_path": "database", "configuration": {"type": "database"}, "reason": "Provision database"},
            format="json",
            **self.header,
        )

        self.assertEqual(listed.status_code, 200, listed.content)
        self.assertIn("no-store", listed["Cache-Control"])
        self.assertEqual(listed.data["mounts"][0]["path"], "secret")
        self.assertEqual(configuration.status_code, 200, configuration.content)
        self.assertEqual(configuration.data["options"]["version"], "2")
        self.assertEqual(tuning.status_code, 200, tuning.content)
        self.assertEqual(tuning.data["description"], "Credentials")
        self.assertEqual(enabled.status_code, 200, enabled.content)
        self.assertEqual(
            backend.calls,
            [("read", "secret"), ("tuning", "secret"), ("enable", "database", {"type": "database"})],
        )
        self.assertTrue(OpenBaoAdministrationLog.objects.filter(action="secret-engine-enable").exists())

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_material_explorer_requires_dedicated_permission_and_no_store(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.explore_secret_operations_openbaocluster",
            "netbox_openbao.reveal_secret_operations_openbaocluster",
        )
        payload = {
            "operation_key": "secret_mount_path :: kv-read-data-path :: GET /{secret_mount_path}/data/{path}",
            "capability_digest": "c" * 64,
            "mount_path": "secret",
            "resource_path": "team/db",
            "query": {},
            "body": {},
            "reason": "Incident response",
        }

        response = self.client.post(self.url("execute-secret-operation"), payload, format="json", **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.data["data"]["data"]["password"], "material-canary")
        self.assertEqual(backend.calls[0], ("execute", "GET", "/secret/data/team/db", {}, {}))

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_explorer_rejects_unadvertised_operation_and_path_traversal(self, get_backend):
        get_backend.return_value = FakeEngineAdministrationBackend(self.cluster)
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.explore_secret_operations_openbaocluster",
            "netbox_openbao.reveal_secret_operations_openbaocluster",
        )
        base = {
            "mount_path": "secret",
            "capability_digest": "c" * 64,
            "query": {},
            "body": {},
            "reason": "Security test",
        }
        unknown = self.client.post(
            self.url("execute-secret-operation"),
            {**base, "operation_key": "unknown :: GET /sys/raw", "resource_path": "data/x"},
            format="json",
            **self.header,
        )
        traversal = self.client.post(
            self.url("execute-secret-operation"),
            {
                **base,
                "operation_key": "secret_mount_path :: kv-read-data-path :: GET /{secret_mount_path}/data/{path}",
                "resource_path": "../sys/seal",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(unknown.status_code, 400, unknown.content)
        self.assertEqual(traversal.status_code, 400, traversal.content)

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_destructive_mounted_operation_requires_separate_permission_and_exact_method(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.explore_secret_operations_openbaocluster",
        )
        payload = {
            "operation_key": "secret_mount_path :: kv-write-destroy-path :: POST /{secret_mount_path}/destroy/{path}",
            "capability_digest": "c" * 64,
            "mount_path": "secret",
            "resource_path": "team/db",
            "query": {},
            "body": {"versions": [1]},
            "reason": "Destroy a compromised version",
            "confirmation": f"POST /secret/destroy/team/db ON {self.cluster.slug}",
        }

        denied = self.client.post(self.url("execute-secret-operation"), payload, format="json", **self.header)
        self.assertEqual(denied.status_code, 403, denied.content)
        self.add_permissions("netbox_openbao.delete_secret_operations_openbaocluster")
        accepted = self.client.post(self.url("execute-secret-operation"), payload, format="json", **self.header)
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(
            backend.calls,
            [("execute", "POST", "/secret/destroy/team/db", {}, {"versions": [1]})],
        )

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_unknown_engine_mutation_is_explicit_and_not_retryable(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        backend.enable_secret_engine = lambda *_args: (_ for _ in ()).throw(OpenBaoMutationUnknown())
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_secret_engines_openbaocluster",
        )

        response = self.client.post(
            self.url("enable-secret-engine"),
            {"mount_path": "database", "configuration": {"type": "database"}, "reason": "Provision database"},
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.data["outcome"], "unknown")
        self.assertEqual(response["X-OpenBao-Operation-Outcome"], "unknown")
        self.assertIn("Do not retry", response.data["message"])

    @patch("netbox_openbao.api.engine_views.SecretEngineAdministrationMixin._audit")
    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_completion_audit_failure_preserves_accepted_mutation(self, get_backend, audit):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        audit.side_effect = AdministrationAuditError("audit unavailable")
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.manage_secret_engines_openbaocluster",
        )

        response = self.client.post(
            self.url("enable-secret-engine"),
            {"mount_path": "database", "configuration": {"type": "database"}, "reason": "Provision database"},
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["outcome"], "accepted-audit-incomplete")
        self.assertEqual(response["X-OpenBao-Audit-Status"], "preflight-only")
