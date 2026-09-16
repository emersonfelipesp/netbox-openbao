"""Secret-engine lifecycle and fail-closed explorer contract tests."""

from dataclasses import replace
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from django.urls import reverse

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.engine_journeys import (
    ENGINE_JOURNEYS,
    engine_journey_catalog,
    normalize_journey_path_parameters,
    resolve_engine_journey,
)
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
    query_parameter_types=(),
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
        query_parameter_types=query_parameter_types,
        path_parameters=path_parameters,
        required_path_parameters=required_path_parameters,
        path_parameter_types=path_parameter_types,
        mount_parameter=mount_parameter,
    )


class EngineContractTest(TestCase):
    def test_mount_metadata_is_bounded_sorted_and_redacted(self):
        mounts = normalize_secret_engine_mounts(
            {
                "data": {
                    "transit/": {"type": "transit", "accessor": "transit_1", "config": {}},
                    "secret/": {
                        "type": "kv",
                        "accessor": "kv_1",
                        "description": "Credentials",
                        "config": {"default_lease_ttl": 30, "max_lease_ttl": 60},
                        "options": {"token": "must-not-be-retained"},
                    },
                }
            }
        )
        self.assertEqual([mount.path for mount in mounts], ["secret", "transit"])
        self.assertEqual(mounts[0].default_lease_ttl, 30)
        self.assertNotIn("must-not-be-retained", repr(mounts))

    def test_mount_metadata_records_only_valid_kv_versions(self):
        mounts = normalize_secret_engine_mounts(
            {
                "data": {
                    "kv1/": {"type": "kv", "options": {"version": "1"}},
                    "kv2/": {"type": "kv", "options": {"version": "2"}},
                    "transit/": {"type": "transit", "options": {}},
                }
            }
        )
        self.assertEqual([(mount.path, mount.kv_version) for mount in mounts], [("kv1", 1), ("kv2", 2), ("transit", 0)])
        for version in (2, "3", True, [], {"nested": "value"}):
            with self.subTest(version=version), self.assertRaises(CapabilitySchemaError):
                normalize_secret_engine_mounts({"data": {"secret/": {"type": "kv", "options": {"version": version}}}})

    def test_first_class_registry_is_static_mount_and_version_bound(self):
        document = capability_document(
            operation("GET", "/{secret_mount_path}/data/{path}", "kv-read-data-path"),
            operation(
                "GET",
                "/{secret_mount_path}/keys/{name}",
                "transit-read-key",
                path_parameters=("name", "secret_mount_path"),
                required_path_parameters=("name", "secret_mount_path"),
                path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                mount_parameter="transit_mount_path",
            ),
        )
        mounts = normalize_secret_engine_mounts(
            {
                "data": {
                    "secret/": {"type": "kv", "options": {"version": "2"}},
                    "transit/": {"type": "transit"},
                }
            }
        )
        catalog = engine_journey_catalog(document, mounts)
        self.assertEqual({item["journey_id"] for item in catalog}, {"kv2.read", "kv2.diff", "transit.key-read"})
        self.assertEqual(len({journey.journey_id for journey in ENGINE_JOURNEYS}), len(ENGINE_JOURNEYS))
        with self.assertRaisesRegex(CapabilitySchemaError, "unavailable"):
            resolve_engine_journey(document, mounts, "transit", "kv2.read")
        with self.assertRaisesRegex(CapabilitySchemaError, "unavailable"):
            resolve_engine_journey(document, mounts, "secret", "kv1.read")

    def test_destructive_database_and_ssh_journeys_use_delete_permissions(self):
        permissions = {journey.journey_id: journey.required_permission for journey in ENGINE_JOURNEYS}
        for journey_id in (
            "database.connection-delete",
            "database.role-delete",
            "database.static-role-delete",
        ):
            self.assertEqual(
                permissions[journey_id],
                "netbox_openbao.delete_database_resources_openbaocluster",
            )
        self.assertEqual(permissions["ssh.role-delete"], "netbox_openbao.delete_ssh_roles_openbaocluster")

    def test_pki_and_kubernetes_journeys_have_dedicated_permissions_and_controls(self):
        selected = {journey.journey_id: journey for journey in ENGINE_JOURNEYS}
        self.assertEqual(
            selected["pki.issuer-delete"].required_permission, "netbox_openbao.delete_pki_issuers_openbaocluster"
        )
        self.assertEqual(
            selected["pki.key-delete"].required_permission, "netbox_openbao.delete_pki_keys_openbaocluster"
        )
        self.assertEqual(
            selected["pki.key-write"].required_permission,
            "netbox_openbao.manage_pki_keys_openbaocluster",
        )
        for journey_id in (
            "pki.key-generate-internal",
            "pki.key-generate-exported",
            "pki.key-generate-kms",
        ):
            self.assertEqual(
                selected[journey_id].required_permission,
                "netbox_openbao.generate_pki_keys_openbaocluster",
            )
        self.assertEqual(
            selected["pki.root-delete"].required_permission,
            "netbox_openbao.delete_pki_roots_openbaocluster",
        )
        self.assertEqual(
            selected["pki.issue"].required_permission, "netbox_openbao.issue_pki_certificates_openbaocluster"
        )
        self.assertEqual(
            selected["kubernetes.credentials"].required_permission,
            "netbox_openbao.generate_k8s_credentials_openbaocluster",
        )
        self.assertEqual(
            selected["kubernetes.config-delete"].required_permission,
            "netbox_openbao.delete_k8s_configuration_openbaocluster",
        )
        for journey_id in (
            "pki.issuer-delete",
            "pki.key-delete",
            "pki.key-generate-internal",
            "pki.root-generate",
            "pki.root-rotate",
            "pki.root-delete",
            "pki.tidy",
        ):
            with self.subTest(journey_id=journey_id):
                self.assertEqual(selected[journey_id].risk_level, "destructive")
                self.assertTrue(selected[journey_id].confirmation_prefix)

    def test_pki_path_contract_normalizes_serials_and_bounds_generation_modes(self):
        selected = {journey.journey_id: journey for journey in ENGINE_JOURNEYS}
        self.assertEqual(
            normalize_journey_path_parameters(selected["pki.certificate-read"], {"serial": "AA:01:bC"}),
            {"serial": "aa-01-bc"},
        )
        self.assertEqual(
            normalize_journey_path_parameters(selected["pki.root-generate"], {"exported": "internal"}),
            {"exported": "internal"},
        )
        for values in ({"serial": "../../root"}, {"exported": "future"}):
            journey = selected["pki.certificate-read"] if "serial" in values else selected["pki.root-generate"]
            with self.subTest(values=values), self.assertRaises(CapabilitySchemaError):
                normalize_journey_path_parameters(journey, values)

    def test_first_class_catalog_fails_closed_on_lossy_mount_name_collision(self):
        advertised = operation("GET", "/{secret_mount_path}/data/{path}", "kv-read-data-path")
        document = capability_document(replace(advertised, mount_parameter="team_db_mount_path"))
        mounts = normalize_secret_engine_mounts(
            {
                "data": {
                    "team-db/": {"type": "kv", "options": {"version": "2"}},
                    "team_db/": {"type": "kv", "options": {"version": "2"}},
                }
            }
        )

        self.assertEqual(engine_journey_catalog(document, mounts), ())
        for mount in mounts:
            with self.subTest(mount=mount.path), self.assertRaisesRegex(CapabilitySchemaError, "unavailable"):
                resolve_engine_journey(document, mounts, mount.path, "kv2.read")

    @patch("netbox_openbao.administration.engine_journeys.classify_explorer_operations")
    def test_first_class_catalog_classifies_runtime_schema_once(self, classify):
        advertised = operation("GET", "/{secret_mount_path}/data/{path}", "kv-read-data-path")
        document = capability_document(advertised)
        mounts = normalize_secret_engine_mounts(
            {"data": {f"secret-{index}/": {"type": "kv", "options": {"version": "2"}} for index in range(20)}}
        )
        classify.return_value = classify_explorer_operations(document)

        engine_journey_catalog(document, mounts)

        classify.assert_called_once_with(document)

    def test_enable_contract_rejects_unknown_type_and_field(self):
        self.assertEqual(validate_enable_payload({"type": "kv", "options": {"version": "2"}})["type"], "kv")
        for payload in ({"type": "future"}, {"type": "kv", "url": "https://attacker.example"}):
            with self.subTest(payload=payload), self.assertRaises(CapabilitySchemaError):
                validate_enable_payload(payload)

    def test_lifecycle_nested_fields_have_fixed_types_and_allowlists(self):
        validate_enable_payload(
            {
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
            }
        )
        validate_tune_payload(
            {
                "listing_visibility": "unauth",
                "plugin_version": "v1.2.3",
                "default_lease_ttl": "5m",
                "allowed_response_headers": ["X-Request-ID"],
                "options": {"version": "2"},
                "user_lockout_config": {"lockout_threshold": 5, "lockout_disable": False},
            }
        )
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
        huge_integer = 10**4_000
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
        document = normalize_openapi_document(
            {
                "openapi": "3.0.2",
                "info": {"version": "2.6.2"},
                "paths": {
                    "/{secret_mount_path}/^.*$": {
                        "get": {"operationId": "external-plugin-read", "summary": "Read", "tags": []}
                    }
                },
            }
        )
        self.assertEqual(document.operations[0].family, "mounted-secrets")

    def test_plugin_specific_mount_placeholder_is_canonicalized(self):
        document = normalize_openapi_document(
            {
                "openapi": "3.0.2",
                "info": {"version": "2.6.2"},
                "paths": {
                    "/{transit_team_mount_path}/keys/{name}": {
                        "parameters": [
                            {
                                "in": "path",
                                "name": "transit_team_mount_path",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {"in": "path", "name": "name", "required": True, "schema": {"type": "string"}},
                        ],
                        "get": {"operationId": "transit-read-key"},
                    }
                },
            }
        )
        discovered = document.operations[0]
        self.assertEqual(discovered.path_template, "/{secret_mount_path}/keys/{name}")
        self.assertEqual(discovered.mount_parameter, "transit_team_mount_path")
        self.assertEqual(discovered.path_parameters, ("name", "secret_mount_path"))
        self.assertTrue(classify_explorer_operations(document)[0].executable)

    def test_discovery_retains_bounded_top_level_request_types(self):
        document = normalize_openapi_document(
            {
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
                        },
                    }
                },
            }
        )
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
        document = normalize_openapi_document(
            {
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
            }
        )
        discovered = document.operations[0]
        self.assertEqual(discovered.required_query_parameters, ("optional",))
        self.assertEqual(discovered.query_parameter_types, (("optional", "boolean"), ("version", "string")))


class FakeEngineAdministrationBackend:
    def __init__(self, cluster):
        self.cluster = cluster
        self.calls = []
        self.material_response = "material-canary"
        self.mounts = normalize_secret_engine_mounts(
            {
                "data": {
                    "secret/": {
                        "type": "kv",
                        "accessor": "kv_1",
                        "config": {},
                        "options": {"version": "2"},
                    }
                }
            }
        )

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

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_pki_kms_key_generation_requires_generation_only_permission(self, get_backend):
        advertised = operation(
            "POST",
            "/{secret_mount_path}/keys/generate/kms",
            "pki-generate-kms-key",
            body_fields=("key_name", "key_type", "key_bits"),
            body_field_types=(("key_name", "string"), ("key_type", "string"), ("key_bits", "integer")),
            path_parameters=("secret_mount_path",),
            required_path_parameters=("secret_mount_path",),
            path_parameter_types=(("secret_mount_path", "string"),),
            mount_parameter="pki_mount_path",
        )
        backend = FakeEngineAdministrationBackend(self.cluster)
        backend.mounts = normalize_secret_engine_mounts({"data": {"pki/": {"type": "pki"}}})
        backend.discover_capabilities = lambda: capability_document(advertised)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            "netbox_openbao.manage_pki_keys_openbaocluster",
        )
        payload = {
            "journey_id": "pki.key-generate-kms",
            "capability_digest": "c" * 64,
            "mount_path": "pki",
            "body": {"key_name": "application"},
            "reason": "Generate an isolated application issuer key",
            "confirmation": f"GENERATE PKI KEY /pki/keys/generate/kms ON {self.cluster.slug}",
        }

        denied = self.client.post(self.url("execute-secret-engine-journey"), payload, format="json", **self.header)
        self.assertEqual(denied.status_code, 403, denied.content)
        self.assertEqual(backend.calls, [])
        self.add_permissions("netbox_openbao.generate_pki_keys_openbaocluster")
        self.user = type(self.user).objects.get(pk=self.user.pk)
        self.client.force_login(self.user)
        accepted = self.client.post(self.url("execute-secret-engine-journey"), payload, format="json", **self.header)
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(
            backend.calls,
            [("execute", "POST", "/pki/keys/generate/kms", {}, {"key_name": "application"})],
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
    def test_first_class_catalog_requires_dedicated_permissions(self, get_backend):
        get_backend.return_value = FakeEngineAdministrationBackend(self.cluster)
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            "netbox_openbao.reveal_kv_secrets_openbaocluster",
        )

        response = self.client.get(self.url("secret-engine-journeys"), **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual({item["journey_id"] for item in response.data["journeys"]}, {"kv2.read", "kv2.diff"})

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_first_class_kv_diff_is_request_scoped_and_reads_exact_versions(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            "netbox_openbao.reveal_kv_secrets_openbaocluster",
        )
        payload = {
            "journey_id": "kv2.diff",
            "capability_digest": "c" * 64,
            "mount_path": "secret",
            "resource_path": "team/db",
            "query": {"from_version": 1, "to_version": 2},
            "reason": "Compare a controlled secret rotation",
        }

        response = self.client.post(self.url("execute-secret-engine-journey"), payload, format="json", **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.data["data"]["from_version"], 1)
        self.assertEqual(
            backend.calls,
            [
                ("execute", "GET", "/secret/data/team/db", {"version": 1}, {}),
                ("execute", "GET", "/secret/data/team/db", {"version": 2}, {}),
            ],
        )

        for extra in (
            {"body": {"ignored": "material"}},
            {"path_parameters": {"ignored": "material"}},
        ):
            with self.subTest(extra=extra):
                rejected = self.client.post(
                    self.url("execute-secret-engine-journey"),
                    {**payload, **extra},
                    format="json",
                    **self.header,
                )
                self.assertEqual(rejected.status_code, 400, rejected.content)

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_first_class_destructive_journey_requires_permission_and_typed_confirmation(self, get_backend):
        backend = FakeEngineAdministrationBackend(self.cluster)
        get_backend.return_value = backend
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
        )
        payload = {
            "journey_id": "kv2.destroy",
            "capability_digest": "c" * 64,
            "mount_path": "secret",
            "resource_path": "team/db",
            "body": {"versions": [1]},
            "reason": "Destroy a compromised secret version",
            "confirmation": f"DESTROY KV VERSIONS /secret/destroy/team/db ON {self.cluster.slug}",
        }

        denied = self.client.post(self.url("execute-secret-engine-journey"), payload, format="json", **self.header)
        self.assertEqual(denied.status_code, 403, denied.content)
        self.add_permissions("netbox_openbao.destroy_kv_versions_openbaocluster")
        wrong_confirmation = self.client.post(
            self.url("execute-secret-engine-journey"),
            {**payload, "confirmation": "DESTROY KV VERSIONS"},
            format="json",
            **self.header,
        )
        self.assertEqual(wrong_confirmation.status_code, 400, wrong_confirmation.content)
        accepted = self.client.post(self.url("execute-secret-engine-journey"), payload, format="json", **self.header)
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(backend.calls, [("execute", "POST", "/secret/destroy/team/db", {}, {"versions": [1]})])

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_representative_transit_database_ssh_and_totp_journeys(self, get_backend):
        cases = (
            (
                "transit",
                "transit.encrypt",
                "use_transit",
                operation(
                    "POST",
                    "/{secret_mount_path}/encrypt/{name}",
                    "transit-encrypt",
                    body_fields=("plaintext",),
                    required_body_fields=("plaintext",),
                    body_field_types=(("plaintext", "string"),),
                    path_parameters=("name", "secret_mount_path"),
                    required_path_parameters=("name", "secret_mount_path"),
                    path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                    mount_parameter="transit_mount_path",
                ),
                {"path_parameters": {"name": "payments"}, "body": {"plaintext": "cGF5bG9hZA=="}},
                ("execute", "POST", "/transit/encrypt/payments", {}, {"plaintext": "cGF5bG9hZA=="}),
            ),
            (
                "database",
                "database.credentials",
                "generate_database_credentials",
                operation(
                    "GET",
                    "/{secret_mount_path}/creds/{name}",
                    "database-generate-credentials",
                    path_parameters=("name", "secret_mount_path"),
                    required_path_parameters=("name", "secret_mount_path"),
                    path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                    mount_parameter="database_mount_path",
                ),
                {"path_parameters": {"name": "readonly"}},
                ("execute", "GET", "/database/creds/readonly", {}, {}),
            ),
            (
                "ssh",
                "ssh.sign",
                "issue_ssh_credentials",
                operation(
                    "POST",
                    "/{secret_mount_path}/sign/{role}",
                    "ssh-sign-certificate",
                    body_fields=("public_key",),
                    required_body_fields=("public_key",),
                    body_field_types=(("public_key", "string"),),
                    path_parameters=("role", "secret_mount_path"),
                    required_path_parameters=("role", "secret_mount_path"),
                    path_parameter_types=(("role", "string"), ("secret_mount_path", "string")),
                    mount_parameter="ssh_mount_path",
                ),
                {"path_parameters": {"role": "operator"}, "body": {"public_key": "ssh-ed25519 AAAA"}},
                ("execute", "POST", "/ssh/sign/operator", {}, {"public_key": "ssh-ed25519 AAAA"}),
            ),
            (
                "totp",
                "totp.code",
                "generate_totp_codes",
                operation(
                    "GET",
                    "/{secret_mount_path}/code/{name}",
                    "totp-generate-code",
                    path_parameters=("name", "secret_mount_path"),
                    required_path_parameters=("name", "secret_mount_path"),
                    path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                    mount_parameter="totp_mount_path",
                ),
                {"path_parameters": {"name": "deploy"}},
                ("execute", "GET", "/totp/code/deploy", {}, {}),
            ),
        )
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
        )
        for mount_path, journey_id, permission, advertised, inputs, expected in cases:
            with self.subTest(journey_id=journey_id):
                backend = FakeEngineAdministrationBackend(self.cluster)
                backend.mounts = normalize_secret_engine_mounts({"data": {f"{mount_path}/": {"type": mount_path}}})
                backend.discover_capabilities = lambda advertised=advertised: capability_document(advertised)
                get_backend.return_value = backend
                self.add_permissions(f"netbox_openbao.{permission}_openbaocluster")
                response = self.client.post(
                    self.url("execute-secret-engine-journey"),
                    {
                        "journey_id": journey_id,
                        "capability_digest": "c" * 64,
                        "mount_path": mount_path,
                        "reason": "Verify a representative first-class journey",
                        **inputs,
                    },
                    format="json",
                    **self.header,
                )
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(backend.calls, [expected])

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_representative_pki_and_kubernetes_journeys(self, get_backend):
        cases = (
            (
                "pki",
                "pki.certificate-read",
                "view_pki",
                operation(
                    "GET",
                    "/{secret_mount_path}/cert/{serial}",
                    "pki-read-cert",
                    path_parameters=("secret_mount_path", "serial"),
                    required_path_parameters=("secret_mount_path", "serial"),
                    path_parameter_types=(("secret_mount_path", "string"), ("serial", "string")),
                    mount_parameter="pki_mount_path",
                ),
                {"path_parameters": {"serial": "AA:01:bC"}},
                ("execute", "GET", "/pki/cert/aa-01-bc", {}, {}),
            ),
            (
                "kubernetes",
                "kubernetes.credentials",
                "generate_k8s_credentials",
                operation(
                    "POST",
                    "/{secret_mount_path}/creds/{name}",
                    "kubernetes-generate-credentials",
                    body_fields=("kubernetes_namespace", "ttl"),
                    required_body_fields=("kubernetes_namespace",),
                    body_field_types=(("kubernetes_namespace", "string"), ("ttl", "integer")),
                    path_parameters=("name", "secret_mount_path"),
                    required_path_parameters=("name", "secret_mount_path"),
                    path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                    mount_parameter="kubernetes_mount_path",
                ),
                {"path_parameters": {"name": "operator"}, "body": {"kubernetes_namespace": "default", "ttl": 60}},
                (
                    "execute",
                    "POST",
                    "/kubernetes/creds/operator",
                    {},
                    {"kubernetes_namespace": "default", "ttl": 60},
                ),
            ),
        )
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
            *(f"netbox_openbao.{case[2]}_openbaocluster" for case in cases),
        )
        for mount_path, journey_id, _permission, advertised, inputs, expected in cases:
            with self.subTest(journey_id=journey_id):
                backend = FakeEngineAdministrationBackend(self.cluster)
                backend.mounts = normalize_secret_engine_mounts({"data": {f"{mount_path}/": {"type": mount_path}}})
                backend.discover_capabilities = lambda advertised=advertised: capability_document(advertised)
                get_backend.return_value = backend
                self.user = type(self.user).objects.get(pk=self.user.pk)
                self.client.force_login(self.user)
                response = self.client.post(
                    self.url("execute-secret-engine-journey"),
                    {
                        "journey_id": journey_id,
                        "capability_digest": "c" * 64,
                        "mount_path": mount_path,
                        "reason": "Verify a representative first-class journey",
                        **inputs,
                    },
                    format="json",
                    **self.header,
                )
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(backend.calls, [expected])

    @patch("netbox_openbao.api.engine_views.get_administration_backend")
    def test_first_class_list_journeys_force_list_query(self, get_backend):
        cases = (
            (
                "kv",
                "2",
                "kv2.browse",
                "reveal_kv_secrets",
                "/{secret_mount_path}/metadata/{path}",
                "kv-read-metadata-path",
                "kv_mount_path",
                "items",
                "/kv/metadata/items",
            ),
            (
                "transit",
                "",
                "transit.keys",
                "use_transit",
                "/{secret_mount_path}/keys",
                "transit-list-keys",
                "transit_mount_path",
                "",
                "/transit/keys",
            ),
            (
                "database",
                "",
                "database.connections",
                "manage_database_roles",
                "/{secret_mount_path}/config",
                "database-list-connections",
                "database_mount_path",
                "",
                "/database/config",
            ),
            (
                "database",
                "",
                "database.roles",
                "manage_database_roles",
                "/{secret_mount_path}/roles",
                "database-list-roles",
                "database_mount_path",
                "",
                "/database/roles",
            ),
            (
                "database",
                "",
                "database.static-roles",
                "manage_database_roles",
                "/{secret_mount_path}/static-roles",
                "database-list-static-roles",
                "database_mount_path",
                "",
                "/database/static-roles",
            ),
            (
                "ssh",
                "",
                "ssh.roles",
                "manage_ssh_roles",
                "/{secret_mount_path}/roles",
                "ssh-list-roles",
                "ssh_mount_path",
                "",
                "/ssh/roles",
            ),
            (
                "totp",
                "",
                "totp.keys",
                "manage_totp_keys",
                "/{secret_mount_path}/keys",
                "totp-list-keys",
                "totp_mount_path",
                "",
                "/totp/keys",
            ),
        )
        self.add_permissions(
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_secret_engines_openbaocluster",
        )
        for (
            engine_type,
            version,
            journey_id,
            permission,
            path,
            operation_id,
            mount_parameter,
            resource,
            compiled,
        ) in cases:
            with self.subTest(journey_id=journey_id):
                advertised = operation(
                    "GET",
                    path,
                    operation_id,
                    query_parameters=("list",),
                    query_parameter_types=(("list", "string"),),
                    path_parameters=("secret_mount_path", "path") if "{path}" in path else ("secret_mount_path",),
                    required_path_parameters=("secret_mount_path", "path")
                    if "{path}" in path
                    else ("secret_mount_path",),
                    mount_parameter=mount_parameter,
                )
                backend = FakeEngineAdministrationBackend(self.cluster)
                options = {"version": version} if version else {}
                backend.mounts = normalize_secret_engine_mounts(
                    {"data": {f"{engine_type}/": {"type": engine_type, "options": options}}}
                )
                backend.discover_capabilities = lambda advertised=advertised: capability_document(advertised)
                get_backend.return_value = backend
                self.add_permissions(f"netbox_openbao.{permission}_openbaocluster")
                response = self.client.post(
                    self.url("execute-secret-engine-journey"),
                    {
                        "journey_id": journey_id,
                        "capability_digest": "c" * 64,
                        "mount_path": engine_type,
                        "resource_path": resource,
                        "reason": "List first-class engine resources",
                    },
                    format="json",
                    **self.header,
                )
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(backend.calls, [("execute", "GET", compiled, {"list": "true"}, {})])

                rejected = self.client.post(
                    self.url("execute-secret-engine-journey"),
                    {
                        "journey_id": journey_id,
                        "capability_digest": "c" * 64,
                        "mount_path": engine_type,
                        "resource_path": resource,
                        "query": {"list": "false"},
                        "reason": "Attempt to override list semantics",
                    },
                    format="json",
                    **self.header,
                )
                self.assertEqual(rejected.status_code, 400, rejected.content)

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
