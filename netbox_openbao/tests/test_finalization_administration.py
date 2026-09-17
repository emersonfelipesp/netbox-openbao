"""Lease, tool, UI configuration, and conformance tests."""

import json
from unittest import TestCase
from unittest.mock import patch

from django.urls import reverse

from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.cluster import SealStatus
from netbox_openbao.administration.finalization import (
    FINAL_RESOURCES,
    MAX_WRAPPING_JSON_BYTES,
    MAX_WRAPPING_JSON_DEPTH,
    MAX_WRAPPING_JSON_MEMBERS,
    MAX_WRAPPING_JSON_STRING,
    conformance_report,
    load_final_route_fixture,
    normalize_final_identifier,
    validate_payload,
)
from netbox_openbao.administration.schema import CapabilityDocument, CapabilitySchemaError, DiscoveredOperation
from netbox_openbao.api import finalization_views
from netbox_openbao.api.views import OpenBaoClusterViewSet
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoMutationUnknown, OpenBaoNotFound
from netbox_openbao.choices import BackendChoices
from netbox_openbao.models import OpenBaoAdministrationLog
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase, _Response


def final_document(*, digest="f" * 64, omit=None, version="2.6.2", unclassified=None, duplicate=None):
    operations = []
    seen = set()
    fixture = load_final_route_fixture()
    for resource in FINAL_RESOURCES.values():
        for name, operation in resource.operations.items():
            if (resource.key, name) == omit:
                continue
            key = (operation.method, operation.path_template)
            if key in seen:
                continue
            seen.add(key)
            contract = next(
                item for item in fixture["operations"]
                if item["resource"] == resource.key and item["operation"] == name
            )
            path = operation.path_template.replace("{identifier}", "{name}")
            query_types = tuple((field, kind.removesuffix("!")) for field, kind in contract["query"].items())
            operation_id = (
                contract["operation_ids"][1]
                if resource.key == "leases" and name == "list"
                else contract["operation_ids"][0]
            )
            discovered = DiscoveredOperation(
                operation_id=operation_id,
                method=operation.method,
                path_template=path,
                summary="Reviewed final operation",
                tags=(resource.family,),
                family=resource.family,
                risk_level=operation.risk,
                response_class=operation.response_kind,
                required_permission=operation.permission,
                classified=(resource.key, name) != unclassified,
                query_parameters=tuple(contract["query"]),
                required_query_parameters=tuple(k for k, v in contract["query"].items() if v.endswith("!")),
                query_parameter_types=query_types,
                path_parameters=("name",) if "{name}" in path else (),
                required_path_parameters=("name",) if "{name}" in path else (),
                path_parameter_types=(("name", "string"),) if "{name}" in path else (),
                body_fields=tuple(contract["body"]),
                body_field_types=tuple(contract["body"].items()),
            )
            operations.append(discovered)
            if resource.key == "leases" and name == "list":
                operations.append(DiscoveredOperation(
                    operation_id=contract["operation_ids"][0], method="LIST", path_template="/sys/leases/lookup/",
                    summary=discovered.summary, tags=discovered.tags, family=discovered.family,
                    risk_level=discovered.risk_level, response_class=discovered.response_class,
                    required_permission=discovered.required_permission, classified=discovered.classified,
                    query_parameters=discovered.query_parameters,
                    required_query_parameters=discovered.required_query_parameters,
                    query_parameter_types=discovered.query_parameter_types,
                ))
            if (resource.key, name) == duplicate:
                operations.append(discovered)
    return CapabilityDocument("3.0.2", version, digest, tuple(operations))


class FinalContractTest(TestCase):
    def test_identifiers_reject_traversal_and_encoded_separators(self):
        for value in ("../root", "team//db", " team", "team/%2fchild", "X Header"):
            with self.subTest(value=value), self.assertRaises(CapabilitySchemaError):
                normalize_final_identifier(value, "lease-prefix")
        self.assertEqual(normalize_final_identifier("database/creds/", "lease-prefix"), "database/creds/")
        self.assertEqual(normalize_final_identifier("Content-Security-Policy", "header"), "Content-Security-Policy")
        self.assertEqual(
            FINAL_RESOURCES["leases"].path("revoke-prefix", "database/creds/"),
            "/sys/leases/revoke-prefix/database/creds",
        )

    def test_required_tool_fields_are_bounded_and_typed(self):
        operation = FINAL_RESOURCES["random"].operations["generate"]
        self.assertEqual(
            validate_payload({"bytes": 32, "format": "base64"}, operation), {"bytes": 32, "format": "base64"}
        )
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"bytes": 4097}, operation)
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"bytes": 0}, operation)
        self.assertEqual(normalize_final_identifier("all", "source"), "all")
        with self.assertRaises(CapabilitySchemaError):
            normalize_final_identifier("seal", "source")

    def test_hash_input_and_wrapping_ttl_use_the_upstream_wire_types(self):
        hash_operation = FINAL_RESOURCES["hash"].operations["run"]
        self.assertEqual(validate_payload({"input": "Y2FuYXJ5"}, hash_operation), {"input": "Y2FuYXJ5"})
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"input": "not-base64"}, hash_operation)
        wrap_operation = FINAL_RESOURCES["wrapping"].operations["wrap"]
        self.assertEqual(
            validate_payload({"data": {"owner": "platform"}, "ttl": "1h30m"}, wrap_operation),
            {"data": {"owner": "platform"}, "ttl": "1h30m"},
        )
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": {}, "ttl": "tomorrow"}, wrap_operation)

    def test_wrapping_data_preserves_nested_unicode_and_rejects_unbounded_shapes(self):
        operation = FINAL_RESOURCES["wrapping"].operations["wrap"]
        data = {"ключ": {"decimal": 1.25, "items": [True, None, "雪"]}}
        self.assertEqual(validate_payload({"data": data}, operation)["data"], data)
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": {"bad\x00key": "value"}}, operation)
        nested = value = {}
        for _ in range(14):
            value["next"] = {}
            value = value["next"]
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": nested}, operation)

    def test_wrapping_data_accepts_each_exact_bound_and_rejects_the_next_value(self):
        operation = FINAL_RESOURCES["wrapping"].operations["wrap"]
        valid_depth = value = {}
        for _ in range(MAX_WRAPPING_JSON_DEPTH):
            value["n"] = {}
            value = value["n"]
        validate_payload({"data": valid_depth}, operation)
        value["n"] = {}
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": valid_depth}, operation)
        validate_payload({"data": {str(index): None for index in range(MAX_WRAPPING_JSON_MEMBERS)}}, operation)
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": {str(index): None for index in range(MAX_WRAPPING_JSON_MEMBERS + 1)}}, operation)
        validate_payload({"data": {"value": "x" * MAX_WRAPPING_JSON_STRING}}, operation)
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": {"value": "x" * (MAX_WRAPPING_JSON_STRING + 1)}}, operation)
        validate_payload({"data": {"k" * MAX_WRAPPING_JSON_STRING: None}}, operation)
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": {"k" * (MAX_WRAPPING_JSON_STRING + 1): None}}, operation)
        empty = {"a": "", "b": "", "c": ""}
        overhead = len(json.dumps(empty, separators=(",", ":")).encode())
        quotient, remainder = divmod(MAX_WRAPPING_JSON_BYTES - overhead, 3)
        fitted = {key: "x" * (quotient + (index < remainder)) for index, key in enumerate(empty)}
        validate_payload({"data": fitted}, operation)
        oversized = dict(fitted)
        oversized["a"] += "x"
        with self.assertRaises(CapabilitySchemaError):
            validate_payload({"data": oversized}, operation)

    def test_wrapping_data_rejects_nonfinite_unsupported_and_control_values(self):
        operation = FINAL_RESOURCES["wrapping"].operations["wrap"]
        for value in (float("nan"), float("inf"), {1, 2}):
            with self.subTest(value=value), self.assertRaises(CapabilitySchemaError):
                validate_payload({"data": {"value": value}}, operation)
        for data in ({"bad\nkey": "value"}, {"key": "bad\tvalue"}):
            with self.assertRaises(CapabilitySchemaError):
                validate_payload({"data": data}, operation)

    def test_ui_header_values_reject_every_control_character(self):
        operation = FINAL_RESOURCES["ui-headers"].operations["write"]
        for control in ("\x00", "\t", "\n", "\r", "\x1f", "\x7f"):
            with self.subTest(control=ord(control)), self.assertRaises(CapabilitySchemaError):
                validate_payload({"values": [f"safe{control}unsafe"]}, operation)

    def test_empty_identifier_is_only_valid_for_root_lease_listing(self):
        resource = FINAL_RESOURCES["leases"]
        self.assertEqual(resource.path("list", ""), "/sys/leases/lookup/")
        self.assertTrue(resource.public()["operations"]["list"]["identifier_allow_blank"])
        with self.assertRaises(CapabilitySchemaError):
            normalize_final_identifier("", resource.operations["revoke-prefix"].identifier_kind)

    def test_conformance_fails_on_a_missing_reviewed_operation(self):
        report = conformance_report(final_document(omit=("hash", "run")))
        self.assertFalse(report["conformant"])
        self.assertTrue(any(entry["resource"] == "hash" and entry["operation"] == "run" for entry in report["missing"]))

    def test_pinned_fixture_exactly_matches_the_reviewed_registry(self):
        fixture = load_final_route_fixture()
        self.assertEqual(fixture["baseline"], "2.6.2")
        self.assertEqual(len(fixture["operations"]), 17)

    def test_conformance_fails_on_duplicate_unclassified_or_stale_runtime_contracts(self):
        duplicate = conformance_report(final_document(duplicate=("hash", "run")))
        self.assertFalse(duplicate["conformant"])
        self.assertEqual(duplicate["duplicates"][0]["duplicates"], 1)
        unclassified = conformance_report(final_document(unclassified=("hash", "run")))
        self.assertFalse(unclassified["conformant"])
        self.assertEqual(unclassified["unclassified"][0]["unclassified"], 1)
        stale = conformance_report(final_document(version="2.6.1"))
        self.assertFalse(stale["conformant"])
        self.assertTrue(stale["stale"])


class FinalBackendTest(OpenBaoAdministrationTestCase):
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_empty_lease_prefix_is_a_valid_empty_collection(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(b"", status_code=404)
        result = DirectAdministrationBackend(self.cluster).execute_final_operation(
            "LIST", "/sys/leases/lookup/", payload={}
        )
        self.assertEqual(result, {"data": {"keys": [], "key_info": {}}})

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_material_tool_response_is_request_scoped_and_preserved(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(
            json.dumps({"data": {"random_bytes": "canary"}}).encode()
        )
        result = DirectAdministrationBackend(self.cluster).execute_final_operation(
            "POST", "/sys/tools/random/platform", payload={"bytes": 8}, material=True
        )
        self.assertEqual(result["data"]["random_bytes"], "canary")

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_wrap_uses_arbitrary_body_and_dedicated_ttl_header(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(
            json.dumps({"wrap_info": {"token": "canary"}}).encode()
        )
        DirectAdministrationBackend(self.cluster).execute_final_operation(
            "POST",
            "/sys/wrapping/wrap",
            payload={"data": {"owner": "platform"}, "ttl": "30m"},
            material=True,
        )
        request = get_session.return_value.request
        self.assertEqual(request.call_args.kwargs["json"], {"owner": "platform"})
        self.assertEqual(request.call_args.kwargs["headers"]["X-Vault-Wrap-TTL"], "30m")

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_ui_header_read_requests_all_values(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(json.dumps({"data": {"values": ["DENY"]}}).encode())
        DirectAdministrationBackend(self.cluster).execute_final_operation(
            "GET", "/sys/config/ui/headers/X-Frame-Options", payload={}
        )
        self.assertEqual(get_session.return_value.request.call_args.kwargs["params"], {"multivalue": "true"})

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    def test_raft_join_uses_the_unauthed_fixed_endpoint(self, get_session):
        get_session.return_value.request.return_value = _Response(b'{"joined":true}')
        result = DirectAdministrationBackend(self.cluster).join_raft(
            {"leader_api_addr": "https://leader.example.invalid:8200", "leader_client_key": "material-canary"}
        )
        self.assertEqual(result, {"joined": True})
        request = get_session.return_value.request
        self.assertEqual(request.call_args.args[:2], ("POST", "https://bao.example.net:8200/v1/sys/storage/raft/join"))
        self.assertNotIn("X-Vault-Token", request.call_args.kwargs["headers"])


class FakeFinalBackend:
    def __init__(self):
        self.document = final_document()
        self.calls = []
        self.state = {
            "/sys/leases/lookup/": {"data": {"keys": ["database/"]}},
            "/sys/leases/lookup/database": {"data": {"keys": ["creds/abc"]}},
            "/sys/config/ui/headers/X-Frame-Options": {"data": {"values": ["DENY"]}},
        }

    def seal_status(self):
        return SealStatus(True, False, 3, 5, 0, "2.6.2", "shamir", False, False, "raft", "test", "id")

    def discover_capabilities(self):
        return self.document

    def execute_final_operation(self, method, path, *, payload, material=False):
        self.calls.append((method, path, payload, material))
        if method in {"GET", "LIST"}:
            if method == "GET" and path.startswith("/sys/config/ui/headers/") and path not in self.state:
                raise OpenBaoNotFound()
            return self.state.get(path, {"data": {"keys": []}})
        if path == "/sys/leases/lookup":
            return {"data": {"id": payload["lease_id"], "renewable": True}}
        return {"accepted": True, "data": {"random_bytes": "material-canary"} if material else {}}


class FinalAdministrationAPITest(OpenBaoAdministrationTestCase):
    def setUp(self):
        super().setUp()
        self.backend = FakeFinalBackend()
        self.base_permissions = ("netbox_openbao.view_openbaocluster", "netbox_openbao.view_operations_openbaocluster")

    def url(self, action):
        return reverse(f"plugins-api:netbox_openbao-api:openbaocluster-{action}", kwargs={"pk": self.cluster.pk})

    @patch.object(finalization_views, "get_administration_backend")
    def test_catalog_filters_operations_by_dedicated_permissions(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.view_leases_openbaocluster")
        response = self.client.get(self.url("final-resources"), **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        leases = next(item for item in response.data["resources"] if item["key"] == "leases")
        self.assertEqual(set(leases["operations"]), {"list", "lookup"})
        self.assertIn("no-store", response["Cache-Control"])

    @patch.object(finalization_views, "get_administration_backend")
    def test_force_revoke_requires_impact_digest_and_exact_confirmation(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.force_revoke_leases_openbaocluster")
        base = {
            "resource": "leases",
            "operation": "force-revoke",
            "identifier": "database",
            "payload": {},
            "reason": "Reconcile a failed backend.",
            "capability_digest": self.backend.document.digest,
        }
        preview = self.client.post(
            self.url("final-resource-operate"), {**base, "preview": True}, format="json", **self.header
        )
        self.assertEqual(preview.status_code, 200, preview.content)
        response = self.client.post(
            self.url("final-resource-operate"),
            {**base, "impact_digest": preview.data["impact_digest"], "confirmation": preview.data["confirmation"]},
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.backend.calls[-1][:2], ("POST", "/sys/leases/revoke-force/database"))
        self.assertEqual(OpenBaoAdministrationLog.objects.get(outcome="authorized").target_identifiers, ["database"])

    @patch.object(finalization_views, "get_administration_backend")
    def test_force_revoke_detects_changed_descendant_under_unchanged_parent(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.force_revoke_leases_openbaocluster")
        base = {"resource": "leases", "operation": "force-revoke", "identifier": "database", "payload": {},
                "reason": "Reconcile changed descendants.", "capability_digest": self.backend.document.digest}
        preview = self.client.post(self.url("final-resource-operate"), {**base, "preview": True},
                                   format="json", **self.header)
        self.backend.state["/sys/leases/lookup/database"]["data"]["keys"] = ["creds/xyz"]
        response = self.client.post(
            self.url("final-resource-operate"),
            {**base, "impact_digest": preview.data["impact_digest"], "confirmation": preview.data["confirmation"]},
            format="json", **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)

    def test_single_revoke_impact_ignores_countdown_ttl_but_binds_identity_state(self):
        payload = {"lease_id": "database/creds/id", "sync": False}
        self.backend.execute_final_operation = lambda *args, **kwargs: {
            "data": {"id": payload["lease_id"], "ttl": 30, "renewable": True, "path": "database/creds/role"}
        }
        first = finalization_views.FinalizationAdministrationMixin._impact(
            self.backend, FINAL_RESOURCES["leases"], "revoke", "", payload
        )
        self.backend.execute_final_operation = lambda *args, **kwargs: {
            "data": {"id": payload["lease_id"], "ttl": 5, "renewable": True, "path": "database/creds/role"}
        }
        delayed = finalization_views.FinalizationAdministrationMixin._impact(
            self.backend, FINAL_RESOURCES["leases"], "revoke", "", payload
        )
        self.assertEqual(first, delayed)
        self.assertNotIn("ttl", first["current"])
        changed = {**delayed, "current": {**delayed["current"], "renewable": False}}
        self.assertNotEqual(first, changed)

    def test_destructive_lease_impact_rejects_incomplete_or_mismatched_responses(self):
        payload = {"lease_id": "database/creds/id", "sync": False}
        for malformed in ({}, {"data": {}}, {"data": {"id": "database/creds/other"}}):
            self.backend.execute_final_operation = lambda *args, value=malformed, **kwargs: value
            with self.subTest(malformed=malformed), self.assertRaises(OpenBaoConflict):
                finalization_views.FinalizationAdministrationMixin._impact(
                    self.backend, FINAL_RESOURCES["leases"], "revoke", "", payload
                )
        for malformed in ({}, {"data": {}}, {"data": {"keys": "not-a-list"}}):
            self.backend.execute_final_operation = lambda *args, value=malformed, **kwargs: value
            with self.subTest(malformed=malformed), self.assertRaises(OpenBaoConflict):
                finalization_views.FinalizationAdministrationMixin._lease_set(self.backend, "database")

    @patch.object(finalization_views, "get_administration_backend")
    def test_successful_preview_is_metadata_audited_and_audit_failure_is_fail_closed(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.force_revoke_leases_openbaocluster")
        body = {
            "resource": "leases",
            "operation": "force-revoke",
            "identifier": "database",
            "payload": {},
            "reason": "Review destructive lease impact.",
            "capability_digest": self.backend.document.digest,
            "preview": True,
        }
        response = self.client.post(self.url("final-resource-operate"), body, format="json", **self.header)
        self.assertEqual(response.status_code, 200, response.content)
        preview_log = OpenBaoAdministrationLog.objects.get(action="preview-final-resource-impact")
        self.assertEqual(preview_log.operation_id, "final:leases:force-revoke:preview")
        self.assertNotIn("creds/abc", preview_log.message)
        self.assertEqual(
            finalization_views.FinalizationAdministrationMixin.final_resource_operate.sensitive_variables,
            "__ALL__",
        )
        with patch.object(finalization_views, "log_administration", side_effect=AdministrationAuditError("failed")):
            failed = self.client.post(self.url("final-resource-operate"), body, format="json", **self.header)
        self.assertEqual(failed.status_code, 503, failed.content)

    @patch.object(finalization_views, "get_administration_backend")
    def test_ui_header_replacement_binds_current_impact(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_ui_configuration_openbaocluster")
        base = {
            "resource": "ui-headers",
            "operation": "write",
            "identifier": "X-Frame-Options",
            "payload": {"values": ["SAMEORIGIN"]},
            "reason": "Align the administrative UI policy.",
            "capability_digest": self.backend.document.digest,
        }
        preview = self.client.post(
            self.url("final-resource-operate"), {**base, "preview": True}, format="json", **self.header
        )
        self.backend.state["/sys/config/ui/headers/X-Frame-Options"]["data"]["values"] = ["DENY", "SAMEORIGIN"]
        response = self.client.post(
            self.url("final-resource-operate"),
            {**base, "impact_digest": preview.data["impact_digest"], "confirmation": preview.data["confirmation"]},
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)

    @patch.object(finalization_views, "get_administration_backend")
    def test_ui_header_create_binds_absent_state_and_rejects_absent_to_present_race(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_ui_configuration_openbaocluster")
        base = {"resource": "ui-headers", "operation": "write", "identifier": "X-New-Header",
                "payload": {"values": ["enabled"]}, "reason": "Create a reviewed UI header.",
                "capability_digest": self.backend.document.digest}
        preview = self.client.post(self.url("final-resource-operate"), {**base, "preview": True},
                                   format="json", **self.header)
        self.assertEqual(preview.data["impact"]["current"], {"state": "absent"})
        self.backend.state["/sys/config/ui/headers/X-New-Header"] = {"data": {"values": ["raced"]}}
        response = self.client.post(
            self.url("final-resource-operate"),
            {**base, "impact_digest": preview.data["impact_digest"], "confirmation": preview.data["confirmation"]},
            format="json", **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)

    @patch.object(finalization_views, "get_administration_backend")
    def test_ui_header_delete_binds_present_state(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_ui_configuration_openbaocluster")
        base = {"resource": "ui-headers", "operation": "delete", "identifier": "X-Frame-Options",
                "payload": {}, "reason": "Remove the reviewed UI header.",
                "capability_digest": self.backend.document.digest}
        preview = self.client.post(self.url("final-resource-operate"), {**base, "preview": True},
                                   format="json", **self.header)
        self.assertEqual(preview.data["impact"]["current"]["state"], "present")
        response = self.client.post(
            self.url("final-resource-operate"),
            {**base, "impact_digest": preview.data["impact_digest"], "confirmation": preview.data["confirmation"]},
            format="json", **self.header,
        )
        self.assertEqual(response.status_code, 200, response.content)

    @patch.object(finalization_views, "get_administration_backend")
    def test_material_tool_response_is_no_store(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.use_tools_openbaocluster")
        response = self.client.post(
            self.url("final-resource-operate"),
            {
                "resource": "random",
                "operation": "generate",
                "identifier": "platform",
                "payload": {"bytes": 8},
                "reason": "Generate request-scoped entropy.",
                "capability_digest": self.backend.document.digest,
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.data["data"]["random_bytes"], "material-canary")

    @patch.object(finalization_views, "get_administration_backend")
    def test_conformance_endpoint_fails_closed_on_missing_operation(self, get_backend):
        self.backend.document = final_document(omit=("hash", "run"))
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions)
        response = self.client.get(self.url("final-conformance"), **self.header)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertFalse(response.data["conformant"])

    def test_broker_mode_fails_closed_without_advertised_contract(self):
        self.cluster.backend = BackendChoices.BACKEND_BROKER
        self.cluster.save(update_fields=["backend"])
        self.add_permissions(*self.base_permissions, "netbox_openbao.view_leases_openbaocluster")
        response = self.client.get(self.url("final-resources"), **self.header)
        self.assertEqual(response.status_code, 503, response.content)
        self.assertNotContains(response, "cluster-service-token", status_code=503)

    @patch("netbox_openbao.api.views.get_administration_backend")
    def test_raft_join_is_dedicated_confirmed_and_metadata_only(self, get_backend):
        self.add_permissions("netbox_openbao.view_openbaocluster", "netbox_openbao.join_raft_openbaocluster")
        self.backend.seal_status = lambda: SealStatus(
            False, True, 0, 0, 0, "2.6.2", "shamir", False, False, "raft", "", ""
        )
        self.backend.initialization_status = lambda: False
        self.backend.join_raft = lambda payload: {"joined": True}
        get_backend.return_value = self.backend
        response = self.client.post(
            self.url("join-raft"),
            {
                "leader_api_addr": "https://leader.example.invalid:8200",
                "leader_ca_cert": "-----BEGIN CERTIFICATE-----\ncanary\n-----END CERTIFICATE-----",
                "reason": "Join the replacement Raft node.",
                "confirmation": f"JOIN RAFT {self.cluster.slug} VIA DIRECT https://leader.example.invalid:8200",
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["joined"], True)
        self.assertNotIn("leader_ca_cert", response.data)
        self.assertFalse(OpenBaoAdministrationLog.objects.filter(message__contains="canary").exists())
        self.assertEqual(OpenBaoClusterViewSet.join_raft.sensitive_variables, "__ALL__")

    @patch("netbox_openbao.api.views.get_administration_backend")
    def test_raft_join_unknown_is_no_retry_and_metadata_audited(self, get_backend):
        self.add_permissions("netbox_openbao.view_openbaocluster", "netbox_openbao.join_raft_openbaocluster")
        self.backend.seal_status = lambda: SealStatus(
            False, True, 0, 0, 0, "2.6.2", "shamir", False, False, "raft", "", ""
        )
        self.backend.initialization_status = lambda: False
        self.backend.join_raft = lambda payload: (_ for _ in ()).throw(OpenBaoMutationUnknown())
        get_backend.return_value = self.backend
        leader = "https://leader.example.invalid:8200"
        response = self.client.post(
            self.url("join-raft"),
            {"leader_api_addr": leader, "reason": "Join replacement node.",
             "confirmation": f"JOIN RAFT {self.cluster.slug} VIA DIRECT {leader}"},
            format="json", **self.header,
        )
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.data["outcome"], "unknown")
        self.assertEqual(response["X-OpenBao-Operation-Outcome"], "unknown")
        self.assertTrue(OpenBaoAdministrationLog.objects.filter(outcome="unknown", action="join-raft").exists())

    @patch("netbox_openbao.api.views.log_administration")
    @patch("netbox_openbao.api.views.get_administration_backend")
    def test_raft_join_unknown_reports_failed_follow_up_audit(self, get_backend, audit):
        self.add_permissions("netbox_openbao.view_openbaocluster", "netbox_openbao.join_raft_openbaocluster")
        self.backend.seal_status = lambda: SealStatus(
            False, True, 0, 0, 0, "2.6.2", "shamir", False, False, "raft", "", ""
        )
        self.backend.initialization_status = lambda: False
        self.backend.join_raft = lambda payload: (_ for _ in ()).throw(OpenBaoMutationUnknown())
        get_backend.return_value = self.backend
        audit.side_effect = [None, AdministrationAuditError("audit unavailable")]
        leader = "https://leader.example.invalid:8200"
        response = self.client.post(
            self.url("join-raft"),
            {"leader_api_addr": leader, "reason": "Join replacement node.",
             "confirmation": f"JOIN RAFT {self.cluster.slug} VIA DIRECT {leader}"},
            format="json", **self.header,
        )
        self.assertEqual(response.data["audit_status"], "failed")
        self.assertEqual(response["X-OpenBao-Audit-Status"], "failed")
