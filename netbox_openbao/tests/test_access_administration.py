"""Policy, identity, OIDC, and namespace administration tests."""

import json
from unittest import TestCase
from unittest.mock import patch

from django.urls import reverse

from netbox_openbao.administration.access import (
    ACCESS_RESOURCES,
    normalize_access_response,
    normalize_identifier,
    runtime_advertises,
    validate_access_payload,
)
from netbox_openbao.administration.audit import AdministrationAuditError
from netbox_openbao.administration.backends import DirectAdministrationBackend
from netbox_openbao.administration.cluster import SealStatus
from netbox_openbao.administration.schema import CapabilityDocument, CapabilitySchemaError, DiscoveredOperation
from netbox_openbao.api import access_views
from netbox_openbao.backends.exceptions import OpenBaoMutationUnknown
from netbox_openbao.models import OpenBaoAdministrationLog
from netbox_openbao.tests.test_administration import OpenBaoAdministrationTestCase, _Response


def access_document(*, digest="c" * 64):
    seen = set()
    operations = []
    for resource in ACCESS_RESOURCES.values():
        for operation in resource.operations.values():
            key = (operation.method, operation.path_template)
            if key in seen:
                continue
            seen.add(key)
            operations.append(
                DiscoveredOperation(
                    operation_id=f"access-operation-{len(operations)}",
                    method=operation.method,
                    path_template=operation.path_template.replace("{identifier}", "{name}"),
                    summary="Reviewed access operation",
                    tags=(resource.family,),
                    family=resource.family,
                    risk_level=operation.risk,
                    response_class=operation.response_kind,
                    required_permission=operation.permission,
                    classified=True,
                )
            )
    return CapabilityDocument(
        openapi_version="3.0.2",
        product_version="2.6.2",
        digest=digest,
        operations=tuple(operations),
    )


class AccessContractTest(TestCase):
    def test_identifier_normalization_rejects_traversal_and_encoding(self):
        for value in ("../root", "team/child", "team//child", "/absolute", "team/%2e%2e", "team\\child", " team"):
            with self.subTest(value=value), self.assertRaises(CapabilitySchemaError):
                normalize_identifier(value, "namespace")
        self.assertEqual(normalize_identifier("team-child", "namespace"), "team-child")

    def test_policy_and_template_documents_remain_inert_bounded_data(self):
        canary = "{{ constructor.constructor('return process')() }}; path \"*\" {}"
        policy = validate_access_payload(
            {"policy": canary}, ACCESS_RESOURCES["acl-policies"].operations["write"].fields
        )
        template = validate_access_payload(
            {"template": canary}, ACCESS_RESOURCES["oidc-scopes"].operations["write"].fields
        )
        self.assertEqual(policy["policy"], canary)
        self.assertEqual(template["template"], canary)

    def test_unknown_fields_and_noncanonical_uuid_references_fail_closed(self):
        fields = ACCESS_RESOURCES["oidc-assignments"].operations["write"].fields
        with self.assertRaises(CapabilitySchemaError):
            validate_access_payload({"future": "field"}, fields)
        with self.assertRaises(CapabilitySchemaError):
            validate_access_payload({"entity_ids": ["NOT-A-UUID"]}, fields)

    def test_metadata_response_removes_material_but_material_contract_preserves_it(self):
        payload = {
            "data": {
                "client_id": "client",
                "client_secret": "secret-canary",
                "key_shares": ["unseal-share-canary"],
                "name": "app",
            }
        }
        self.assertNotIn("client_secret", normalize_access_response(payload)["data"])
        self.assertNotIn("key_shares", normalize_access_response(payload)["data"])
        self.assertEqual(
            normalize_access_response(payload, material=True)["data"]["client_secret"], "secret-canary"
        )

    def test_namespace_writes_require_explicit_replacement_metadata_and_reject_seal_material(self):
        fields = ACCESS_RESOURCES["namespaces"].operations["write"].fields
        with self.assertRaises(CapabilitySchemaError):
            validate_access_payload({}, fields)
        with self.assertRaises(CapabilitySchemaError):
            validate_access_payload({"custom_metadata": {}, "seal": "shamir"}, fields)
        self.assertEqual(validate_access_payload({"custom_metadata": {}}, fields), {"custom_metadata": {}})

    def test_runtime_proof_matches_literals_not_upstream_placeholder_names(self):
        operation = ACCESS_RESOURCES["oidc-providers"].operations["read"]
        self.assertTrue(runtime_advertises(access_document(), operation))
        wrong = access_document()
        candidate = wrong.operations[0]
        wrong = CapabilityDocument(
            openapi_version=wrong.openapi_version,
            product_version=wrong.product_version,
            digest=wrong.digest,
            operations=(
                DiscoveredOperation(
                    operation_id=candidate.operation_id,
                    method="GET",
                    path_template="/identity/oidc/provider/{name}/authorize",
                    summary="Wrong literal",
                    tags=("oidc",),
                    family="oidc",
                    risk_level="read",
                    response_class="metadata",
                    required_permission="netbox_openbao.view_access_openbaocluster",
                    classified=True,
                ),
            ),
        )
        self.assertFalse(runtime_advertises(wrong, operation))


class AccessBackendTest(OpenBaoAdministrationTestCase):
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_transport_uses_fixed_namespace_headers_and_never_relays_material_for_metadata(
        self, get_client, get_session
    ):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(
            json.dumps({"data": {"name": "alice", "token": "material-canary"}}).encode()
        )
        self.cluster.namespace = "team-a"

        result = DirectAdministrationBackend(self.cluster).execute_access_operation(
            "GET", "/identity/entity/id/11111111-1111-1111-8111-111111111111", payload={}
        )

        self.assertEqual(result, {"data": {"name": "alice"}})
        request = get_session.return_value.request.call_args
        self.assertEqual(request.args[0], "GET")
        self.assertEqual(request.kwargs["headers"]["X-Vault-Namespace"], "team-a")
        self.assertNotIn("material-canary", str(result))

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_mutation_transport_failure_is_an_unknown_outcome(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.side_effect = TimeoutError("after dispatch")
        with self.assertRaises(OpenBaoMutationUnknown):
            DirectAdministrationBackend(self.cluster).execute_access_operation(
                "POST", "/sys/policies/acl/team", payload={"policy": "path \"secret/*\" {}"}
            )

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_accepted_mutation_with_malformed_response_is_an_unknown_outcome(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(b'{"data":')
        with self.assertRaises(OpenBaoMutationUnknown):
            DirectAdministrationBackend(self.cluster).execute_access_operation(
                "POST", "/sys/policies/acl/team", payload={"policy": "path \"secret/*\" {}"}
            )

    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_session")
    @patch("netbox_openbao.administration.backends.OpenBaoBackend._get_client")
    def test_empty_list_response_is_a_valid_empty_collection(self, get_client, get_session):
        get_client.return_value.token = "cluster-service-token"
        get_session.return_value.request.return_value = _Response(b"", status_code=404)

        result = DirectAdministrationBackend(self.cluster).execute_access_operation(
            "LIST", "/identity/entity/id", payload={}
        )

        self.assertEqual(result, {"data": {"keys": [], "key_info": {}}})


class FakeAccessBackend:
    def __init__(self, cluster):
        self.cluster = cluster
        self.document = access_document()
        self.calls = []
        self.values = {
            "/sys/policies/acl/team": {"data": {"name": "team", "policy": "path \"secret/*\" {}"}},
            "/identity/entity/id/11111111-1111-1111-8111-111111111111": {
                "data": {"id": "11111111-1111-1111-8111-111111111111", "name": "destination"}
            },
            "/identity/entity/id/22222222-2222-2222-8222-222222222222": {
                "data": {"id": "22222222-2222-2222-8222-222222222222", "name": "source"}
            },
        }

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

    def execute_access_operation(self, method, path, *, payload, material=False):
        self.calls.append((method, path, payload, material))
        if method in {"GET", "LIST"}:
            return self.values.get(path, {"data": {"keys": ["team"]}})
        if method == "POST" and path == "/identity/oidc/client/app":
            return {"data": {"client_id": "id", "client_secret": "client-secret-canary"}}
        return {"path": path, "accepted": True}


class AccessAdministrationAPITest(OpenBaoAdministrationTestCase):
    def setUp(self):
        super().setUp()
        self.backend = FakeAccessBackend(self.cluster)
        self.base_permissions = (
            "netbox_openbao.view_openbaocluster",
            "netbox_openbao.view_access_openbaocluster",
        )

    def catalog_url(self):
        return reverse(
            "plugins-api:netbox_openbao-api:openbaocluster-access-resources", kwargs={"pk": self.cluster.pk}
        )

    def preview_url(self):
        return reverse(
            "plugins-api:netbox_openbao-api:openbaocluster-access-resource-preview",
            kwargs={"pk": self.cluster.pk},
        )

    def execute_url(self):
        return reverse(
            "plugins-api:netbox_openbao-api:openbaocluster-access-resource-execute",
            kwargs={"pk": self.cluster.pk},
        )

    def write_request(self):
        return {
            "resource": "acl-policies",
            "operation": "write",
            "identifier": "team",
            "payload": {"policy": "path \"secret/*\" {}"},
            "reason": "Update the team policy.",
            "capability_digest": self.backend.document.digest,
        }

    @patch.object(access_views, "get_administration_backend")
    def test_catalog_is_runtime_and_object_permission_filtered(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_policies_openbaocluster")

        response = self.client.get(self.catalog_url(), **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        policies = next(item for item in response.data["resources"] if item["key"] == "acl-policies")
        self.assertEqual(set(policies["operations"]), {"list", "read", "write"})
        oidc_clients = next(item for item in response.data["resources"] if item["key"] == "oidc-clients")
        self.assertEqual(set(oidc_clients["operations"]), {"list"})

    @patch.object(access_views, "get_administration_backend")
    def test_stale_capability_digest_refuses_execution_before_backend_operation(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_policies_openbaocluster")
        response = self.client.post(
            self.execute_url(),
            {
                "resource": "acl-policies",
                "operation": "write",
                "identifier": "team",
                "payload": {"policy": "path \"secret/*\" {}"},
                "reason": "Update the team policy.",
                "capability_digest": "d" * 64,
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(self.backend.calls, [])

    @patch.object(access_views, "log_administration")
    @patch.object(access_views, "get_administration_backend")
    def test_durable_preflight_audit_failure_blocks_mutation(self, get_backend, audit):
        get_backend.return_value = self.backend
        audit.side_effect = AdministrationAuditError("audit unavailable")
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_policies_openbaocluster")

        response = self.client.post(self.execute_url(), self.write_request(), format="json", **self.header)

        self.assertEqual(response.status_code, 503, response.content)
        self.assertFalse(any(call[0] == "POST" for call in self.backend.calls))

    @patch.object(access_views, "log_administration")
    @patch.object(access_views, "get_administration_backend")
    def test_completion_audit_failure_preserves_accepted_mutation(self, get_backend, audit):
        get_backend.return_value = self.backend
        audit.side_effect = (None, AdministrationAuditError("audit unavailable"))
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_policies_openbaocluster")

        response = self.client.post(self.execute_url(), self.write_request(), format="json", **self.header)

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["outcome"], "accepted-audit-incomplete")
        self.assertEqual(response["X-OpenBao-Audit-Status"], "preflight-only")
        self.assertEqual(sum(call[0] == "POST" for call in self.backend.calls), 1)

    @patch.object(access_views, "get_administration_backend")
    def test_uuid_identity_update_is_retained_in_audit_targets(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.manage_identity_openbaocluster")
        entity_id = "11111111-1111-1111-8111-111111111111"

        response = self.client.post(
            self.execute_url(),
            {
                "resource": "entities",
                "operation": "write",
                "payload": {"id": entity_id, "disabled": True},
                "reason": "Disable the obsolete identity.",
                "capability_digest": self.backend.document.digest,
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        logs = OpenBaoAdministrationLog.objects.filter(operation_id="access:entities:write")
        self.assertEqual({tuple(log.target_identifiers) for log in logs}, {(entity_id,)})

    @patch.object(access_views, "get_administration_backend")
    def test_empty_list_is_returned_through_the_mediated_api(self, get_backend):
        get_backend.return_value = self.backend
        self.backend.values["/identity/entity/id"] = {"data": {"keys": [], "key_info": {}}}
        self.add_permissions(*self.base_permissions)

        response = self.client.post(
            self.execute_url(),
            {
                "resource": "entities",
                "operation": "list",
                "payload": {},
                "reason": "List the empty identity collection.",
                "capability_digest": self.backend.document.digest,
            },
            format="json",
            **self.header,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data, {"data": {"keys": [], "key_info": {}}})

    @patch.object(access_views, "get_administration_backend")
    def test_delete_requires_current_impact_digest_and_exact_confirmation(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.delete_policies_openbaocluster")
        request = {
            "resource": "acl-policies",
            "operation": "delete",
            "identifier": "team",
            "payload": {},
            "capability_digest": self.backend.document.digest,
        }

        preview = self.client.post(self.preview_url(), request, format="json", **self.header)
        self.assertEqual(preview.status_code, 200, preview.content)
        self.backend.values["/sys/policies/acl/team"]["request_id"] = "fresh-request-id"
        request.update(
            {
                "reason": "Retire the obsolete team policy.",
                "impact_digest": preview.data["impact_digest"],
                "confirmation": preview.data["confirmation"],
            }
        )
        executed = self.client.post(self.execute_url(), request, format="json", **self.header)
        self.assertEqual(executed.status_code, 200, executed.content)
        self.assertEqual(self.backend.calls[-1][:2], ("DELETE", "/sys/policies/acl/team"))
        authorized = OpenBaoAdministrationLog.objects.get(outcome="authorized")
        self.assertEqual(authorized.target_identifiers, ["team"])

    @patch.object(access_views, "get_administration_backend")
    def test_changed_impact_refuses_destructive_execution(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.delete_policies_openbaocluster")
        base = {
            "resource": "acl-policies",
            "operation": "delete",
            "identifier": "team",
            "payload": {},
            "capability_digest": self.backend.document.digest,
        }
        preview = self.client.post(self.preview_url(), base, format="json", **self.header)
        self.backend.values["/sys/policies/acl/team"]["data"]["policy"] = "changed"
        response = self.client.post(
            self.execute_url(),
            {
                **base,
                "reason": "Retire the obsolete team policy.",
                "impact_digest": preview.data["impact_digest"],
                "confirmation": preview.data["confirmation"],
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertFalse(any(call[0] == "DELETE" for call in self.backend.calls))

    @patch.object(access_views, "get_administration_backend")
    def test_merge_preview_binds_force_and_alias_conflict_choices(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.merge_identity_openbaocluster")
        payload = {
            "to_entity_id": "11111111-1111-1111-8111-111111111111",
            "from_entity_ids": ["22222222-2222-2222-8222-222222222222"],
            "force": False,
            "conflicting_alias_ids_to_keep": [],
        }
        request = {
            "resource": "entities",
            "operation": "merge",
            "payload": payload,
            "capability_digest": self.backend.document.digest,
        }
        preview = self.client.post(self.preview_url(), request, format="json", **self.header)
        self.assertEqual(preview.status_code, 200, preview.content)
        self.assertEqual(preview.data["impact"]["payload"], payload)

        response = self.client.post(
            self.execute_url(),
            {
                **request,
                "payload": {**payload, "force": True},
                "reason": "Merge duplicate identities.",
                "impact_digest": preview.data["impact_digest"],
                "confirmation": preview.data["confirmation"],
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertFalse(any(call[0] == "POST" for call in self.backend.calls))

    @patch.object(access_views, "get_administration_backend")
    def test_oidc_client_material_requires_dedicated_read_permission_and_is_no_store(self, get_backend):
        get_backend.return_value = self.backend
        self.add_permissions(*self.base_permissions, "netbox_openbao.reveal_oidc_client_secrets_openbaocluster")
        response = self.client.post(
            self.execute_url(),
            {
                "resource": "oidc-clients",
                "operation": "read",
                "identifier": "app",
                "payload": {},
                "reason": "Transfer the generated client credential.",
                "capability_digest": self.backend.document.digest,
            },
            format="json",
            **self.header,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(self.backend.calls[-1][-1], True)

    def test_ui_requires_dedicated_object_permission(self):
        url = reverse("plugins:netbox_openbao:openbaocluster_access", kwargs={"pk": self.cluster.pk})
        self.add_permissions("netbox_openbao.view_openbaocluster")
        self.assertEqual(self.client.get(url).status_code, 302)
        self.add_permissions("netbox_openbao.view_access_openbaocluster")
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Access administration")

        detail = self.client.get(self.cluster.get_absolute_url())
        self.assertContains(detail, "Policies and identity")
