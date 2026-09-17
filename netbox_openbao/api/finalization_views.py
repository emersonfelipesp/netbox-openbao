"""REST actions for leases, tools, UI headers, and parity conformance."""

import json
from hashlib import sha256

from django.db import DatabaseError
from django.views.decorators.debug import sensitive_variables
from packaging.version import InvalidVersion, Version
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from netbox_openbao.administration import get_administration_backend
from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.administration.finalization import (
    FINAL_RESOURCES,
    advertised,
    conformance_report,
    normalize_final_identifier,
)
from netbox_openbao.administration.schema import CapabilitySchemaError
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoError, OpenBaoMutationUnknown, OpenBaoNotFound
from netbox_openbao.models import OpenBaoCluster

from .authentication_views import _no_store
from .finalization_serializers import FinalOperationSerializer
from .permissions import ClusterActionPermissions


def _digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _lease_entries(response: dict, prefix: str) -> list[tuple[bool, str]]:
    if not isinstance(response, dict):
        raise OpenBaoConflict("OpenBao returned an invalid lease hierarchy.")
    container = response.get("data")
    if not isinstance(container, dict):
        raise OpenBaoConflict("OpenBao returned an invalid lease hierarchy.")
    keys = container.get("keys")
    if not isinstance(keys, list) or len(keys) > 2_000:
        raise OpenBaoConflict("OpenBao returned an invalid lease hierarchy.")
    entries = []
    for key in keys:
        if not isinstance(key, str) or not key:
            raise OpenBaoConflict("OpenBao returned an invalid lease hierarchy.")
        combined = "/".join(part for part in (prefix, key.rstrip("/")) if part)
        try:
            normalized = normalize_final_identifier(combined, "lease-prefix")
        except CapabilitySchemaError:
            raise OpenBaoConflict("OpenBao returned an invalid lease hierarchy.") from None
        entries.append((key.endswith("/"), normalized))
    return entries


def _bounded_lease_result(leaves: set[str]) -> list[str]:
    result = sorted(leaves)
    if len(result) > 2_000 or len(json.dumps(result, separators=(",", ":")).encode()) > 256_000:
        raise OpenBaoConflict("The lease hierarchy exceeds the reviewed preview bounds.")
    return result


class FinalizationAdministrationMixin:
    """Reviewed final parity actions mixed into the cluster API."""

    @staticmethod
    def _permission_action(permission: str) -> str:
        codename = permission.rsplit(".", 1)[-1]
        return codename.removesuffix("_openbaocluster")

    def _can(self, request, cluster, permission: str) -> bool:
        return (
            OpenBaoCluster.objects.restrict(request.user, self._permission_action(permission))
            .filter(pk=cluster.pk)
            .exists()
        )

    def _prepare_final(self, cluster, operation, supplied_digest: str):
        backend = get_administration_backend(cluster)
        seal = backend.seal_status()
        self._require_baseline(seal)
        if not seal.initialized or seal.sealed:
            raise OpenBaoConflict("The OpenBao cluster is not ready for this operation.")
        document = backend.discover_capabilities()
        try:
            version = Version(document.product_version)
        except InvalidVersion:
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.") from None
        if version < Version("2.6.2") or version.release[:2] != (2, 6):
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.")
        if document.digest != supplied_digest:
            raise OpenBaoConflict("OpenBao capabilities changed; reload the operations workspace.")
        if not conformance_report(document)["conformant"] or not advertised(document, operation):
            raise OpenBaoConflict("OpenBao does not advertise the reviewed operation.")
        return backend, document

    @staticmethod
    def _lease_set(backend, prefix: str) -> list[str]:
        pending = [(prefix.rstrip("/"), 0)]
        visited = set()
        leaves = set()
        leaf_bytes = 2
        while pending:
            current_prefix, depth = pending.pop()
            if current_prefix in visited or depth > 12 or len(visited) >= 256:
                raise OpenBaoConflict("The lease hierarchy exceeds the reviewed preview bounds.")
            visited.add(current_prefix)
            response = backend.execute_final_operation(
                "LIST", FINAL_RESOURCES["leases"].path("list", current_prefix), payload={}
            )
            for branch, path in _lease_entries(response, current_prefix):
                if branch:
                    pending.append((path, depth + 1))
                    if len(visited) + len(pending) > 256:
                        raise OpenBaoConflict("The lease hierarchy exceeds the reviewed preview bounds.")
                else:
                    previous_count = len(leaves)
                    leaves.add(path)
                    if len(leaves) != previous_count:
                        leaf_bytes += len(json.dumps(path, ensure_ascii=True).encode()) + 1
                    if len(leaves) > 2_000:
                        raise OpenBaoConflict("The lease hierarchy exceeds the reviewed preview bounds.")
                    if leaf_bytes > 256_000:
                        raise OpenBaoConflict("The lease hierarchy exceeds the reviewed preview bounds.")
        return _bounded_lease_result(leaves)

    @staticmethod
    def _impact(backend, resource, operation_name: str, identifier: str, payload: dict) -> dict:
        if resource.key == "leases":
            if operation_name == "revoke":
                response = backend.execute_final_operation(
                    "POST", "/sys/leases/lookup", payload={"lease_id": payload["lease_id"]}
                )
                current = response.get("data") if isinstance(response, dict) else None
                if not isinstance(current, dict) or current.get("id") != payload["lease_id"]:
                    raise OpenBaoConflict("OpenBao returned an invalid lease identity.")
                current = dict(current)
                current.pop("ttl", None)
            else:
                current = {"leases": FinalizationAdministrationMixin._lease_set(backend, identifier)}
        elif resource.key == "ui-headers":
            try:
                response = backend.execute_final_operation("GET", resource.path("read", identifier), payload={})
            except OpenBaoNotFound:
                current = {"state": "absent"}
            else:
                current = {"state": "present", "data": response.get("data", response)}
        else:
            raise OpenBaoConflict("The selected operation has no reviewed impact preview.")
        return {
            "resource": resource.key,
            "operation": operation_name,
            "identifier": identifier,
            "payload": payload,
            "current": current,
        }

    @action(
        detail=True,
        methods=["get"],
        url_path="final-resources",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def final_resources(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_operations")
        try:
            backend = get_administration_backend(cluster)
            seal = backend.seal_status()
            self._require_baseline(seal)
            document = backend.discover_capabilities()
            if not conformance_report(document)["conformant"]:
                raise OpenBaoConflict("OpenBao does not conform to the pinned final-operation contract.")
            resources = []
            for resource in FINAL_RESOURCES.values():
                public = resource.public()
                public["operations"] = {
                    name: contract
                    for name, contract in public["operations"].items()
                    if self._can(request, cluster, contract["required_permission"])
                    and advertised(document, resource.operations[name])
                }
                if public["operations"]:
                    resources.append(public)
            log_administration(
                cluster,
                request.user,
                action="list-final-resources",
                operation_id="final-resource-catalog",
                risk_level="read",
                capability_digest=document.digest,
                success=True,
                status_code=200,
                message="Listed permission-filtered final parity resources.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "list-final-resources", exc, risk_level="read")
        return _no_store(Response({"capability_digest": document.digest, "resources": resources}))

    @action(
        detail=True,
        methods=["get"],
        url_path="final-conformance",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def final_conformance(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_operations")
        try:
            backend = get_administration_backend(cluster)
            seal = backend.seal_status()
            self._require_baseline(seal)
            document = backend.discover_capabilities()
            report = conformance_report(document)
            log_administration(
                cluster,
                request.user,
                action="final-conformance",
                operation_id="final-conformance",
                risk_level="read",
                capability_digest=document.digest,
                success=report["conformant"],
                status_code=200 if report["conformant"] else 409,
                message="Compared the runtime contract with the pinned OpenBao 2.6.2 final-operation fixture.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "final-conformance", exc, risk_level="read")
        return _no_store(Response(report, status=200 if report["conformant"] else 409))

    @sensitive_variables()
    @action(
        detail=True,
        methods=["post"],
        url_path="final-resources/operate",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def final_resource_operate(self, request, pk=None):
        raw_request = getattr(request, "_request", request)
        raw_request.sensitive_post_parameters = "__ALL__"
        cluster = self._cluster(request, pk, "view_operations")
        serializer = FinalOperationSerializer(data=request.data, context={"cluster": cluster})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        resource, operation = data["resource_spec"], data["operation_spec"]
        cluster = self._cluster(request, pk, self._permission_action(operation.permission))
        target = data.get("identifier") or data["payload"].get("lease_id", resource.key)
        try:
            backend, document = self._prepare_final(cluster, operation, data["capability_digest"])
            if data["preview"]:
                impact = self._impact(backend, resource, data["operation"], data.get("identifier", ""), data["payload"])
                log_administration(
                    cluster,
                    request.user,
                    action="preview-final-resource-impact",
                    operation_id=f"final:{resource.key}:{data['operation']}:preview",
                    risk_level="read",
                    method="GET",
                    path_template=operation.path_template,
                    capability_digest=document.digest,
                    target_identifiers=[target],
                    success=True,
                    status_code=200,
                    message="Previewed final-operation impact without retaining response data.",
                    request=request,
                )
                return _no_store(
                    Response(
                        {
                            "impact": impact,
                            "impact_digest": _digest(impact),
                            "confirmation": data["expected_confirmation"],
                        }
                    )
                )
            if operation.confirmation:
                impact = self._impact(backend, resource, data["operation"], data.get("identifier", ""), data["payload"])
                if _digest(impact) != data["impact_digest"]:
                    raise OpenBaoConflict("The operation impact changed; preview it again.")
            log_administration(
                cluster,
                request.user,
                action="execute-final-resource-authorized",
                operation_id=f"final:{resource.key}:{data['operation']}",
                risk_level=operation.risk,
                method=operation.method,
                path_template=operation.path_template,
                reason=data["reason"],
                capability_digest=document.digest,
                target_identifiers=[target],
                outcome="authorized",
                success=True,
                message="Authorized a reviewed final parity operation.",
                request=request,
                require_durable=True,
            )
            result = backend.execute_final_operation(
                operation.method,
                resource.path(data["operation"], data.get("identifier", "")),
                payload=data["payload"],
                material=operation.response_kind == "material",
            )
        except OpenBaoMutationUnknown:
            audit_status = "best-effort"
            try:
                log_administration(
                    cluster,
                    request.user,
                    action="execute-final-resource",
                    operation_id=f"final:{resource.key}:{data['operation']}",
                    risk_level=operation.risk,
                    method=operation.method,
                    path_template=operation.path_template,
                    reason=data["reason"],
                    capability_digest=data["capability_digest"],
                    target_identifiers=[target],
                    outcome="unknown",
                    success=False,
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    message="The final operation outcome is unknown; no request material was retained.",
                    request=request,
                )
            except (AdministrationAuditError, DatabaseError):
                audit_status = "failed"
            response = _no_store(
                Response(
                    {
                        "outcome": "unknown",
                        "audit_status": audit_status,
                        "message": "OpenBao may have accepted the request. Do not retry; verify current state first.",
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )
            )
            response["X-OpenBao-Operation-Outcome"] = "unknown"
            response["X-OpenBao-Audit-Status"] = audit_status
            return response
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(
                request, cluster, "execute-final-resource", exc, reason=data["reason"], risk_level=operation.risk
            )
        audit_complete = True
        try:
            log_administration(
                cluster,
                request.user,
                action="execute-final-resource",
                operation_id=f"final:{resource.key}:{data['operation']}",
                risk_level=operation.risk,
                method=operation.method,
                path_template=operation.path_template,
                reason=data["reason"],
                capability_digest=document.digest,
                target_identifiers=[target],
                success=True,
                status_code=200,
                message="Completed a reviewed final parity operation.",
                request=request,
            )
        except AdministrationAuditError:
            audit_complete = False
        return _no_store(self._mutation_response(result, status_code=200, audit_complete=audit_complete))
