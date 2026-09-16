"""Typed REST actions for OpenBao policies, identity, OIDC, and namespaces."""

from __future__ import annotations

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
from netbox_openbao.administration.access import ACCESS_RESOURCES, runtime_advertises
from netbox_openbao.administration.audit import AdministrationAuditError, log_administration
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoError, OpenBaoMutationUnknown, OpenBaoUnavailable
from netbox_openbao.models import OpenBaoCluster

from .access_serializers import AccessExecuteSerializer, AccessPreviewSerializer
from .authentication_views import _no_store
from .permissions import ClusterActionPermissions


def _canonical_digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _stable_resource_state(response: dict) -> dict:
    """Exclude OpenBao's per-request transport envelope from impact binding."""
    data = response.get("data")
    if not isinstance(data, dict):
        raise OpenBaoUnavailable("OpenBao returned an invalid resource state.")
    return data


def _audit_targets(resource, operation_name: str, identifier: str, payload: dict) -> list[str]:
    if operation_name == "merge":
        return [payload["to_entity_id"], *payload["from_entity_ids"]]
    targets = [identifier or payload.get("id") or payload.get("name", "")]
    canonical_id = payload.get("canonical_id")
    if canonical_id and canonical_id not in targets:
        targets.append(canonical_id)
    return [target for target in targets if target]


def _completion_targets(targets: list[str], result: dict) -> list[str]:
    result_id = result.get("data", {}).get("id") if isinstance(result.get("data"), dict) else None
    if isinstance(result_id, str) and result_id not in targets:
        return [*targets, result_id]
    return targets


class AccessAdministrationMixin:
    """Policy, identity, OIDC, and namespace actions mixed into the cluster API."""

    @staticmethod
    def _permission_action(permission: str) -> str:
        suffix = "_openbaocluster"
        codename = permission.rsplit(".", 1)[-1]
        return codename[: -len(suffix)] if codename.endswith(suffix) else codename

    def _can_access(self, request, cluster, permission: str) -> bool:
        action_name = self._permission_action(permission)
        return OpenBaoCluster.objects.restrict(request.user, action_name).filter(pk=cluster.pk).exists()

    @staticmethod
    def _require_access_version(document):
        try:
            version = Version(document.product_version)
        except InvalidVersion:
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.") from None
        if version < Version("2.6.2") or version.release[:2] != (2, 6):
            raise OpenBaoConflict("OpenBao returned an unsupported capability version.")

    def _prepare_access_operation(self, cluster, operation, supplied_digest: str):
        backend = get_administration_backend(cluster)
        seal = backend.seal_status()
        self._require_baseline(seal)
        if not seal.initialized or seal.sealed:
            raise OpenBaoConflict("The OpenBao cluster is not ready for access administration.")
        document = backend.discover_capabilities()
        self._require_access_version(document)
        if document.digest != supplied_digest:
            raise OpenBaoConflict("OpenBao capabilities changed; reload the access workspace.")
        if not runtime_advertises(document, operation):
            raise OpenBaoConflict("OpenBao does not advertise the reviewed operation.")
        return backend, document

    @staticmethod
    def _unknown_access_response():
        response = _no_store(
            Response(
                {
                    "outcome": "unknown",
                    "audit_status": "preflight-only",
                    "message": "OpenBao may have accepted the request. Do not retry; verify current state first.",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        )
        response["X-OpenBao-Operation-Outcome"] = "unknown"
        response["X-OpenBao-Audit-Status"] = "preflight-only"
        return response

    def _impact_state(self, backend, resource, operation_name: str, identifier: str, payload: dict) -> dict:
        if operation_name == "merge":
            ids = [payload["to_entity_id"], *payload["from_entity_ids"]]
            read_operation = ACCESS_RESOURCES["entities"].operations["read"]
            entities = [
                _stable_resource_state(
                    backend.execute_access_operation(
                        read_operation.method,
                        ACCESS_RESOURCES["entities"].path("read", entity_id),
                        payload={},
                    )
                )
                for entity_id in ids
            ]
            return {
                "resource": resource.key,
                "operation": operation_name,
                "payload": payload,
                "entities": entities,
            }
        read_operation = resource.operations.get("read")
        if read_operation is None:
            raise OpenBaoConflict("The selected operation has no reviewed impact preview.")
        current = _stable_resource_state(
            backend.execute_access_operation(
                read_operation.method,
                resource.path("read", identifier),
                payload={},
                material=False,
            )
        )
        return {
            "resource": resource.key,
            "operation": operation_name,
            "identifier": identifier,
            "current": current,
        }

    @action(
        detail=True,
        methods=["get"],
        url_path="access-resources",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def access_resources(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_access")
        try:
            backend = get_administration_backend(cluster)
            seal = backend.seal_status()
            self._require_baseline(seal)
            document = backend.discover_capabilities()
            self._require_access_version(document)
            resources = []
            for resource in ACCESS_RESOURCES.values():
                public = resource.as_public_dict()
                public["operations"] = {
                    name: contract
                    for name, contract in public["operations"].items()
                    if self._can_access(request, cluster, contract["required_permission"])
                    and runtime_advertises(document, resource.operations[name])
                }
                if public["operations"]:
                    resources.append(public)
            log_administration(
                cluster,
                request.user,
                action="list-access-resources",
                operation_id="access-resource-catalog",
                risk_level="read",
                method="GET",
                path_template="reviewed access resource registry",
                capability_digest=document.digest,
                success=True,
                status_code=200,
                message="Listed permission-filtered reviewed access-control resources.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "list-access-resources", exc, risk_level="read")
        return _no_store(Response({"capability_digest": document.digest, "resources": resources}))

    @action(
        detail=True,
        methods=["post"],
        url_path="access-resources/preview",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def access_resource_preview(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_access")
        serializer = AccessPreviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        resource = data["resource_spec"]
        operation = data["operation_spec"]
        if not self._can_access(request, cluster, operation.permission):
            cluster = self._cluster(request, pk, self._permission_action(operation.permission))
        try:
            backend, document = self._prepare_access_operation(cluster, operation, data["capability_digest"])
            impact = self._impact_state(
                backend, resource, data["operation"], data.get("identifier", ""), data["payload"]
            )
            impact_digest = _canonical_digest(impact)
            confirmation = operation.confirmation.format(
                resource=resource.key,
                identifier=data.get("identifier", ""),
                cluster=cluster.slug,
            )
            log_administration(
                cluster,
                request.user,
                action="preview-access-impact",
                operation_id=f"access:{resource.key}:{data['operation']}:preview",
                risk_level="read",
                method="GET",
                path_template=operation.path_template,
                capability_digest=document.digest,
                success=True,
                status_code=200,
                message="Previewed current access-control impact without retaining response data.",
                request=request,
            )
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(request, cluster, "preview-access-impact", exc, risk_level="read")
        return _no_store(
            Response({"impact": impact, "impact_digest": impact_digest, "confirmation": confirmation})
        )

    @sensitive_variables()
    @action(
        detail=True,
        methods=["post"],
        url_path="access-resources/execute",
        permission_classes=[ClusterActionPermissions],
        renderer_classes=[JSONRenderer],
    )
    def access_resource_execute(self, request, pk=None):
        cluster = self._cluster(request, pk, "view_access")
        serializer = AccessExecuteSerializer(data=request.data, context={"cluster": cluster})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        resource = data["resource_spec"]
        operation = data["operation_spec"]
        cluster = self._cluster(request, pk, self._permission_action(operation.permission))
        raw_request = getattr(request, "_request", request)
        raw_request.sensitive_post_parameters = "__ALL__"
        digest = ""
        targets = _audit_targets(resource, data["operation"], data.get("identifier", ""), data["payload"])
        try:
            backend, document = self._prepare_access_operation(cluster, operation, data["capability_digest"])
            digest = document.digest
            if operation.confirmation:
                impact = self._impact_state(
                    backend, resource, data["operation"], data.get("identifier", ""), data["payload"]
                )
                if _canonical_digest(impact) != data["impact_digest"]:
                    raise OpenBaoConflict("The access-control impact changed; preview it again.")
            log_administration(
                cluster,
                request.user,
                action="execute-access-resource-authorized",
                operation_id=f"access:{resource.key}:{data['operation']}",
                risk_level=operation.risk,
                method=operation.method,
                path_template=operation.path_template,
                reason=data["reason"],
                capability_digest=digest,
                target_identifiers=targets,
                outcome="authorized",
                success=True,
                message="Authorized a reviewed access-control operation.",
                request=request,
                require_durable=True,
            )
            result = backend.execute_access_operation(
                operation.method,
                resource.path(data["operation"], data.get("identifier", "")),
                payload=data["payload"],
                material=operation.response_kind == "material",
            )
            completion_targets = _completion_targets(targets, result)
        except OpenBaoMutationUnknown:
            return self._unknown_access_response()
        except (AdministrationAuditError, DatabaseError, OpenBaoError) as exc:
            self._backend_failure(
                request,
                cluster,
                "execute-access-resource",
                exc,
                reason=data["reason"],
                risk_level=operation.risk,
            )
        except Exception:
            self._backend_failure(
                request,
                cluster,
                "execute-access-resource",
                OpenBaoUnavailable("OpenBao access administration failed."),
                reason=data["reason"],
                risk_level=operation.risk,
            )
        audit_complete = True
        try:
            log_administration(
                cluster,
                request.user,
                action="execute-access-resource",
                operation_id=f"access:{resource.key}:{data['operation']}",
                risk_level=operation.risk,
                method=operation.method,
                path_template=operation.path_template,
                reason=data["reason"],
                capability_digest=digest,
                target_identifiers=completion_targets,
                success=True,
                status_code=200,
                message="Completed a reviewed access-control operation.",
                request=request,
            )
        except AdministrationAuditError:
            audit_complete = False
        response = self._mutation_response(result, status_code=200, audit_complete=audit_complete)
        return _no_store(response)
