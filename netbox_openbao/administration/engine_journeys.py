"""Static first-class journeys layered over runtime-advertised mounted operations."""

from dataclasses import asdict, dataclass
from typing import Final

from .engines import (
    ExplorerOperation,
    SecretEngineMount,
    classify_explorer_operations,
    mount_parameter_for_path,
)
from .schema import CapabilityDocument, CapabilitySchemaError


@dataclass(frozen=True, slots=True)
class EngineJourney:
    """One reviewed task-oriented use of an exact OpenBao mounted operation."""

    journey_id: str
    engine_type: str
    group: str
    label: str
    method: str
    path_template: str
    operation_id: str
    required_permission: str
    risk_level: str = "read"
    response_class: str = "sensitive-material"
    confirmation_prefix: str = ""
    kv_versions: tuple[int, ...] = ()
    fixed_query: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return asdict(self)


def _journey(
    journey_id: str,
    engine_type: str,
    group: str,
    label: str,
    method: str,
    path_template: str,
    operation_id: str,
    permission: str,
    *,
    risk: str = "read",
    confirmation: str = "",
    kv_versions: tuple[int, ...] = (),
    fixed_query: tuple[tuple[str, str], ...] = (),
) -> EngineJourney:
    return EngineJourney(
        journey_id=journey_id,
        engine_type=engine_type,
        group=group,
        label=label,
        method=method,
        path_template=path_template,
        operation_id=operation_id,
        required_permission=f"netbox_openbao.{permission}_openbaocluster",
        risk_level=risk,
        confirmation_prefix=confirmation,
        kv_versions=kv_versions,
        fixed_query=fixed_query,
    )


KV: Final = (
    _journey(
        "kv1.browse",
        "kv",
        "KV v1",
        "Browse keys",
        "GET",
        "/{secret_mount_path}/{path}",
        "kv-read-path",
        "reveal_kv_secrets",
        kv_versions=(1,),
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "kv1.read",
        "kv",
        "KV v1",
        "Read secret",
        "GET",
        "/{secret_mount_path}/{path}",
        "kv-read-path",
        "reveal_kv_secrets",
        kv_versions=(1,),
    ),
    _journey(
        "kv1.write",
        "kv",
        "KV v1",
        "Create or update secret",
        "POST",
        "/{secret_mount_path}/{path}",
        "kv-write-path",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(1,),
    ),
    _journey(
        "kv1.delete",
        "kv",
        "KV v1",
        "Delete secret",
        "DELETE",
        "/{secret_mount_path}/{path}",
        "kv-delete-path",
        "destroy_kv_versions",
        risk="destructive",
        confirmation="DELETE KV SECRET",
        kv_versions=(1,),
    ),
    _journey(
        "kv2.browse",
        "kv",
        "KV v2",
        "Browse keys",
        "GET",
        "/{secret_mount_path}/metadata/{path}",
        "kv-read-metadata-path",
        "reveal_kv_secrets",
        kv_versions=(2,),
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "kv2.read",
        "kv",
        "KV v2",
        "Read secret version",
        "GET",
        "/{secret_mount_path}/data/{path}",
        "kv-read-data-path",
        "reveal_kv_secrets",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.diff",
        "kv",
        "KV v2",
        "Compare two versions",
        "GET",
        "/{secret_mount_path}/data/{path}",
        "kv-read-data-path",
        "reveal_kv_secrets",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.write",
        "kv",
        "KV v2",
        "Create or update with CAS",
        "POST",
        "/{secret_mount_path}/data/{path}",
        "kv-write-data-path",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.patch",
        "kv",
        "KV v2",
        "Patch with CAS",
        "PATCH",
        "/{secret_mount_path}/data/{path}",
        "kv-patch-data-path",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.delete-latest",
        "kv",
        "KV v2",
        "Delete latest version",
        "DELETE",
        "/{secret_mount_path}/data/{path}",
        "kv-delete-data-path",
        "destroy_kv_versions",
        risk="destructive",
        confirmation="DELETE LATEST KV VERSION",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.delete-versions",
        "kv",
        "KV v2",
        "Delete versions",
        "POST",
        "/{secret_mount_path}/delete/{path}",
        "kv-write-delete-path",
        "destroy_kv_versions",
        risk="destructive",
        confirmation="DELETE KV VERSIONS",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.undelete",
        "kv",
        "KV v2",
        "Undelete versions",
        "POST",
        "/{secret_mount_path}/undelete/{path}",
        "kv-write-undelete-path",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.destroy",
        "kv",
        "KV v2",
        "Destroy versions irreversibly",
        "POST",
        "/{secret_mount_path}/destroy/{path}",
        "kv-write-destroy-path",
        "destroy_kv_versions",
        risk="destructive",
        confirmation="DESTROY KV VERSIONS",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.metadata",
        "kv",
        "KV v2",
        "Read metadata and versions",
        "GET",
        "/{secret_mount_path}/metadata/{path}",
        "kv-read-metadata-path",
        "reveal_kv_secrets",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.metadata-write",
        "kv",
        "KV v2",
        "Update metadata",
        "POST",
        "/{secret_mount_path}/metadata/{path}",
        "kv-write-metadata-path",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.metadata-delete",
        "kv",
        "KV v2",
        "Delete metadata and all versions",
        "DELETE",
        "/{secret_mount_path}/metadata/{path}",
        "kv-delete-metadata-path",
        "destroy_kv_versions",
        risk="destructive",
        confirmation="DESTROY KV METADATA",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.config-read",
        "kv",
        "KV v2",
        "Read mount configuration",
        "GET",
        "/{secret_mount_path}/config",
        "kv-read-config",
        "reveal_kv_secrets",
        kv_versions=(2,),
    ),
    _journey(
        "kv2.config-write",
        "kv",
        "KV v2",
        "Configure mount",
        "POST",
        "/{secret_mount_path}/config",
        "kv-write-config",
        "manage_kv_secrets",
        risk="write",
        kv_versions=(2,),
    ),
)

TRANSIT: Final = (
    _journey(
        "transit.keys",
        "transit",
        "Transit keys",
        "List keys",
        "GET",
        "/{secret_mount_path}/keys",
        "transit-list-keys",
        "use_transit",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "transit.key-read",
        "transit",
        "Transit keys",
        "Read key metadata",
        "GET",
        "/{secret_mount_path}/keys/{name}",
        "transit-read-key",
        "use_transit",
    ),
    _journey(
        "transit.key-create",
        "transit",
        "Transit keys",
        "Create key",
        "POST",
        "/{secret_mount_path}/keys/{name}",
        "transit-create-key",
        "manage_transit_keys",
        risk="write",
    ),
    _journey(
        "transit.key-configure",
        "transit",
        "Transit keys",
        "Configure key",
        "POST",
        "/{secret_mount_path}/keys/{name}/config",
        "transit-configure-key",
        "manage_transit_keys",
        risk="write",
    ),
    _journey(
        "transit.key-rotate",
        "transit",
        "Transit keys",
        "Rotate key",
        "POST",
        "/{secret_mount_path}/keys/{name}/rotate",
        "transit-rotate-key",
        "manage_transit_keys",
        risk="write",
    ),
    _journey(
        "transit.key-delete",
        "transit",
        "Transit keys",
        "Delete key",
        "DELETE",
        "/{secret_mount_path}/keys/{name}",
        "transit-delete-key",
        "delete_transit_keys",
        risk="destructive",
        confirmation="DELETE TRANSIT KEY",
    ),
    _journey(
        "transit.encrypt",
        "transit",
        "Transit operations",
        "Encrypt",
        "POST",
        "/{secret_mount_path}/encrypt/{name}",
        "transit-encrypt",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.decrypt",
        "transit",
        "Transit operations",
        "Decrypt",
        "POST",
        "/{secret_mount_path}/decrypt/{name}",
        "transit-decrypt",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.rewrap",
        "transit",
        "Transit operations",
        "Rewrap",
        "POST",
        "/{secret_mount_path}/rewrap/{name}",
        "transit-rewrap",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.sign",
        "transit",
        "Transit operations",
        "Sign",
        "POST",
        "/{secret_mount_path}/sign/{name}",
        "transit-sign",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.verify",
        "transit",
        "Transit operations",
        "Verify signature",
        "POST",
        "/{secret_mount_path}/verify/{name}",
        "transit-verify",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.hash",
        "transit",
        "Transit operations",
        "Hash",
        "POST",
        "/{secret_mount_path}/hash",
        "transit-hash",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.hmac",
        "transit",
        "Transit operations",
        "Generate HMAC",
        "POST",
        "/{secret_mount_path}/hmac/{name}",
        "transit-generate-hmac",
        "use_transit",
        risk="write",
    ),
    _journey(
        "transit.random",
        "transit",
        "Transit operations",
        "Generate random bytes",
        "POST",
        "/{secret_mount_path}/random",
        "transit-generate-random",
        "use_transit",
        risk="write",
    ),
)

DATABASE: Final = (
    _journey(
        "database.connections",
        "database",
        "Database connections",
        "List connections",
        "GET",
        "/{secret_mount_path}/config",
        "database-list-connections",
        "manage_database_roles",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "database.connection-read",
        "database",
        "Database connections",
        "Read connection",
        "GET",
        "/{secret_mount_path}/config/{name}",
        "database-read-connection-configuration",
        "manage_database_roles",
    ),
    _journey(
        "database.connection-write",
        "database",
        "Database connections",
        "Configure connection",
        "POST",
        "/{secret_mount_path}/config/{name}",
        "database-configure-connection",
        "manage_database_roles",
        risk="write",
    ),
    _journey(
        "database.connection-delete",
        "database",
        "Database connections",
        "Delete connection",
        "DELETE",
        "/{secret_mount_path}/config/{name}",
        "database-delete-connection-configuration",
        "delete_database_resources",
        risk="destructive",
        confirmation="DELETE DATABASE CONNECTION",
    ),
    _journey(
        "database.roles",
        "database",
        "Database roles",
        "List dynamic roles",
        "GET",
        "/{secret_mount_path}/roles",
        "database-list-roles",
        "manage_database_roles",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "database.role-read",
        "database",
        "Database roles",
        "Read dynamic role",
        "GET",
        "/{secret_mount_path}/roles/{name}",
        "database-read-role",
        "manage_database_roles",
    ),
    _journey(
        "database.role-write",
        "database",
        "Database roles",
        "Configure dynamic role",
        "POST",
        "/{secret_mount_path}/roles/{name}",
        "database-write-role",
        "manage_database_roles",
        risk="write",
    ),
    _journey(
        "database.role-delete",
        "database",
        "Database roles",
        "Delete dynamic role",
        "DELETE",
        "/{secret_mount_path}/roles/{name}",
        "database-delete-role",
        "delete_database_resources",
        risk="destructive",
        confirmation="DELETE DATABASE ROLE",
    ),
    _journey(
        "database.static-roles",
        "database",
        "Database static roles",
        "List static roles",
        "GET",
        "/{secret_mount_path}/static-roles",
        "database-list-static-roles",
        "manage_database_roles",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "database.static-role-read",
        "database",
        "Database static roles",
        "Read static role",
        "GET",
        "/{secret_mount_path}/static-roles/{name}",
        "database-read-static-role",
        "manage_database_roles",
    ),
    _journey(
        "database.static-role-write",
        "database",
        "Database static roles",
        "Configure static role",
        "POST",
        "/{secret_mount_path}/static-roles/{name}",
        "database-write-static-role",
        "manage_database_roles",
        risk="write",
    ),
    _journey(
        "database.static-role-delete",
        "database",
        "Database static roles",
        "Delete static role",
        "DELETE",
        "/{secret_mount_path}/static-roles/{name}",
        "database-delete-static-role",
        "delete_database_resources",
        risk="destructive",
        confirmation="DELETE DATABASE STATIC ROLE",
    ),
    _journey(
        "database.credentials",
        "database",
        "Database credentials",
        "Generate dynamic credentials",
        "GET",
        "/{secret_mount_path}/creds/{name}",
        "database-generate-credentials",
        "generate_database_credentials",
    ),
    _journey(
        "database.static-credentials",
        "database",
        "Database credentials",
        "Read static credentials",
        "GET",
        "/{secret_mount_path}/static-creds/{name}",
        "database-read-static-role-credentials",
        "generate_database_credentials",
    ),
    _journey(
        "database.rotate-root",
        "database",
        "Database rotation",
        "Rotate root credentials",
        "POST",
        "/{secret_mount_path}/rotate-root/{name}",
        "database-rotate-root-credentials",
        "rotate_database_credentials",
        risk="destructive",
        confirmation="ROTATE DATABASE ROOT CREDENTIALS",
    ),
    _journey(
        "database.rotate-static",
        "database",
        "Database rotation",
        "Rotate static-role credentials",
        "POST",
        "/{secret_mount_path}/rotate-role/{name}",
        "database-rotate-static-role-credentials",
        "rotate_database_credentials",
        risk="destructive",
        confirmation="ROTATE DATABASE STATIC CREDENTIALS",
    ),
    _journey(
        "database.reset",
        "database",
        "Database rotation",
        "Reset connection",
        "POST",
        "/{secret_mount_path}/reset/{name}",
        "database-reset-connection",
        "rotate_database_credentials",
        risk="destructive",
        confirmation="RESET DATABASE CONNECTION",
    ),
)

SSH: Final = (
    _journey(
        "ssh.roles",
        "ssh",
        "SSH roles",
        "List roles",
        "GET",
        "/{secret_mount_path}/roles",
        "ssh-list-roles",
        "manage_ssh_roles",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "ssh.role-read",
        "ssh",
        "SSH roles",
        "Read role",
        "GET",
        "/{secret_mount_path}/roles/{role}",
        "ssh-read-role",
        "manage_ssh_roles",
    ),
    _journey(
        "ssh.role-write",
        "ssh",
        "SSH roles",
        "Configure role",
        "POST",
        "/{secret_mount_path}/roles/{role}",
        "ssh-write-role",
        "manage_ssh_roles",
        risk="write",
    ),
    _journey(
        "ssh.role-delete",
        "ssh",
        "SSH roles",
        "Delete role",
        "DELETE",
        "/{secret_mount_path}/roles/{role}",
        "ssh-delete-role",
        "delete_ssh_roles",
        risk="destructive",
        confirmation="DELETE SSH ROLE",
    ),
    _journey(
        "ssh.credentials",
        "ssh",
        "SSH credentials",
        "Generate credentials",
        "POST",
        "/{secret_mount_path}/creds/{role}",
        "ssh-generate-credentials",
        "issue_ssh_credentials",
        risk="write",
    ),
    _journey(
        "ssh.sign",
        "ssh",
        "SSH credentials",
        "Sign public key",
        "POST",
        "/{secret_mount_path}/sign/{role}",
        "ssh-sign-certificate",
        "issue_ssh_credentials",
        risk="write",
    ),
    _journey(
        "ssh.lookup",
        "ssh",
        "SSH credentials",
        "Find roles for IP",
        "POST",
        "/{secret_mount_path}/lookup",
        "ssh-list-roles-by-ip",
        "issue_ssh_credentials",
        risk="write",
    ),
    _journey(
        "ssh.public-key",
        "ssh",
        "SSH credentials",
        "Read CA public key",
        "GET",
        "/{secret_mount_path}/public_key",
        "ssh-read-public-key",
        "issue_ssh_credentials",
    ),
    _journey(
        "ssh.verify-otp",
        "ssh",
        "SSH credentials",
        "Verify OTP",
        "POST",
        "/{secret_mount_path}/verify",
        "ssh-verify-otp",
        "issue_ssh_credentials",
        risk="write",
    ),
)

TOTP: Final = (
    _journey(
        "totp.keys",
        "totp",
        "TOTP keys",
        "List keys",
        "GET",
        "/{secret_mount_path}/keys",
        "totp-list-keys",
        "manage_totp_keys",
        fixed_query=(("list", "true"),),
    ),
    _journey(
        "totp.key-read",
        "totp",
        "TOTP keys",
        "Read key metadata",
        "GET",
        "/{secret_mount_path}/keys/{name}",
        "totp-read-key",
        "manage_totp_keys",
    ),
    _journey(
        "totp.key-create",
        "totp",
        "TOTP keys",
        "Create or import key",
        "POST",
        "/{secret_mount_path}/keys/{name}",
        "totp-create-key",
        "manage_totp_keys",
        risk="write",
    ),
    _journey(
        "totp.key-delete",
        "totp",
        "TOTP keys",
        "Delete key",
        "DELETE",
        "/{secret_mount_path}/keys/{name}",
        "totp-delete-key",
        "delete_totp_keys",
        risk="destructive",
        confirmation="DELETE TOTP KEY",
    ),
    _journey(
        "totp.code",
        "totp",
        "TOTP codes",
        "Generate code",
        "GET",
        "/{secret_mount_path}/code/{name}",
        "totp-generate-code",
        "generate_totp_codes",
    ),
    _journey(
        "totp.validate",
        "totp",
        "TOTP codes",
        "Validate code",
        "POST",
        "/{secret_mount_path}/code/{name}",
        "totp-validate-code",
        "generate_totp_codes",
        risk="write",
    ),
)

ENGINE_JOURNEYS: Final = (*KV, *TRANSIT, *DATABASE, *SSH, *TOTP)
ENGINE_JOURNEY_BY_ID: Final = {journey.journey_id: journey for journey in ENGINE_JOURNEYS}

if len(ENGINE_JOURNEY_BY_ID) != len(ENGINE_JOURNEYS):  # pragma: no cover - import-time invariant
    raise RuntimeError("The engine journey registry contains duplicate identifiers.")


def _mount_supports(mount: SecretEngineMount, journey: EngineJourney) -> bool:
    return mount.engine_type == journey.engine_type and (
        not journey.kv_versions or mount.kv_version in journey.kv_versions
    )


def _operation_for(
    operation_index: dict[tuple[str, str, str, str], ExplorerOperation],
    mount: SecretEngineMount,
    journey: EngineJourney,
) -> ExplorerOperation | None:
    return operation_index.get(
        (
            mount_parameter_for_path(mount.path),
            journey.operation_id,
            journey.method,
            journey.path_template,
        )
    )


def _operation_index(document: CapabilityDocument) -> dict[tuple[str, str, str, str], ExplorerOperation]:
    return {
        (operation.mount_parameter, operation.operation_id, operation.method, operation.path_template): operation
        for operation in classify_explorer_operations(document)
        if operation.executable
    }


def _ambiguous_mount_parameters(mounts: tuple[SecretEngineMount, ...]) -> set[str]:
    counts: dict[str, int] = {}
    for mount in mounts:
        parameter = mount_parameter_for_path(mount.path)
        counts[parameter] = counts.get(parameter, 0) + 1
    return {parameter for parameter, count in counts.items() if count > 1}


def engine_journey_catalog(
    document: CapabilityDocument,
    mounts: tuple[SecretEngineMount, ...],
) -> tuple[dict, ...]:
    """Return only static journeys proven by the current mount-specific schema."""
    result = []
    ambiguous = _ambiguous_mount_parameters(mounts)
    operation_index = _operation_index(document)
    for mount in mounts:
        if mount_parameter_for_path(mount.path) in ambiguous:
            continue
        for journey in ENGINE_JOURNEYS:
            if not _mount_supports(mount, journey):
                continue
            operation = _operation_for(operation_index, mount, journey)
            if operation is None:
                continue
            item = journey.as_dict()
            item.update(
                {
                    "mount_path": mount.path,
                    "operation_key": operation.operation_key,
                    "query_parameters": operation.query_parameters,
                    "required_query_parameters": operation.required_query_parameters,
                    "query_parameter_types": operation.query_parameter_types,
                    "path_parameters": operation.path_parameters,
                    "required_path_parameters": operation.required_path_parameters,
                    "path_parameter_types": operation.path_parameter_types,
                    "body_fields": operation.body_fields,
                    "required_body_fields": operation.required_body_fields,
                    "body_field_types": operation.body_field_types,
                }
            )
            result.append(item)
    return tuple(
        sorted(result, key=lambda item: (item["engine_type"], item["group"], item["label"], item["mount_path"]))
    )


def resolve_engine_journey(
    document: CapabilityDocument,
    mounts: tuple[SecretEngineMount, ...],
    mount_path: str,
    journey_id: str,
) -> tuple[EngineJourney, ExplorerOperation]:
    journey = ENGINE_JOURNEY_BY_ID.get(journey_id)
    mount = next((item for item in mounts if item.path == mount_path), None)
    ambiguous = _ambiguous_mount_parameters(mounts)
    if (
        journey is None
        or mount is None
        or mount_parameter_for_path(mount.path) in ambiguous
        or not _mount_supports(mount, journey)
    ):
        raise CapabilitySchemaError("The selected first-class engine journey is unavailable.")
    operation = _operation_for(_operation_index(document), mount, journey)
    if operation is None:
        raise CapabilitySchemaError("OpenBao does not advertise the reviewed first-class engine journey.")
    return journey, operation
