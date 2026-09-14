"""Bound and normalize runtime OpenBao OpenAPI documents before displaying them."""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

MAX_DOCUMENT_BYTES = 2_000_000
MAX_DOCUMENT_DEPTH = 30
MAX_PATHS = 2_000
MAX_OPERATIONS = 5_000
MAX_STRING_LENGTH = 20_000
ALLOWED_METHODS = frozenset({'delete', 'get', 'list', 'patch', 'post', 'put'})

_PATH_RE = re.compile(r'^/[A-Za-z0-9_.*{}~:/+^$-]*$')
_OPERATION_ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,199}$')
_OPENAPI_VERSION_RE = re.compile(r'^3\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$')


class CapabilitySchemaError(ValueError):
    """A fixed safe error for malformed or unsafe capability documents."""


@dataclass(frozen=True, slots=True)
class DiscoveredOperation:
    """A normalized operation. Discovery never makes an operation executable."""

    operation_id: str
    method: str
    path_template: str
    summary: str
    tags: tuple[str, ...]
    family: str
    risk_level: str
    response_class: str
    required_permission: str
    classified: bool
    executable: bool = False

    @property
    def operation_key(self) -> str:
        """Stable unique identity; OpenBao may reuse an upstream operation ID."""
        return f'{self.method} {self.path_template}'

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result['operation_key'] = self.operation_key
        return result


@dataclass(frozen=True, slots=True)
class CapabilityDocument:
    """Stable metadata derived from an OpenAPI document."""

    openapi_version: str
    product_version: str
    digest: str
    operations: tuple[DiscoveredOperation, ...]

    @property
    def classified_count(self) -> int:
        return sum(operation.classified for operation in self.operations)

    @property
    def unclassified_count(self) -> int:
        return len(self.operations) - self.classified_count

    def as_dict(self) -> dict[str, Any]:
        return {
            'openapi_version': self.openapi_version,
            'product_version': self.product_version,
            'digest': self.digest,
            'classified_count': self.classified_count,
            'unclassified_count': self.unclassified_count,
            'operations': [operation.as_dict() for operation in self.operations],
        }


def _safe_string(value: Any, field: str, *, maximum: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(ord(character) < 32 for character in value):
        raise CapabilitySchemaError(f'OpenBao capability document has an invalid {field}.')
    return value


def _validate_mapping(value: dict, depth: int) -> None:
    if len(value) > MAX_OPERATIONS:
        raise CapabilitySchemaError('OpenBao capability document contains too many fields.')
    for key, child in value.items():
        _safe_string(key, 'object key', maximum=500)
        _validate_shape(child, depth=depth + 1)


def _validate_list(value: list, depth: int) -> None:
    if len(value) > MAX_OPERATIONS:
        raise CapabilitySchemaError('OpenBao capability document contains too many list items.')
    for child in value:
        _validate_shape(child, depth=depth + 1)


def _validate_scalar(value: Any) -> None:
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH or '\x00' in value:
            raise CapabilitySchemaError('OpenBao capability document has an invalid string.')
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise CapabilitySchemaError('OpenBao capability document contains an unsupported value.')
    if value is not None and not isinstance(value, (bool, int, float)):
        raise CapabilitySchemaError('OpenBao capability document contains an unsupported value.')


def _validate_shape(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DOCUMENT_DEPTH:
        raise CapabilitySchemaError('OpenBao capability document is nested too deeply.')
    if isinstance(value, dict):
        _validate_mapping(value, depth)
        return
    if isinstance(value, list):
        _validate_list(value, depth)
        return
    _validate_scalar(value)


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    try:
        encoded = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    except (TypeError, ValueError, RecursionError):
        raise CapabilitySchemaError('OpenBao capability document is not valid JSON data.') from None
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise CapabilitySchemaError('OpenBao capability document is too large.')
    return encoded


def _normalize_path(path: Any) -> str:
    path = _safe_string(path, 'path template', maximum=500)
    if path.startswith('/v1/'):
        path = path[3:]
    if (
        not _PATH_RE.fullmatch(path)
        or '//' in path
        or '\\' in path
        or '/./' in f'{path}/'
        or '/../' in f'{path}/'
        or path.startswith('//')
    ):
        raise CapabilitySchemaError('OpenBao capability document contains an unsafe path template.')
    return path


def _family_for(path: str, tags: tuple[str, ...]) -> str:
    lowered_tags = {tag.lower() for tag in tags}
    rules = (
        ('cluster', ('/sys/health', '/sys/init', '/sys/seal', '/sys/unseal', '/sys/leader', '/sys/ha-status')),
        ('storage', ('/sys/storage/raft',)),
        ('authentication', ('/sys/auth', '/auth')),
        ('mfa', ('/identity/mfa', '/sys/mfa')),
        ('policies', ('/sys/policies', '/sys/policy')),
        ('identity', ('/identity/entity', '/identity/group')),
        ('oidc', ('/identity/oidc',)),
        ('namespaces', ('/sys/namespaces',)),
        ('leases', ('/sys/leases',)),
        ('tools', ('/sys/wrapping', '/sys/tools')),
        ('ui-configuration', ('/sys/config/ui',)),
        ('api-explorer', ('/sys/internal/specs/openapi',)),
        ('secret-engine-lifecycle', ('/sys/mounts', '/sys/remount')),
    )
    for family, prefixes in rules:
        if any(path == prefix or path.startswith(f'{prefix}/') for prefix in prefixes):
            return family
    if 'secrets' in lowered_tags or 'secret' in lowered_tags:
        return 'mounted-secrets'
    return 'unclassified'


def _risk_for(method: str, path: str) -> str:
    destructive_tokens = ('destroy', 'force-revoke', 'revoke-force', 'restore', '/seal', 'remove-peer')
    if method == 'delete' or any(token in path for token in destructive_tokens):
        return 'destructive'
    if method in {'get', 'list'}:
        return 'read'
    return 'write'


def _permission_for(risk_level: str) -> str:
    if risk_level == 'destructive':
        return 'netbox_openbao.operate_destructive_openbaocluster'
    if risk_level == 'write':
        return 'netbox_openbao.operate_openbaocluster'
    return 'netbox_openbao.discover_openbaocluster'


def _document_metadata(document: dict[str, Any]) -> tuple[str, str, dict]:
    openapi_version = _safe_string(document.get('openapi', ''), 'OpenAPI version', maximum=32)
    if not _OPENAPI_VERSION_RE.fullmatch(openapi_version):
        raise CapabilitySchemaError('OpenBao capability document uses an unsupported OpenAPI version.')
    info = document.get('info') or {}
    if not isinstance(info, dict):
        raise CapabilitySchemaError('OpenBao capability document has invalid product metadata.')
    product_version = _safe_string(info.get('version', ''), 'product version', maximum=64)
    paths = document.get('paths')
    if not isinstance(paths, dict):
        raise CapabilitySchemaError('OpenBao capability document has no paths object.')
    if len(paths) > MAX_PATHS:
        raise CapabilitySchemaError('OpenBao capability document contains too many paths.')
    return openapi_version, product_version, paths


def _operation_tags(operation: dict[str, Any]) -> tuple[str, ...]:
    raw_tags = operation.get('tags') or []
    if not isinstance(raw_tags, list) or len(raw_tags) > 20:
        raise CapabilitySchemaError('OpenBao capability operation has invalid tags.')
    return tuple(sorted({_safe_string(tag, 'operation tag', maximum=100) for tag in raw_tags}))


def _normalize_operation(
    path: str,
    method: str,
    operation: Any,
) -> DiscoveredOperation:
    if not isinstance(operation, dict):
        raise CapabilitySchemaError('OpenBao capability operation must be an object.')
    operation_id = _safe_string(operation.get('operationId', ''), 'operation ID', maximum=200)
    if not _OPERATION_ID_RE.fullmatch(operation_id):
        raise CapabilitySchemaError('OpenBao capability document has an invalid operation ID.')
    tags = _operation_tags(operation)
    family = _family_for(path, tags)
    risk_level = _risk_for(method, path)
    classified = family != 'unclassified'
    return DiscoveredOperation(
        operation_id=operation_id,
        method=method.upper(),
        path_template=path,
        summary=_safe_string(operation.get('summary', ''), 'operation summary', maximum=500),
        tags=tags,
        family=family,
        risk_level=risk_level,
        response_class='public-metadata' if family in {'cluster', 'api-explorer'} else 'unreviewed',
        required_permission=_permission_for(risk_level) if classified else '',
        classified=classified,
    )


def normalize_openapi_document(document: Any) -> CapabilityDocument:
    """Return a bounded, display-safe capability document; never an executable registry."""
    if not isinstance(document, dict):
        raise CapabilitySchemaError('OpenBao capability document must be an object.')
    canonical = _canonical_bytes(document)
    _validate_shape(document)
    openapi_version, product_version, paths = _document_metadata(document)

    operations: list[DiscoveredOperation] = []
    for raw_path, path_item in paths.items():
        path = _normalize_path(raw_path)
        if not isinstance(path_item, dict):
            raise CapabilitySchemaError('OpenBao capability path entry must be an object.')
        for raw_method, operation in path_item.items():
            method = str(raw_method).lower()
            if method not in ALLOWED_METHODS:
                continue
            operations.append(_normalize_operation(path, method, operation))
            if len(operations) > MAX_OPERATIONS:
                raise CapabilitySchemaError('OpenBao capability document contains too many operations.')

    operations.sort(key=lambda item: (item.family, item.path_template, item.method, item.operation_id))
    return CapabilityDocument(
        openapi_version=openapi_version,
        product_version=product_version,
        digest=sha256(canonical).hexdigest(),
        operations=tuple(operations),
    )
