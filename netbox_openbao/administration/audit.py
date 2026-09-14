"""Synchronous metadata-only audit writes for the OpenBao administration plane."""

from django.db import transaction


class AdministrationAuditError(RuntimeError):
    """Raised when an administration access cannot be durably audited."""


def _text(value, maximum: int) -> str:
    return str(value or '')[:maximum]


def _request_context(request) -> dict:
    if request is None:
        return {'source_ip': None, 'request_id': ''}
    from utilities.request import get_client_ip

    try:
        client_ip = get_client_ip(request)
        source_ip = str(client_ip) if client_ip else None
    except Exception:
        source_ip = None
    return {
        'source_ip': source_ip,
        'request_id': str(getattr(request, 'id', '') or '')[:64],
    }


def log_administration(
    cluster,
    user,
    *,
    action: str,
    operation_id: str = '',
    risk_level: str = 'read',
    method: str = '',
    path_template: str = '',
    reason: str = '',
    capability_digest: str = '',
    success: bool = True,
    status_code: int | None = None,
    message: str = '',
    request=None,
):
    """Append one safe record and fail closed if the evidence cannot commit."""
    from netbox_openbao.models import OpenBaoAdministrationLog

    try:
        with transaction.atomic():
            return OpenBaoAdministrationLog.objects.create(
                cluster=cluster,
                cluster_name_snapshot=_text(cluster.name, 100),
                cluster_slug_snapshot=_text(cluster.slug, 100),
                user=user if (user is not None and getattr(user, 'is_authenticated', False)) else None,
                username_snapshot=_text(getattr(user, 'username', ''), 150),
                action=_text(action, 100),
                operation_id=_text(operation_id, 200),
                risk_level=_text(risk_level, 32),
                method=_text(method, 16),
                path_template=_text(path_template, 500),
                reason=_text(reason, 10_000),
                capability_digest=_text(capability_digest, 64),
                success=bool(success),
                status_code=status_code,
                message=_text(message, 500),
                **_request_context(request),
            )
    except Exception:
        raise AdministrationAuditError('OpenBao administration access could not be audited.') from None
