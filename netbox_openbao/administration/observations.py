"""Transactional observed-state and audit persistence for administration reads."""

from django.db import transaction
from django.utils import timezone

from .audit import log_administration


def record_health_observation(cluster, user, result: dict, request=None):
    """Persist bounded health metadata and its success audit atomically."""
    checked = timezone.now()
    with transaction.atomic():
        cluster.__class__.objects.filter(pk=cluster.pk).update(
            status=result['status'],
            status_message=result['message'][:500],
            last_checked=checked,
        )
        log_administration(
            cluster,
            user,
            action='health',
            operation_id='sys-health',
            risk_level='read',
            method='GET',
            path_template='/sys/health',
            success=True,
            status_code=200,
            message='Read cluster health.',
            request=request,
        )
    return checked


def record_capability_observation(cluster, user, document, request=None):
    """Persist capability metadata and its success audit atomically."""
    checked = timezone.now()
    with transaction.atomic():
        cluster.__class__.objects.filter(pk=cluster.pk).update(
            openbao_version=document.product_version,
            capability_digest=document.digest,
            capabilities_checked=checked,
        )
        log_administration(
            cluster,
            user,
            action='discover-capabilities',
            operation_id='sys-internal-specs-openapi',
            risk_level='read',
            method='GET',
            path_template='/sys/internal/specs/openapi',
            capability_digest=document.digest,
            success=True,
            status_code=200,
            message='Discovered cluster capabilities.',
            request=request,
        )
    return checked
