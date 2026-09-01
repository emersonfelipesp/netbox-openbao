"""Mirror OpenBao SSH credentials into netbox-nms for automation consumers."""

from __future__ import annotations

import logging

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import transaction

logger = logging.getLogger("netbox.plugins.netbox_openbao.nms_bridge")

SSH_SERVICE_TYPE = "ssh"


def nms_is_available() -> bool:
    return apps.is_installed("netbox_nms") and apps.is_installed("netbox_network")


def sync_ssh_password_to_nms(
    target,
    *,
    username: str,
    password: str,
    name: str | None = None,
    port: int = 22,
    user=None,
    request=None,
) -> tuple[object | None, object | None]:
    """Create or update a netbox-nms SSH DeviceService backed by OpenBao.

    Returns ``(DeviceCredential, DeviceService)`` when netbox-nms is installed,
    otherwise ``(None, None)``.
    """
    if not nms_is_available() or not password:
        return None, None

    from netbox_network.models import DeviceService
    from netbox_nms.models import DeviceCredential

    credential_name = name or f"{target} ssh"
    device = _device_for_target(target)
    if device is None:
        logger.info("Skipping netbox-nms SSH sync for %s: no dcim.Device parent", target)
        return None, None

    with transaction.atomic():
        credential = DeviceCredential.objects.filter(name=credential_name).first()
        if credential is None:
            credential = DeviceCredential(
                name=credential_name,
                username=username,
                auth_method=DeviceCredential.AUTH_METHOD_PASSWORD,
            )
        else:
            credential.username = username
            credential.auth_method = DeviceCredential.AUTH_METHOD_PASSWORD

        if user is not None:
            credential._openbao_write_user = user
        if request is not None:
            credential._openbao_write_request = request
        credential.set_password(password)
        credential.save()

        parent_type = ContentType.objects.get_for_model(device)
        service = (
            DeviceService.objects.filter(
                assigned_object_type=parent_type,
                assigned_object_id=device.pk,
                service_type=SSH_SERVICE_TYPE,
            )
            .select_related("credential")
            .first()
        )
        if service is None:
            service = DeviceService(
                device=device,
                assigned_object_type=parent_type,
                assigned_object_id=device.pk,
                service_type=SSH_SERVICE_TYPE,
                enabled=True,
                port=port,
                credential=credential,
                ssh_strict_host_key_checking=False,
            )
        else:
            service.device = device
            service.credential = credential
            service.port = port
            service.enabled = True
        service.full_clean()
        service.save()

    return credential, service


def _device_for_target(target):
    from dcim.models import Device
    from virtualization.models import VirtualMachine

    if isinstance(target, Device):
        return target
    if isinstance(target, VirtualMachine):
        return getattr(target, "device", None)
    service_model = apps.get_model("ipam", "Service")
    if isinstance(target, service_model):
        parent = target.parent
        if isinstance(parent, Device):
            return parent
        if isinstance(parent, VirtualMachine):
            return getattr(parent, "device", None)
    return None
