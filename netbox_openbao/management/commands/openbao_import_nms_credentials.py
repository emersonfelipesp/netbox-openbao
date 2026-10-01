import json
from pathlib import Path

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, connection

from netbox_openbao.models import Credential, CredentialPolicy, ServiceEndpoint, SSHPublicKey
from netbox_openbao.services import (
    assign_credential,
    create_service_endpoint,
    create_ssh_public_key,
    store_credential,
)

# Namespaces the advisory lock key so it can never collide with an unrelated
# lock elsewhere in the plugin (e.g. `services.lock_custom_metadata_projection`
# uses the same `hashtextextended` mechanism under a different prefix).
_IMPORT_LOCK_PREFIX = 'netbox-openbao:import-source:'

SOURCE_MODELS = (
    ('netbox_nms', 'DeviceCredential'),
    ('netbox_network', 'DeviceService'),
    ('netbox_network', 'UserSSHKey'),
    ('netbox_nms', 'ProxmoxEndpointSSHBinding'),
    ('netbox_nms', 'CloudVMCredential'),
    ('netbox_nms', 'ObservabilitySecret'),
)
DEFAULT_PORTS = {'ssh': 22, 'telnet': 23, 'netconf': 830, 'restconf': 443, 'gnmi': 57400, 'snmp': 161, 'http': 80}
IMPORT_STARTED_RECORD = '{"version":1,"event":"openbao_import_started"}\n'


class Command(BaseCommand):
    help = 'Copy legacy NMS and network credentials into netbox-openbao without deleting source rows.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--id-map', type=Path)

    def handle(self, *args, **options):
        self.stdout.write(IMPORT_STARTED_RECORD, ending='')
        self.stdout.flush()
        del args
        id_map = {f'{app_label}.{model}': {} for app_label, model in SOURCE_MODELS}
        available = self._available_models()
        if options['dry_run']:
            self._report_dry_run(available)
        else:
            policy = CredentialPolicy.objects.select_related('engine').order_by('-engine__is_default', 'pk').first()
            if policy is None and available:
                raise CommandError('At least one CredentialPolicy is required before importing credentials.')
            self._import_all(available, policy, id_map)
        if options['id_map'] and not options['dry_run']:
            options['id_map'].write_text(json.dumps(id_map, indent=2, sort_keys=True) + '\n')
        self.stdout.write(json.dumps(id_map, sort_keys=True))

    def _available_models(self):
        available = {}
        for app_label, model_name in SOURCE_MODELS:
            key = f'{app_label}.{model_name}'
            if not apps.is_installed(app_label):
                self.stdout.write(self.style.WARNING(f'{app_label} is not installed; skipping {key}.'))
                continue
            model = apps.get_model(app_label, model_name)
            if model is None:
                self.stdout.write(self.style.WARNING(f'{key} is unavailable; skipping.'))
                continue
            available[key] = model
        return available

    def _report_dry_run(self, available):
        for key, model in available.items():
            self.stdout.write(f'{key}: would inspect {model.objects.count()} row(s)')

    def _import_all(self, available, policy, id_map):
        handlers = (
            ('netbox_nms.DeviceCredential', self._device_credential),
            ('netbox_network.DeviceService', self._device_service),
            ('netbox_network.UserSSHKey', self._user_ssh_key),
            ('netbox_nms.ProxmoxEndpointSSHBinding', self._proxmox_binding),
            ('netbox_nms.CloudVMCredential', self._cloud_vm_credential),
            ('netbox_nms.ObservabilitySecret', self._observability_secret),
        )
        for key, handler in handlers:
            model = available.get(key)
            if model is None:
                continue
            for source in model.objects.all().iterator():
                imported = handler(source, policy)
                if imported is not None:
                    id_map[key][str(source.pk)] = imported.pk

    @staticmethod
    def _existing_credential(import_source):
        return Credential.objects.filter(import_source=import_source).first()

    def _create_credential(self, source, policy, credential_type, payload, *, username='', name=None):
        import_source = f'{source._meta.app_label}.{source.__class__.__name__}:{source.pk}'
        existing = self._existing_credential(import_source)
        if existing is not None:
            return existing

        def persist(metadata):
            credential = Credential(
                name=name or str(source), credential_type=credential_type, policy=policy,
                username=username, import_source=import_source, **metadata,
            )
            credential.full_clean()
            credential.save()
            return credential

        self._acquire_import_lock(import_source)
        try:
            # Re-check under the lock: another process may have claimed and
            # committed this import_source between the unlocked check above
            # and here.
            existing = self._existing_credential(import_source)
            if existing is not None:
                return existing
            try:
                credential, _version = store_credential(persist, credential_type, payload, target_policy=policy)
            except IntegrityError:
                # `store_credential()` calls `persist()` — and therefore the
                # `import_source` unique constraint — before it ever writes to
                # the OpenBao backend (see services.store_credential), so a
                # constraint violation here means no OpenBao path was written
                # by this attempt. Re-read the row another process committed
                # rather than retrying the write.
                return Credential.objects.get(import_source=import_source)
            return credential
        finally:
            self._release_import_lock(import_source)

    @staticmethod
    def _advisory_lock_key(import_source):
        return f'{_IMPORT_LOCK_PREFIX}{import_source}'

    @classmethod
    def _acquire_import_lock(cls, import_source):
        """Session-scoped lock serializing concurrent claims of one source row.

        `pg_advisory_lock` rather than `pg_advisory_xact_lock`: the credential
        write happens inside `store_credential()`'s own
        `material_transactions.material_transaction()`, which owns a durable
        (outermost) atomic block and refuses to run nested inside a caller's
        `transaction.atomic()`. A session-scoped lock spans the whole
        check-then-create sequence, including that inner transaction, without
        wrapping it in one of our own; it is released explicitly in a
        `finally` block once the claim is settled.
        """
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_lock(hashtextextended(%s, 0))', [cls._advisory_lock_key(import_source)])

    @classmethod
    def _release_import_lock(cls, import_source):
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT pg_advisory_unlock(hashtextextended(%s, 0))', [cls._advisory_lock_key(import_source)],
            )

    def _device_credential(self, source, policy):
        if source.ssh_private_key_encrypted:
            payload = {'private_key': source.get_private_key()}
            if source.ssh_private_key_passphrase_encrypted:
                payload['passphrase'] = source.get_private_key_passphrase()
            credential_type = 'ssh_key'
        elif source.password_encrypted:
            payload = {'password': source.get_password()}
            credential_type = 'ssh_password'
        else:
            return None
        credential = self._create_credential(
            source, policy, credential_type, payload, username=source.username, name=source.name,
        )
        services = getattr(source, 'services', None)
        if services is not None:
            for service in services.all():
                target = service.assigned_object or service.device
                if target is not None:
                    self._ensure_assignment(credential, target)
        return credential

    def _device_service(self, source, policy):
        if source.service_type not in DEFAULT_PORTS:
            return None
        target = source.assigned_object or source.device
        if target is None:
            return None
        import_source = f'netbox_network.DeviceService:{source.pk}'
        existing = ServiceEndpoint.objects.filter(import_source=import_source).first()
        credential = self._service_snmp_credential(source, policy)
        if credential is None and source.credential_id:
            legacy_source = f'netbox_nms.DeviceCredential:{source.credential_id}'
            credential = Credential.objects.filter(import_source=legacy_source).first()
        # Reconcile every run, not only the first: a re-import must pick up a
        # credential (or target/host/port/ssh settings/options) that changed
        # or appeared after the endpoint was first created — most notably a
        # credential import that ran after this endpoint's first import left
        # `credential` null.
        fields = {
            'assigned_object': target, 'service_type': source.service_type,
            'host': source.get_management_address(), 'port': source.port or DEFAULT_PORTS[source.service_type],
            'ssh_known_hosts_entry': source.ssh_known_hosts_entry,
            'ssh_strict_host_key_checking': source.ssh_strict_host_key_checking,
            'options': self._service_options(source), 'credential': credential, 'import_source': import_source,
        }
        if existing is not None:
            fields['instance'] = existing
        return create_service_endpoint(**fields)

    def _service_snmp_credential(self, source, policy):
        if source.service_type != 'snmp':
            return None
        if source.snmp_version == 'v2c' and source.snmp_community_encrypted:
            return self._create_credential(
                source, policy, 'snmp_v2c', {'community': source.get_snmp_community()},
                name=f'{source} SNMP v2c',
            )
        if source.snmp_version == 'v3' and source.snmp_auth_password_encrypted:
            payload = {
                'username': source.snmp_user,
                'auth_password': source.get_snmp_auth_password(),
                'auth_protocol': source.snmp_auth_protocol,
                'priv_protocol': source.snmp_priv_protocol,
            }
            if source.snmp_priv_password_encrypted:
                payload['priv_password'] = source.get_snmp_priv_password()
            return self._create_credential(
                source, policy, 'snmp_v3', payload, username=source.snmp_user, name=f'{source} SNMP v3',
            )
        return None

    @staticmethod
    def _service_options(source):
        names = (
            'enabled', 'restconf_driver', 'restconf_base_path', 'restconf_verify_ssl',
            'netconf_driver', 'gnmi_encoding', 'gnmi_engine', 'snmp_version',
            'snmp_auth_protocol', 'snmp_priv_protocol', 'snmp_engine_order', 'telnet_policy_enabled',
        )
        return {name: getattr(source, name) for name in names if getattr(source, name, None) not in (None, '')}

    def _user_ssh_key(self, source, policy):
        del policy
        import_source = f'netbox_network.UserSSHKey:{source.pk}'
        existing = SSHPublicKey.objects.filter(import_source=import_source).first()
        if existing is not None:
            return existing
        endpoint = ServiceEndpoint.objects.filter(
            import_source=f'netbox_network.DeviceService:{source.device_service_id}',
        ).first()
        if endpoint is None:
            return None
        return create_ssh_public_key(
            user=source.netbox_user, service_endpoint=endpoint, public_key=source.public_key,
            installed_at=source.installed_at, import_source=import_source,
        )

    def _proxmox_binding(self, source, policy):
        del policy
        if not apps.is_installed('netbox_proxbox'):
            return None
        endpoint_model = apps.get_model('netbox_proxbox', 'ProxmoxEndpoint')
        target = endpoint_model.objects.filter(pk=source.proxmox_endpoint_id).first()
        if target is None:
            return None
        import_source = f'netbox_nms.ProxmoxEndpointSSHBinding:{source.pk}'
        existing = ServiceEndpoint.objects.filter(import_source=import_source).first()
        if existing is not None:
            return existing
        credential = Credential.objects.filter(
            import_source=f'netbox_nms.DeviceCredential:{source.credential_id}',
        ).first()
        return create_service_endpoint(
            assigned_object=target, service_type='ssh', host=source.ssh_host,
            port=source.ssh_port, ssh_known_hosts_entry=source.ssh_known_hosts_entry,
            ssh_strict_host_key_checking=source.ssh_strict_host_key_checking,
            options={'proxmox_endpoint_name': source.proxmox_endpoint_name},
            credential=credential, import_source=import_source,
        )

    def _cloud_vm_credential(self, source, policy):
        if not source.netbox_vm_id or not apps.is_installed('virtualization'):
            return None
        vm_model = apps.get_model('virtualization', 'VirtualMachine')
        vm = vm_model.objects.filter(pk=source.netbox_vm_id).first()
        if vm is None:
            return None
        payload = {}
        if source.cipassword_encrypted:
            payload['password'] = source.get_password()
        if source.ssh_private_key_encrypted:
            payload['private_key'] = source.get_private_key()
        if not payload:
            return None
        credential = self._create_credential(
            source, policy, 'cloud_init', payload, username=source.ciuser,
            name=f'{vm} cloud-init',
        )
        self._ensure_assignment(credential, vm)
        return credential

    def _observability_secret(self, source, policy):
        if not source.secret_encrypted:
            return None
        payload = {'value': source.get_secret(), 'purpose': source.purpose}
        if source.external_reference:
            payload['external_reference'] = source.external_reference
        return self._create_credential(
            source, policy, 'observability', payload, name=source.name,
        )

    @staticmethod
    def _ensure_assignment(credential, target):
        existing = credential.assignments.filter(
            assigned_object_type__app_label=target._meta.app_label,
            assigned_object_type__model=target._meta.model_name,
            assigned_object_id=target.pk,
            purpose='login',
        ).exists()
        if not existing:
            assign_credential(credential=credential, assigned_object=target, purpose='login')
