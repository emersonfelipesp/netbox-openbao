"""Drop `ServiceEndpoint` and reuse the built-in Application Service instead.

The single migration of this release over the 0.2.0 boundary:

* `CredentialAssignment` gains the SSH host-key pin (`ssh_known_hosts_entry`,
  `ssh_strict_host_key_checking`) that used to live on the endpoint.
* `SSHPublicKey` is re-keyed from the endpoint to the Application Service
  (`ipam.Service`) the endpoint was attached to.
* Host-key pins of endpoints attached to a service are copied onto the matching
  credential assignment; SSH keys of endpoints attached to a service move to
  that service. An endpoint that bound a credential without an assignment gets
  the assignment created. Identical keys of one user on one service collapse;
  different keys stop the migration with the rows to reconcile. Rows that
  cannot be mapped (an endpoint attached directly to a device or virtual
  machine has no Application Service) are not carried over; endpoints never
  held secret material, only connection metadata.
* The `ServiceEndpoint` table is deleted.

Reversing recreates the empty `ServiceEndpoint` table and removes the new
columns. Endpoint rows and SSH keys cannot be reconstructed, so a reverse run
clears the SSH key inventory first; restore the pre-upgrade database backup to
get the old data back.
"""

import django.db.models.deletion
from django.db import migrations, models


def carry_over_endpoint_data(apps, schema_editor):
    ServiceEndpoint = apps.get_model('netbox_openbao', 'ServiceEndpoint')
    CredentialAssignment = apps.get_model('netbox_openbao', 'CredentialAssignment')
    SSHPublicKey = apps.get_model('netbox_openbao', 'SSHPublicKey')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    Service = apps.get_model('ipam', 'Service')

    service_type = ContentType.objects.filter(app_label='ipam', model='service').first()
    if service_type is None:
        SSHPublicKey.objects.all().delete()
        return

    # Endpoints that share a service and credential (different ports) collapse
    # onto one assignment. Differing host-key settings cannot be merged without
    # losing the stricter one, so stop and name the rows.
    # Endpoints attach through a generic relation, so one can outlive its
    # service. Those have no Application Service to move to and are unmappable.
    live_endpoints = ServiceEndpoint.objects.filter(
        assigned_object_type=service_type,
        assigned_object_id__in=Service.objects.values('pk'),
    )
    pins = {}
    conflicts = []
    for endpoint in live_endpoints.filter(credential__isnull=False).order_by('pk'):
        if not (endpoint.ssh_known_hosts_entry or endpoint.service_type == 'ssh'):
            continue
        slot = (endpoint.credential_id, endpoint.assigned_object_id)
        setting = (endpoint.ssh_known_hosts_entry, endpoint.ssh_strict_host_key_checking)
        first = pins.setdefault(slot, (endpoint.pk, setting))
        if first[1] != setting:
            conflicts.append(f'endpoints {first[0]} and {endpoint.pk} disagree on the host-key settings')
    if conflicts:
        raise RuntimeError(
            'Cannot merge SSH host-key settings onto one credential assignment; reconcile these endpoints first: '
            + '; '.join(conflicts)
        )

    for endpoint in live_endpoints:
        if endpoint.credential_id is not None:
            enabled = (endpoint.options or {}).get('enabled') is not False
            # An endpoint could bind a credential without an assignment. Create
            # the missing login assignment so the relationship survives the
            # table. Assignments of other purposes are left alone.
            assignment, created = CredentialAssignment.objects.get_or_create(
                credential_id=endpoint.credential_id,
                assigned_object_type=service_type,
                assigned_object_id=endpoint.assigned_object_id,
                purpose='login',
                defaults={'enabled': enabled},
            )
            if endpoint.ssh_known_hosts_entry or endpoint.service_type == 'ssh':
                assignment.ssh_known_hosts_entry = endpoint.ssh_known_hosts_entry
                assignment.ssh_strict_host_key_checking = endpoint.ssh_strict_host_key_checking
                assignment.save(update_fields=['ssh_known_hosts_entry', 'ssh_strict_host_key_checking'])
        SSHPublicKey.objects.filter(service_endpoint_id=endpoint.pk).update(
            application_service_id=endpoint.assigned_object_id,
        )

    # A key whose endpoint could not be mapped to a service has nowhere to live.
    SSHPublicKey.objects.filter(application_service__isnull=True).delete()

    # Several endpoints on one service (different ports) may hold a key for the
    # same user. Identical keys collapse; different keys cannot be merged
    # silently, so the migration stops with the rows to reconcile.
    seen = {}
    conflicts = []
    for key in SSHPublicKey.objects.order_by('pk'):
        slot = (key.user_id, key.application_service_id)
        first = seen.setdefault(slot, key)
        if first is key:
            continue
        if first.public_key.strip() != key.public_key.strip():
            conflicts.append(f'user {slot[0]} on service {slot[1]}: keys {first.pk} and {key.pk} differ')
        else:
            key.delete()
    if conflicts:
        raise RuntimeError(
            'Cannot move SSH public keys onto Application Services; remove or reconcile these rows first: '
            + '; '.join(conflicts)
        )


def clear_keys_on_reverse(apps, schema_editor):
    """SSH keys have no endpoint to return to; remove them so the old schema can be restored."""
    apps.get_model('netbox_openbao', 'SSHPublicKey').objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('ipam', '0097_merge_ipaddress_host_index_and_multi_protocol_services'),
        ('netbox_openbao', '0024_engine_auth_material'),
    ]

    operations = [
        migrations.AddField(
            model_name='credentialassignment',
            name='ssh_known_hosts_entry',
            field=models.TextField(
                blank=True,
                help_text='Pinned host key of the service this credential logs in to (SSH only)',
                verbose_name='SSH known_hosts entry',
            ),
        ),
        migrations.AddField(
            model_name='credentialassignment',
            name='ssh_strict_host_key_checking',
            field=models.BooleanField(
                default=True,
                help_text='Refuse to connect when the host key does not match the pinned entry (SSH only)',
                verbose_name='strict host key checking',
            ),
        ),
        migrations.AddField(
            model_name='sshpublickey',
            name='application_service',
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='openbao_ssh_public_keys',
                to='ipam.service',
            ),
        ),
        migrations.RunPython(carry_over_endpoint_data, migrations.RunPython.noop),
        migrations.RemoveConstraint(
            model_name='sshpublickey',
            name='netbox_openbao_sshpublickey_unique_user_endpoint',
        ),
        migrations.RemoveField(model_name='sshpublickey', name='service_endpoint'),
        migrations.AlterField(
            model_name='sshpublickey',
            name='application_service',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='openbao_ssh_public_keys',
                to='ipam.service',
            ),
        ),
        migrations.AlterModelOptions(
            name='sshpublickey',
            options={'ordering': ('user', 'application_service', 'pk')},
        ),
        migrations.AddConstraint(
            model_name='sshpublickey',
            constraint=models.UniqueConstraint(
                fields=('user', 'application_service'),
                name='netbox_openbao_sshpublickey_unique_user_service',
            ),
        ),
        migrations.DeleteModel(name='ServiceEndpoint'),
        # Last on purpose: a reverse run executes it first, so the key table is
        # empty before the endpoint foreign key is added back.
        migrations.RunPython(migrations.RunPython.noop, clear_keys_on_reverse),
    ]
