from django.db import migrations

TEMPLATE_NAME = 'SSH'


def seed_ssh_service_template(apps, schema_editor):
    """Create the `SSH` service template if no template of that name exists.

    Never overwrites: an operator who renamed the ports or description keeps
    their edit, and a re-run is a no-op.
    """
    ServiceTemplate = apps.get_model('ipam', 'ServiceTemplate')
    if ServiceTemplate.objects.filter(name__iexact=TEMPLATE_NAME).exists():
        return
    ServiceTemplate.objects.create(
        name=TEMPLATE_NAME,
        port_mappings=['tcp/22'],
        description='SSH remote login. Credentials stored in OpenBao are tied to this service.',
    )


class Migration(migrations.Migration):

    dependencies = [
        ('ipam', '0097_merge_ipaddress_host_index_and_multi_protocol_services'),
        ('netbox_openbao', '0022_credential_import_source_unique'),
    ]

    operations = [
        migrations.RunPython(seed_ssh_service_template, migrations.RunPython.noop),
    ]
