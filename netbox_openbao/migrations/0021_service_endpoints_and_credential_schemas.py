import django.core.validators
import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.conf import settings
from django.db import migrations, models

SCHEMAS = {
    'ssh_password': ('SSH password', {'password': {'type': 'string'}}, ['password'], '', ['password']),
    'ssh_key': (
        'SSH key',
        {'private_key': {'type': 'string'}, 'passphrase': {'type': 'string'}},
        ['private_key', 'passphrase'],
        'ssh',
        ['private_key'],
    ),
    'snmp_v2c': ('SNMP v2c', {'community': {'type': 'string'}}, ['community'], '', ['community']),
    'snmp_v3': (
        'SNMP v3',
        {
            'username': {'type': 'string'}, 'auth_password': {'type': 'string'},
            'priv_password': {'type': 'string'}, 'auth_protocol': {'type': 'string'},
            'priv_protocol': {'type': 'string'},
        },
        ['auth_password', 'priv_password'],
        '',
        ['username', 'auth_password'],
    ),
    'cloud_init': (
        'Cloud-init',
        {'username': {'type': 'string'}, 'password': {'type': 'string'}, 'private_key': {'type': 'string'}},
        ['password', 'private_key'],
        '',
        [],
    ),
    'observability': (
        'Observability',
        {'value': {'type': 'string'}, 'purpose': {'type': 'string'}, 'external_reference': {'type': 'string'}},
        ['value'],
        '',
        ['value'],
    ),
}


# Marks a row this migration created, so the reverse migration deletes only
# rows it is responsible for and never an operator's own schema that reuses
# one of the seeded slugs (e.g. after a manual edit or a restore).
_DESCRIPTION_MARKER = 'Credential schema used by the NMS import for {name}.'


def _seeded_fields(name, properties, secret_fields, extractor, required):
    return {
        'name': name,
        'description': _DESCRIPTION_MARKER.format(name=name),
        'schema': {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'type': 'object',
            'properties': properties,
            'required': required,
            'additionalProperties': False,
        },
        'secret_fields': secret_fields,
        'extractor': extractor,
    }


def seed_schemas(apps, schema_editor):
    """Create the seeded schemas only where the slug is absent.

    Never overwrites an existing row at the same slug — an operator-defined
    `CredentialTypeSchema` that happens to reuse a seeded slug (or a schema
    left over from a prior partial run) is left untouched rather than
    clobbered by `update_or_create`.
    """
    CredentialTypeSchema = apps.get_model('netbox_openbao', 'CredentialTypeSchema')
    existing_slugs = set(
        CredentialTypeSchema.objects.filter(slug__in=SCHEMAS).values_list('slug', flat=True)
    )
    for slug, spec in SCHEMAS.items():
        if slug in existing_slugs:
            continue
        CredentialTypeSchema.objects.create(slug=slug, **_seeded_fields(*spec))


def unseed_schemas(apps, schema_editor):
    """Leave seeded schemas in place on reverse.

    Field equality cannot prove this migration created a row: an operator may
    have defined an identical schema before it ran. Deleting would risk
    removing operator-owned validation policy, and a leftover schema row is
    harmless to the pre-0021 code, so the reverse is deliberately a no-op.
    """


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('netbox_openbao', '0020_finalization_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceEndpoint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ('assigned_object_id', models.PositiveBigIntegerField()),
                ('service_type', models.CharField(choices=[('ssh', 'SSH'), ('telnet', 'Telnet'), ('netconf', 'NETCONF'), ('restconf', 'RESTCONF'), ('gnmi', 'gNMI'), ('snmp', 'SNMP'), ('http', 'HTTP')], max_length=20)),
                ('host', models.CharField(blank=True, max_length=255)),
                ('port', models.PositiveIntegerField(validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(65535)])),
                ('ssh_known_hosts_entry', models.TextField(blank=True)),
                ('ssh_strict_host_key_checking', models.BooleanField(default=True)),
                ('options', models.JSONField(blank=True, default=dict)),
                ('import_source', models.CharField(blank=True, db_index=True, editable=False, max_length=200)),
                ('assigned_object_type', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='+', to='contenttypes.contenttype')),
                ('credential', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='service_endpoints', to='netbox_openbao.credential')),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
            ],
            options={'ordering': ('assigned_object_type', 'assigned_object_id', 'service_type', 'port')},
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.CreateModel(
            name='SSHPublicKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ('public_key', models.TextField()),
                ('fingerprint', models.CharField(blank=True, db_index=True, editable=False, max_length=128)),
                ('key_type', models.CharField(blank=True, editable=False, max_length=50)),
                ('installed_at', models.DateTimeField(blank=True, null=True)),
                ('import_source', models.CharField(blank=True, db_index=True, editable=False, max_length=200)),
                ('service_endpoint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ssh_public_keys', to='netbox_openbao.serviceendpoint')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='openbao_ssh_public_keys', to=settings.AUTH_USER_MODEL)),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
            ],
            options={'ordering': ('user', 'service_endpoint', 'pk')},
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.AddIndex(model_name='serviceendpoint', index=models.Index(fields=['assigned_object_type', 'assigned_object_id'], name='openbao_service_object_idx')),
        migrations.AddConstraint(model_name='serviceendpoint', constraint=models.UniqueConstraint(fields=('assigned_object_type', 'assigned_object_id', 'service_type', 'port'), name='netbox_openbao_serviceendpoint_unique_object_service_port')),
        migrations.AddConstraint(model_name='sshpublickey', constraint=models.UniqueConstraint(fields=('user', 'service_endpoint'), name='netbox_openbao_sshpublickey_unique_user_endpoint')),
        migrations.RunPython(seed_schemas, unseed_schemas),
    ]
