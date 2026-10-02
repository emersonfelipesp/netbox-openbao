"""
The single schema and data migration of release 0.2.0rc1.

It folds together everything added since the published 0.1.0.post2 boundary
(0020): the service endpoint and credential schema models and their seed, the
unique credential import source constraint with its duplicate disambiguation,
the idempotent SSH service template seed, the retained legacy policy prefix and
the encrypted authentication material model.

It keeps the name `0024_engine_auth_material` on purpose. Databases built from
the integration branch recorded that name, and a different name would make
Django replay schema they already applied. Those databases skip this
migration; a database at the 0.1.0.post2 boundary runs it once. The numbers
0021 to 0023 are intentionally unused.
"""
import django.core.validators
import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.conf import settings
from django.db import migrations, models
from django.db.models import Count

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


"""Prevent two Credential rows from claiming the same import provenance.

Without this constraint, two concurrent runs of
`openbao_import_nms_credentials` (or a concurrent run of the separate
`netbox_secrets` importer) racing on the same source row can both pass the
"does a Credential with this import_source already exist?" check before
either commits, and both write a distinct OpenBao path for what is supposed
to be a single imported credential. `import_source` values are already
globally unique by construction — every writer stamps
`<app_label>.<Model>:<pk>` (management command) or a `<SOURCE_SYSTEM>:<id>`
prefix (`netbox_openbao/importers/netbox_secrets.py`) — so a real, non-blank
value colliding across two rows is always a bug, never a legitimate shared
value. The constraint is partial (`import_source != ''`) because the column
is blank for every credential nobody imported, and those blanks must not
collide with each other.
"""



def disambiguate_duplicate_import_sources(apps, schema_editor):
    """Make pre-existing duplicate provenance values unique before constraining.

    A database that already holds duplicates must not fail ``migrate`` on
    startup. The oldest row keeps the original value; every later row keeps
    the original as a prefix plus ``#duplicate-<pk>``, so no provenance is lost
    and an operator can reconcile the copies afterwards. No row or secret is
    deleted.
    """
    Credential = apps.get_model('netbox_openbao', 'Credential')
    duplicated = (
        Credential.objects.exclude(import_source='')
        .values('import_source')
        .annotate(total=Count('pk'))
        .filter(total__gt=1)
        .values_list('import_source', flat=True)
    )
    occupied = set(Credential.objects.exclude(import_source='').values_list('import_source', flat=True))
    for value in list(duplicated):
        rows = Credential.objects.filter(import_source=value).order_by('pk')
        for row in list(rows)[1:]:
            row.import_source = _unused_value(value, row.pk, occupied)
            occupied.add(row.import_source)
            row.save(update_fields=['import_source'])


def _unused_value(value, pk, occupied):
    """Return ``value#duplicate-<pk>[-n]`` that no row already holds."""
    attempt = 0
    while True:
        suffix = f'#duplicate-{pk}' + (f'-{attempt}' if attempt else '')
        candidate = value[: 200 - len(suffix)] + suffix
        if candidate not in occupied:
            return candidate
        attempt += 1


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
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ipam', '0097_merge_ipaddress_host_index_and_multi_protocol_services'),
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
        migrations.RunPython(disambiguate_duplicate_import_sources, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name='credential',
            constraint=models.UniqueConstraint(
                fields=('import_source',),
                condition=~models.Q(import_source=''),
                name='netbox_openbao_credential_unique_import_source',
            ),
        ),
        migrations.RunPython(seed_ssh_service_template, migrations.RunPython.noop),
        migrations.RenameField(
            model_name='credentialpolicy',
            old_name='approle_env_prefix',
            new_name='legacy_approle_env_prefix',
        ),
        migrations.AlterField(
            model_name='credentialpolicy',
            name='legacy_approle_env_prefix',
            field=models.CharField(
                blank=True,
                editable=False,
                help_text=(
                    'Retained only so the explicit one-time environment import can locate '
                    'legacy tier credentials.'
                ),
                max_length=100,
                verbose_name='legacy AppRole environment prefix',
            ),
        ),
        migrations.CreateModel(
            name='EngineAuthMaterial',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('role_id_ciphertext', models.TextField(blank=True, editable=False)),
                ('secret_id_ciphertext', models.TextField(blank=True, editable=False)),
                ('token_ciphertext', models.TextField(blank=True, editable=False)),
                ('k8s_role_ciphertext', models.TextField(blank=True, editable=False)),
                ('k8s_jwt_path_ciphertext', models.TextField(blank=True, editable=False)),
                ('client_cert_ciphertext', models.TextField(blank=True, editable=False)),
                ('client_key_ciphertext', models.TextField(blank=True, editable=False)),
                ('revision', models.PositiveBigIntegerField(default=1, editable=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                (
                    'cluster',
                    models.OneToOneField(
                        blank=True,
                        help_text='Service identity used only by the cluster administration plane.',
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='auth_material',
                        to='netbox_openbao.openbaocluster',
                        verbose_name='OpenBao cluster',
                    ),
                ),
                (
                    'engine',
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='auth_material',
                        to='netbox_openbao.secretengine',
                        verbose_name='secret engine',
                    ),
                ),
                (
                    'policy',
                    models.OneToOneField(
                        blank=True,
                        help_text='Optional tier-specific identity. Blank tiers use their engine identity.',
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='auth_material',
                        to='netbox_openbao.credentialpolicy',
                        verbose_name='credential policy',
                    ),
                ),
            ],
            options={
                'verbose_name': 'engine authentication material',
                'verbose_name_plural': 'engine authentication material',
                'ordering': ('engine_id', 'policy_id', 'cluster_id'),
            },
        ),
        migrations.AddConstraint(
            model_name='engineauthmaterial',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(('engine__isnull', False), ('policy__isnull', True), ('cluster__isnull', True))
                    | models.Q(('engine__isnull', True), ('policy__isnull', False), ('cluster__isnull', True))
                    | models.Q(('engine__isnull', True), ('policy__isnull', True), ('cluster__isnull', False))
                ),
                name='netbox_openbao_auth_material_one_owner',
            ),
        ),
    ]
