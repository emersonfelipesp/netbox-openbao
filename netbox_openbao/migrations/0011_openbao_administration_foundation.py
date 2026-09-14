import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.conf import settings
from django.db import migrations, models


def copy_engine_connections(apps, schema_editor):
    OpenBaoCluster = apps.get_model('netbox_openbao', 'OpenBaoCluster')
    SecretEngine = apps.get_model('netbox_openbao', 'SecretEngine')

    for engine in SecretEngine.objects.using(schema_editor.connection.alias).all().iterator():
        cluster = OpenBaoCluster.objects.using(schema_editor.connection.alias).create(
            name=engine.name,
            slug=engine.slug,
            backend=engine.backend,
            api_url=engine.api_url,
            namespace=engine.namespace,
            auth_method=engine.auth_method,
            tls_verify=engine.tls_verify,
            ca_cert_path=engine.ca_cert_path,
            host_device_id=engine.host_device_id,
            status=engine.status,
            status_message=engine.status_message,
            last_checked=engine.last_checked,
            description=engine.description,
            comments=engine.comments,
        )
        engine.cluster_id = cluster.pk
        engine.save(update_fields=('cluster',))


def remove_migrated_clusters(apps, schema_editor):
    OpenBaoCluster = apps.get_model('netbox_openbao', 'OpenBaoCluster')
    SecretEngine = apps.get_model('netbox_openbao', 'SecretEngine')
    database = schema_editor.connection.alias
    cluster_ids = list(
        SecretEngine.objects.using(database)
        .exclude(cluster_id=None)
        .values_list('cluster_id', flat=True)
        .distinct()
    )
    SecretEngine.objects.using(database).update(cluster_id=None)
    OpenBaoCluster.objects.using(database).filter(pk__in=cluster_ids).delete()


class Migration(migrations.Migration):
    # PostgreSQL must commit the reverse data cleanup before it can drop the
    # relation and cluster table; otherwise deferred FK trigger events block
    # the following ALTER TABLE. Keep the data copy itself atomic below.
    atomic = False

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('dcim', '0001_initial'),
        ('netbox_openbao', '0010_live_identity_and_policy_lock'),
    ]

    operations = [
        migrations.CreateModel(
            name='OpenBaoCluster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='name')),
                ('slug', models.SlugField(max_length=100, unique=True, verbose_name='slug')),
                ('backend', models.CharField(default='openbao', max_length=50, verbose_name='backend')),
                ('api_url', models.URLField(help_text='Base URL of the OpenBao API, for example https://bao.example.net:8200', max_length=200, verbose_name='API URL')),
                ('namespace', models.CharField(blank=True, max_length=200, verbose_name='namespace')),
                ('auth_method', models.CharField(default='approle', max_length=50, verbose_name='authentication method')),
                ('tls_verify', models.BooleanField(default=True, verbose_name='verify TLS')),
                ('ca_cert_path', models.CharField(blank=True, help_text='Filesystem path to the CA bundle used to verify the OpenBao certificate', max_length=500, verbose_name='CA certificate path')),
                ('status', models.CharField(default='unknown', editable=False, max_length=50, verbose_name='status')),
                ('status_message', models.CharField(blank=True, editable=False, max_length=500, verbose_name='status message')),
                ('last_checked', models.DateTimeField(blank=True, editable=False, null=True, verbose_name='last checked')),
                ('openbao_version', models.CharField(blank=True, editable=False, max_length=64, verbose_name='OpenBao version')),
                ('capability_digest', models.CharField(blank=True, editable=False, help_text='SHA-256 of the last successfully normalized OpenAPI capability document', max_length=64, verbose_name='capability digest')),
                ('capabilities_checked', models.DateTimeField(blank=True, editable=False, null=True, verbose_name='capabilities checked')),
                ('comments', models.TextField(blank=True)),
                ('description', models.CharField(blank=True, max_length=200)),
                ('host_device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='openbao_clusters', to='dcim.device', verbose_name='OpenBao host')),
                ('owner', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='users.owner')),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
            ],
            options={
                'verbose_name': 'OpenBao cluster',
                'verbose_name_plural': 'OpenBao clusters',
                'ordering': ('name',),
                'permissions': (
                    ('discover', 'Discover OpenBao administrative capabilities'),
                    ('operate', 'Run non-sensitive OpenBao administrative operations'),
                    ('operate_sensitive', 'Run material-bearing OpenBao administrative operations'),
                    ('operate_destructive', 'Run destructive OpenBao administrative operations'),
                ),
            },
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.AddField(
            model_name='secretengine',
            name='cluster',
            field=models.ForeignKey(blank=True, help_text='Cluster connection used for administration. Existing engine connection fields remain authoritative for credential traffic during the compatibility migration.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='secret_engines', to='netbox_openbao.openbaocluster', verbose_name='OpenBao cluster'),
        ),
        migrations.CreateModel(
            name='OpenBaoAdministrationLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('cluster_name_snapshot', models.CharField(max_length=100, verbose_name='cluster name')),
                ('cluster_slug_snapshot', models.CharField(max_length=100, verbose_name='cluster slug')),
                ('username_snapshot', models.CharField(blank=True, max_length=150, verbose_name='username')),
                ('action', models.CharField(max_length=100, verbose_name='action')),
                ('operation_id', models.CharField(blank=True, max_length=200, verbose_name='operation ID')),
                ('risk_level', models.CharField(max_length=32, verbose_name='risk level')),
                ('method', models.CharField(blank=True, max_length=16, verbose_name='method')),
                ('path_template', models.CharField(blank=True, max_length=500, verbose_name='path template')),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True, verbose_name='source IP')),
                ('reason', models.TextField(blank=True, verbose_name='reason')),
                ('request_id', models.CharField(blank=True, max_length=64, verbose_name='request ID')),
                ('capability_digest', models.CharField(blank=True, max_length=64, verbose_name='capability digest')),
                ('success', models.BooleanField(default=True, verbose_name='success')),
                ('status_code', models.PositiveSmallIntegerField(blank=True, null=True, verbose_name='status code')),
                ('message', models.CharField(blank=True, help_text='Fixed safe summary. Request bodies, response bodies, and backend diagnostics are forbidden.', max_length=500, verbose_name='message')),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='timestamp')),
                ('cluster', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='administration_logs', to='netbox_openbao.openbaocluster')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'OpenBao administration log',
                'verbose_name_plural': 'OpenBao administration logs',
                'ordering': ('-timestamp', '-pk'),
                'default_permissions': ('view',),
                'indexes': [
                    models.Index(fields=['cluster', '-timestamp'], name='netbox_open_cluster_f4f101_idx'),
                    models.Index(fields=['user', '-timestamp'], name='netbox_open_user_id_3a1b1a_idx'),
                    models.Index(fields=['operation_id', '-timestamp'], name='netbox_open_operati_0c70d4_idx'),
                ],
            },
        ),
        migrations.RunPython(copy_engine_connections, remove_migrated_clusters, atomic=True),
    ]
