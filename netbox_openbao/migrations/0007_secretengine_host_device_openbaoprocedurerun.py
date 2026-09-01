import django.contrib.auth.models
import django.db.models.deletion
import taggit.managers
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_openbao', '0006_align_owner_related_name'),
        ('netbox_rpc', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='secretengine',
            name='host_device',
            field=models.ForeignKey(
                blank=True,
                help_text='Device where OpenBao runs. Required for netbox-rpc host operations.',
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='openbao_secret_engines',
                to='dcim.device',
                verbose_name='OpenBao host',
            ),
        ),
        migrations.CreateModel(
            name='OpenBaoProcedureRun',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                (
                    'custom_field_data',
                    models.JSONField(blank=True, default=dict, encoder=None),
                ),
                ('procedure_name', models.CharField(max_length=100, verbose_name='procedure')),
                (
                    'engine',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='procedure_runs',
                        to='netbox_openbao.secretengine',
                    ),
                ),
                (
                    'initiated_by',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='users.user',
                    ),
                ),
                (
                    'rpc_execution',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='netbox_rpc.rpcexecution',
                    ),
                ),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
            ],
            options={
                'verbose_name': 'OpenBao procedure run',
                'verbose_name_plural': 'OpenBao procedure runs',
                'ordering': ('-created',),
            },
        ),
    ]
