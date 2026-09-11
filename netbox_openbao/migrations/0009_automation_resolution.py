"""Add non-secret execution correlation and durable provider-use reservations."""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_openbao', '0008_openbaosettings'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='credentialassignment', name='enabled',
            field=models.BooleanField(default=True, db_default=True, help_text='Permit this assignment to be used by execution-bound automation'),
        ),
        migrations.AddField(
            model_name='credentialaccesslog', name='executor',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(model_name='credentialaccesslog', name='executor_snapshot', field=models.CharField(blank=True, db_default='', max_length=150)),
        migrations.AddField(model_name='credentialaccesslog', name='execution_id', field=models.PositiveBigIntegerField(blank=True, db_index=True, null=True)),
        migrations.AddField(model_name='credentialaccesslog', name='intent_run_id', field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name='credentialaccesslog', name='step_id', field=models.CharField(blank=True, db_default='', max_length=100)),
        migrations.AddField(model_name='credentialaccesslog', name='reference_name', field=models.CharField(blank=True, db_default='', max_length=100)),
        migrations.AddField(model_name='credentialaccesslog', name='assignment_id', field=models.PositiveBigIntegerField(blank=True, null=True)),
        migrations.AddField(model_name='credentialaccesslog', name='resolved_version', field=models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField(model_name='credentialaccesslog', name='purpose', field=models.CharField(blank=True, db_default='', max_length=50)),
        migrations.AddField(model_name='credentialaccesslog', name='dispatch_nonce_digest', field=models.CharField(blank=True, db_default='', max_length=64)),
        migrations.CreateModel(
            name='AutomationResolutionReceipt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('execution_id', models.PositiveBigIntegerField()),
                ('dispatch_nonce_digest', models.CharField(max_length=64)),
                ('step_id', models.CharField(blank=True, max_length=100)),
                ('reference_name', models.CharField(max_length=100)),
                ('credential_uuid', models.UUIDField()),
                ('assignment_id', models.PositiveBigIntegerField()),
                ('resolved_version', models.PositiveIntegerField()),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
            options={'constraints': [models.UniqueConstraint(fields=('execution_id', 'dispatch_nonce_digest', 'step_id', 'reference_name'), name='openbao_automation_once')]},
        ),
    ]
