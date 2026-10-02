import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_openbao', '0023_seed_ssh_service_template'),
    ]

    operations = [
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
