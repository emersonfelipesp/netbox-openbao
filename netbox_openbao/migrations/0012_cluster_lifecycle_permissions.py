from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_openbao', '0011_openbao_administration_foundation'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='openbaocluster',
            options={
                'ordering': ('name',),
                'permissions': (
                    ('discover', 'Discover OpenBao administrative capabilities'),
                    ('operate', 'Run non-sensitive OpenBao administrative operations'),
                    ('operate_sensitive', 'Run material-bearing OpenBao administrative operations'),
                    ('operate_destructive', 'Run destructive OpenBao administrative operations'),
                    ('initialize', 'Initialize an OpenBao cluster'),
                    ('unseal', 'Submit OpenBao unseal material or reset unseal progress'),
                    ('seal', 'Seal an OpenBao cluster'),
                    ('manage_raft', 'Manage OpenBao Raft configuration'),
                    ('remove_raft_peer', 'Remove an OpenBao Raft peer'),
                    ('download_raft_snapshot', 'Download an OpenBao Raft snapshot'),
                    ('restore_raft_snapshot', 'Restore an OpenBao Raft snapshot'),
                    ('force_restore_raft_snapshot', 'Force restore an OpenBao Raft snapshot'),
                ),
                'verbose_name': 'OpenBao cluster',
                'verbose_name_plural': 'OpenBao clusters',
            },
        ),
    ]
