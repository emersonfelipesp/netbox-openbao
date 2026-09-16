from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_openbao", "0018_access_administration_permissions"),
    ]

    operations = [
        migrations.AddField(
            model_name="openbaoadministrationlog",
            name="target_identifiers",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Validated non-secret resource identifiers used to reconcile the operation.",
                verbose_name="target identifiers",
            ),
        ),
    ]
