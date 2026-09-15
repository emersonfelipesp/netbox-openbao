from django.db import migrations, models


def classify_legacy_audit_outcomes(apps, schema_editor):
    """Preserve the meaning of audit rows created before explicit outcomes."""
    Log = apps.get_model("netbox_openbao", "OpenBaoAdministrationLog")
    Log.objects.filter(success=False).update(outcome="failed")
    Log.objects.filter(success=True, action__endswith="-authorized").update(outcome="authorized")


def restore_legacy_audit_outcomes(apps, schema_editor):
    """The reverse field removal makes an outcome rewrite unnecessary."""


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_openbao", "0012_cluster_lifecycle_permissions"),
    ]

    operations = [
        migrations.AddField(
            model_name="openbaoadministrationlog",
            name="outcome",
            field=models.CharField(
                choices=(
                    ("authorized", "Authorized"),
                    ("succeeded", "Succeeded"),
                    ("failed", "Failed"),
                    ("unknown", "Unknown"),
                ),
                default="succeeded",
                max_length=32,
                verbose_name="outcome",
            ),
        ),
        migrations.RunPython(classify_legacy_audit_outcomes, restore_legacy_audit_outcomes),
        migrations.AlterModelOptions(
            name="openbaocluster",
            options={
                "ordering": ("name",),
                "permissions": (
                    ("discover", "Discover OpenBao administrative capabilities"),
                    ("operate", "Run non-sensitive OpenBao administrative operations"),
                    ("operate_sensitive", "Run material-bearing OpenBao administrative operations"),
                    ("operate_destructive", "Run destructive OpenBao administrative operations"),
                    ("initialize", "Initialize an OpenBao cluster"),
                    ("unseal", "Submit OpenBao unseal material or reset unseal progress"),
                    ("seal", "Seal an OpenBao cluster"),
                    ("manage_raft", "Manage OpenBao Raft configuration"),
                    ("remove_raft_peer", "Remove an OpenBao Raft peer"),
                    ("download_raft_snapshot", "Download an OpenBao Raft snapshot"),
                    ("restore_raft_snapshot", "Restore an OpenBao Raft snapshot"),
                    ("force_restore_raft_snapshot", "Force restore an OpenBao Raft snapshot"),
                    ("view_authentication", "View OpenBao authentication and MFA configuration"),
                    ("manage_auth_methods", "Enable, configure, tune, and remount OpenBao auth methods"),
                    ("disable_auth_methods", "Disable OpenBao auth methods"),
                    ("manage_auth_resources", "Manage OpenBao auth method resources"),
                    ("delete_auth_resources", "Delete OpenBao auth method resources"),
                    ("issue_auth_material", "Issue one-shot OpenBao authentication material"),
                    ("authenticate", "Use OpenBao authentication and MFA flows"),
                    ("manage_tokens", "Look up and renew OpenBao tokens"),
                    ("revoke_tokens", "Revoke OpenBao tokens"),
                    ("manage_mfa", "Manage OpenBao MFA methods and login enforcements"),
                    ("delete_mfa", "Delete OpenBao MFA methods, secrets, and login enforcements"),
                ),
                "verbose_name": "OpenBao cluster",
                "verbose_name_plural": "OpenBao clusters",
            },
        ),
    ]
