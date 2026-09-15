from django.db import migrations

PERMISSIONS = (
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
    ("view_secret_engines", "View OpenBao secrets-engine configuration"),
    ("manage_secret_engines", "Enable, tune, and remount OpenBao secrets engines"),
    ("disable_secret_engines", "Disable OpenBao secrets engines"),
    ("explore_secret_operations", "View classified OpenBao mounted operations"),
    ("execute_secret_operations", "Execute write operations on OpenBao secrets engines"),
    ("delete_secret_operations", "Delete or destroy mounted OpenBao secret resources"),
    ("reveal_secret_operations", "Read material-bearing OpenBao secrets-engine responses"),
)


class Migration(migrations.Migration):
    dependencies = [("netbox_openbao", "0014_align_cluster_owner_related_name")]

    operations = [
        migrations.AlterModelOptions(
            name="openbaocluster",
            options={
                "ordering": ("name",),
                "verbose_name": "OpenBao cluster",
                "verbose_name_plural": "OpenBao clusters",
                "permissions": PERMISSIONS,
            },
        ),
    ]
