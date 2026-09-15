from django.db import migrations

ENGINE_JOURNEY_PERMISSIONS = (
    ("reveal_kv_secrets", "Read KV secret values, metadata, versions, and diffs"),
    ("manage_kv_secrets", "Create, update, patch, undelete, and configure KV secrets"),
    ("destroy_kv_versions", "Delete or irreversibly destroy KV secrets and versions"),
    ("use_transit", "Use OpenBao transit cryptographic operations"),
    ("manage_transit_keys", "Create, configure, and rotate OpenBao transit keys"),
    ("delete_transit_keys", "Delete OpenBao transit keys"),
    ("generate_database_credentials", "Generate OpenBao database credentials"),
    ("manage_database_roles", "Manage OpenBao database connections and roles"),
    ("delete_database_resources", "Delete OpenBao database connections and roles"),
    ("rotate_database_credentials", "Rotate OpenBao database credentials and connections"),
    ("issue_ssh_credentials", "Issue and verify OpenBao SSH credentials and certificates"),
    ("manage_ssh_roles", "Manage OpenBao SSH roles"),
    ("delete_ssh_roles", "Delete OpenBao SSH roles"),
    ("generate_totp_codes", "Generate and validate OpenBao TOTP codes"),
    ("manage_totp_keys", "Create and view OpenBao TOTP keys"),
    ("delete_totp_keys", "Delete OpenBao TOTP keys"),
)


class Migration(migrations.Migration):
    dependencies = [("netbox_openbao", "0015_secret_engine_administration_permissions")]

    operations = [
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
                    ("view_secret_engines", "View OpenBao secrets-engine configuration"),
                    ("manage_secret_engines", "Enable, tune, and remount OpenBao secrets engines"),
                    ("disable_secret_engines", "Disable OpenBao secrets engines"),
                    ("explore_secret_operations", "View classified OpenBao mounted operations"),
                    ("execute_secret_operations", "Execute write operations on OpenBao secrets engines"),
                    ("delete_secret_operations", "Delete or destroy mounted OpenBao secret resources"),
                    ("reveal_secret_operations", "Read material-bearing OpenBao secrets-engine responses"),
                    *ENGINE_JOURNEY_PERMISSIONS,
                ),
                "verbose_name": "OpenBao cluster",
                "verbose_name_plural": "OpenBao clusters",
            },
        ),
    ]
