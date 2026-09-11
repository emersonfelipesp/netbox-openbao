"""Public version-bound key identity and synchronized policy relationships.

No identity is inferred from legacy display metadata. Empty identity remains
unverified until a normal material write derives it from the actual key.
"""

from django.db import migrations, models

LOCK_POLICY_GROUPS = """
CREATE FUNCTION openbao_lock_policy_groups() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM id FROM netbox_openbao_credentialpolicy
        WHERE id = NEW.credentialpolicy_id FOR UPDATE;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM id FROM netbox_openbao_credentialpolicy
        WHERE id = OLD.credentialpolicy_id FOR UPDATE;
        RETURN OLD;
    ELSE
        PERFORM id FROM netbox_openbao_credentialpolicy
        WHERE id IN (OLD.credentialpolicy_id, NEW.credentialpolicy_id)
        ORDER BY id FOR UPDATE;
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER openbao_policy_groups_lock
BEFORE INSERT OR UPDATE OR DELETE ON netbox_openbao_credentialpolicy_groups
FOR EACH ROW EXECUTE FUNCTION openbao_lock_policy_groups();
"""

UNLOCK_POLICY_GROUPS = """
DROP TRIGGER IF EXISTS openbao_policy_groups_lock ON netbox_openbao_credentialpolicy_groups;
DROP FUNCTION IF EXISTS openbao_lock_policy_groups();
"""


class Migration(migrations.Migration):
    dependencies = [('netbox_openbao', '0009_automation_resolution')]

    operations = [
        migrations.AddField(model_name='credential', name='live_key_fingerprint',
                            field=models.CharField(blank=True, db_default='', editable=False, max_length=128)),
        migrations.AddField(model_name='credential', name='live_key_version',
                            field=models.PositiveIntegerField(blank=True, editable=False, null=True)),
        migrations.AddField(model_name='credential', name='staged_key_fingerprint',
                            field=models.CharField(blank=True, db_default='', editable=False, max_length=128)),
        migrations.AddField(model_name='credential', name='staged_key_version',
                            field=models.PositiveIntegerField(blank=True, editable=False, null=True)),
        migrations.RunSQL(LOCK_POLICY_GROUPS, reverse_sql=UNLOCK_POLICY_GROUPS),
    ]
