"""Prevent two Credential rows from claiming the same import provenance.

Without this constraint, two concurrent runs of
`openbao_import_nms_credentials` (or a concurrent run of the separate
`netbox_secrets` importer) racing on the same source row can both pass the
"does a Credential with this import_source already exist?" check before
either commits, and both write a distinct OpenBao path for what is supposed
to be a single imported credential. `import_source` values are already
globally unique by construction — every writer stamps
`<app_label>.<Model>:<pk>` (management command) or a `<SOURCE_SYSTEM>:<id>`
prefix (`netbox_openbao/importers/netbox_secrets.py`) — so a real, non-blank
value colliding across two rows is always a bug, never a legitimate shared
value. The constraint is partial (`import_source != ''`) because the column
is blank for every credential nobody imported, and those blanks must not
collide with each other.
"""

from django.db import migrations, models
from django.db.models import Count


def disambiguate_duplicate_import_sources(apps, schema_editor):
    """Make pre-existing duplicate provenance values unique before constraining.

    A database that already holds duplicates must not fail ``migrate`` on
    startup. The oldest row keeps the original value; every later row keeps
    the original as a prefix plus ``#duplicate-<pk>``, so no provenance is lost
    and an operator can reconcile the copies afterwards. No row or secret is
    deleted.
    """
    Credential = apps.get_model('netbox_openbao', 'Credential')
    duplicated = (
        Credential.objects.exclude(import_source='')
        .values('import_source')
        .annotate(total=Count('pk'))
        .filter(total__gt=1)
        .values_list('import_source', flat=True)
    )
    occupied = set(Credential.objects.exclude(import_source='').values_list('import_source', flat=True))
    for value in list(duplicated):
        rows = Credential.objects.filter(import_source=value).order_by('pk')
        for row in list(rows)[1:]:
            row.import_source = _unused_value(value, row.pk, occupied)
            occupied.add(row.import_source)
            row.save(update_fields=['import_source'])


def _unused_value(value, pk, occupied):
    """Return ``value#duplicate-<pk>[-n]`` that no row already holds."""
    attempt = 0
    while True:
        suffix = f'#duplicate-{pk}' + (f'-{attempt}' if attempt else '')
        candidate = value[: 200 - len(suffix)] + suffix
        if candidate not in occupied:
            return candidate
        attempt += 1


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_openbao', '0021_service_endpoints_and_credential_schemas'),
    ]

    operations = [
        migrations.RunPython(disambiguate_duplicate_import_sources, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name='credential',
            constraint=models.UniqueConstraint(
                fields=('import_source',),
                condition=~models.Q(import_source=''),
                name='netbox_openbao_credential_unique_import_source',
            ),
        ),
    ]
