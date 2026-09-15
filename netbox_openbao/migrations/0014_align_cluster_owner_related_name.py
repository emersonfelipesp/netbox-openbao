"""Align the cluster ``owner`` migration state with the running NetBox core.

NetBox 4.7 adds ``related_name="+"`` to ``OwnerMixin.owner`` while NetBox 4.6
does not. The OpenBao cluster was introduced after the equivalent compatibility
migration for the plugin's original owner-bearing models, so its recorded state
must be aligned separately. The reverse relation has no database representation;
this migration changes state without emitting schema DDL.
"""

from django.db import migrations, models
from django.db.models.deletion import PROTECT


def _core_owner_field() -> models.ForeignKey:
    """Return an ``owner`` field matching the running NetBox release."""
    kwargs: dict[str, object] = {
        "to": "users.owner",
        "on_delete": PROTECT,
        "blank": True,
        "null": True,
    }
    from netbox.models.mixins import OwnerMixin

    related_name = OwnerMixin._meta.get_field("owner").remote_field.related_name
    if related_name:
        kwargs["related_name"] = related_name
    return models.ForeignKey(**kwargs)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_openbao", "0013_authentication_administration_permissions"),
    ]

    operations = [
        migrations.AlterField(
            model_name="openbaocluster",
            name="owner",
            field=_core_owner_field(),
        ),
    ]
