"""Align the recorded ``owner`` field with whatever NetBox core declares.

NetBox 4.7.0-beta2 added ``related_name="+"`` to ``OwnerMixin.owner``; 4.5 and
4.6 declare the same field without it. ``0001_initial`` was generated against
4.7 and recorded the newer form, so ``makemigrations --check`` reported drift on
every supported 4.6 runtime — the plugin's model state said one thing and the
running core said another.

``related_name`` is a Python-side reverse accessor with no database
representation, so an ``AlterField`` between the two forms emits no DDL. This
migration therefore builds the field from the running core's own declaration,
which makes the recorded state match on every supported release without
pinning the plugin to one of them.
"""

from django.db import migrations, models
from django.db.models.deletion import PROTECT


def _core_owner_field() -> models.ForeignKey:
    """Return an ``owner`` field mirroring the running NetBox core."""
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
        ("netbox_openbao", "0005_credentialtypeschema"),
        ("users", "0016_default_ordering_indexes"),
    ]

    operations = [
        migrations.AlterField(
            model_name=model_name,
            name="owner",
            field=_core_owner_field(),
        )
        for model_name in ("credential", "credentialpolicy", "secretengine")
    ]
