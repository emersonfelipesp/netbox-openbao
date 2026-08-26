"""
The three places NetBox 4.6 and 4.7 differ for this plugin.

Kept in one module on purpose. Version-dependent behaviour scattered through
the codebase is how a plugin ends up quietly broken on one of the releases it
claims to support: each site looks locally reasonable and nothing states the
whole surface. This does.

Every difference is detected from what the running NetBox actually provides —
an import that either resolves or does not, a field that either exists or does
not — rather than from a version comparison. The capability is the thing being
depended on; a version string is a weaker second statement of the same fact,
and one that needs editing again at 4.8.

The surface, in full:

1. ``Choice`` — 4.7 wraps choice-set entries in a class carrying an optional
   description. 4.6 uses plain tuples.
2. ``GenericObjectChoiceField`` / ``GenericObjectFormMixin`` — 4.7's combined
   content-type-plus-object selector, absent from 4.6. ``FieldSet(html_id=...)``
   goes with it: it exists to give that field's HTMX re-render a target, so
   :mod:`netbox_openbao.forms` passes it only when the field is available.
3. ``attrs.ArrayAttr`` — 4.7 renders list attributes as chips. 4.6 has no such
   attribute; the fallback below joins the list instead.
4. ``ipam.Service`` ports — 4.7 replaced ``protocol`` + ``ports`` with a
   ``port_mappings`` array. Handled in :mod:`netbox_openbao.quickadd`, which is
   the only code that writes a service.

Deliberately *not* here: everything else. Of the 64 NetBox imports this plugin
makes, 61 resolve identically on both releases, as do 29 of the 30
``netbox.ui`` attributes it uses — including ``netbox.api.gfk_fields``,
``netbox.jobs``, ``netbox.forms`` and the whole declarative panel framework,
which an earlier version of this plugin assumed were 4.7-only. They are not.
Those counts come from importing each name under both releases, not from
reading release notes.
"""

__all__ = (
    'ArrayAttr',
    'Choice',
    'GenericObjectChoiceField',
    'GenericObjectFormMixin',
    'HAS_GENERIC_OBJECT_FIELD',
)


# --- 1. Choice ---------------------------------------------------------------

try:
    from utilities.choices import Choice  # type: ignore[attr-defined]
except ImportError:  # NetBox 4.6

    def Choice(value, label, color=None, description=None):  # noqa: N802
        """Stand in for 4.7's ``Choice`` using the tuple form 4.6 expects.

        ``description`` is dropped rather than emulated. It feeds a 4.7 UI
        affordance that renders help text beside each option; there is nowhere
        for it to go on 4.6, and inventing a placement would be a worse
        outcome than the field simply not having help text on the older
        release. The choice's value and label — the parts anything depends on
        — are identical either way.
        """
        return (value, label, color) if color is not None else (value, label)


# --- 2. The generic-object form field ----------------------------------------

try:
    from utilities.forms import GenericObjectFormMixin  # type: ignore[attr-defined]
    from utilities.forms.fields.generic import GenericObjectChoiceField

    HAS_GENERIC_OBJECT_FIELD = True
except ImportError:  # NetBox 4.6
    HAS_GENERIC_OBJECT_FIELD = False

    class GenericObjectFormMixin:
        """No-op stand-in.

        On 4.7 this mixin binds the combined selector's value back onto the
        model's content-type and object-id fields. On 4.6 the form declares
        those two fields itself and binds them in ``clean()``, so there is
        nothing for a mixin to do — and an empty mixin keeps the class
        definition identical across both releases rather than forking it.
        """

    GenericObjectChoiceField = None


# --- 3. ArrayAttr ------------------------------------------------------------

try:
    from netbox.ui.attrs import ArrayAttr
except ImportError:  # NetBox 4.6
    from netbox.ui.attrs import TextAttr

    class ArrayAttr(TextAttr):
        """Render a list attribute as text, since 4.6 has no array attribute.

        4.7 renders each element as its own chip. Joining is the honest
        degradation: the same values, in the same order, without the styling.

        Empty lists deliberately collapse to `''` rather than to `'[]'` or a
        stray separator — `ObjectAttribute.render` treats `''` as empty and
        substitutes the standard placeholder, which is what every other
        attribute does with no value, and what an operator reading the panel
        expects.
        """

        def get_value(self, obj):
            value = super().get_value(obj)
            if not value:
                return ''
            return ', '.join(str(item) for item in value)
