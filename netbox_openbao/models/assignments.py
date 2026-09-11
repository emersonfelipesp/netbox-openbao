from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel

from netbox_openbao.choices import PurposeChoices
from netbox_openbao.config import assignable_model_labels

__all__ = ('CredentialAssignment',)


class CredentialAssignment(NetBoxModel):
    """
    Binds a credential to an object for a stated purpose.

    Modelled as a through-table rather than a GenericForeignKey on
    `Credential` itself because the relationship is genuinely many-to-many:
    one fleet SSH key is deployed to hundreds of devices, and one device holds
    a login, an enable, and an out-of-band credential.
    """

    credential = models.ForeignKey(
        to='netbox_openbao.Credential',
        on_delete=models.CASCADE,
        related_name='assignments',
        verbose_name=_('credential'),
    )
    assigned_object_type = models.ForeignKey(
        to='contenttypes.ContentType',
        on_delete=models.PROTECT,
        related_name='+',
    )
    assigned_object_id = models.PositiveBigIntegerField()
    assigned_object = GenericForeignKey(
        ct_field='assigned_object_type',
        fk_field='assigned_object_id',
    )
    purpose = models.CharField(
        verbose_name=_('purpose'),
        max_length=50,
        choices=PurposeChoices,
        default=PurposeChoices.PURPOSE_LOGIN,
    )
    is_primary = models.BooleanField(
        verbose_name=_('is primary'),
        default=False,
        help_text=_('The credential automation should choose for this object and purpose'),
    )
    enabled = models.BooleanField(
        default=True,
        db_default=True,
        help_text=_('Permit this assignment to be used by execution-bound automation'),
    )
    description = models.CharField(
        verbose_name=_('description'),
        max_length=200,
        blank=True,
    )

    clone_fields = ('credential', 'assigned_object_type', 'purpose')

    class Meta:
        ordering = ('credential', 'pk')
        verbose_name = _('credential assignment')
        verbose_name_plural = _('credential assignments')
        indexes = (
            models.Index(fields=('assigned_object_type', 'assigned_object_id')),
        )
        constraints = (
            models.UniqueConstraint(
                fields=('credential', 'assigned_object_type', 'assigned_object_id', 'purpose'),
                name='%(app_label)s_%(class)s_unique_assignment',
                violation_error_message=_('This credential is already assigned to that object for that purpose.'),
            ),
            # At most one primary per (object, purpose), so "which credential
            # does automation use here?" always has exactly one answer.
            models.UniqueConstraint(
                fields=('assigned_object_type', 'assigned_object_id', 'purpose'),
                condition=models.Q(is_primary=True),
                name='%(app_label)s_%(class)s_single_primary',
                violation_error_message=_('Another credential is already primary for that object and purpose.'),
            ),
        )

    def __str__(self):
        return f'{self.credential}: {self.get_purpose_display()} on {self.assigned_object}'

    def clean(self):
        super().clean()

        # Restrict assignment to the object types the deployment opted into.
        # Enforced here rather than only in the form so the REST API and any
        # direct ORM caller are held to the same list.
        if self.assigned_object_type_id:
            label = f'{self.assigned_object_type.app_label}.{self.assigned_object_type.model}'
            permitted = assignable_model_labels()
            if label not in permitted:
                raise ValidationError({
                    'assigned_object_type': _(
                        'Credentials may not be assigned to {label}. Permitted types: {permitted}.'
                    ).format(label=label, permitted=', '.join(permitted) or _('none configured')),
                })
