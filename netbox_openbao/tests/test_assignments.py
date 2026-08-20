from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.test import override_settings

from netbox_openbao.choices import PurposeChoices
from netbox_openbao.models import CredentialAssignment

from .base import OpenBaoTestCase


class AssignmentTest(OpenBaoTestCase):

    def setUp(self):
        super().setUp()
        site = Site.objects.create(name='Site 1', slug='site-1')
        manufacturer = Manufacturer.objects.create(name='Acme', slug='acme')
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer, model='Switch', slug='switch',
        )
        role = DeviceRole.objects.create(name='Access', slug='access')
        self.device = Device.objects.create(
            name='core-sw-01', site=site, device_type=device_type, role=role,
        )
        self.device_ct = ContentType.objects.get_for_model(Device)

        self.credential = self.make_credential()
        self.credential.save()

    def _assignment(self, **kwargs):
        kwargs.setdefault('credential', self.credential)
        kwargs.setdefault('assigned_object_type', self.device_ct)
        kwargs.setdefault('assigned_object_id', self.device.pk)
        return CredentialAssignment(**kwargs)

    def test_assignment_to_permitted_type(self):
        assignment = self._assignment()
        assignment.full_clean()
        assignment.save()
        self.assertEqual(assignment.assigned_object, self.device)

    @override_settings(PLUGINS_CONFIG={'netbox_openbao': {'assignable_models': ['ipam.service']}})
    def test_assignment_to_forbidden_type_is_rejected(self):
        """
        The allowlist is enforced on the model, not only the form, so the REST
        API and direct ORM callers are held to the same list.
        """
        assignment = self._assignment()
        with self.assertRaises(ValidationError) as ctx:
            assignment.full_clean()
        self.assertIn('assigned_object_type', ctx.exception.message_dict)

    def test_duplicate_assignment_is_rejected(self):
        self._assignment().save()
        with self.assertRaises(IntegrityError):
            self._assignment().save()

    def test_same_credential_different_purpose_is_allowed(self):
        self._assignment(purpose=PurposeChoices.PURPOSE_LOGIN).save()
        second = self._assignment(purpose=PurposeChoices.PURPOSE_ENABLE)
        second.save()
        self.assertEqual(CredentialAssignment.objects.count(), 2)

    def test_only_one_primary_per_object_and_purpose(self):
        """
        "Which credential does automation use here?" must have exactly one
        answer.
        """
        self._assignment(is_primary=True).save()

        other = self.make_credential(name='second-credential')
        other.save()
        with self.assertRaises(IntegrityError):
            CredentialAssignment(
                credential=other,
                assigned_object_type=self.device_ct,
                assigned_object_id=self.device.pk,
                purpose=PurposeChoices.PURPOSE_LOGIN,
                is_primary=True,
            ).save()
