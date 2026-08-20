"""
Forms.

Secret inputs use widgets with `render_value=False`, so a validation error
re-renders the form with the material *cleared* rather than echoed back into
the HTML. An echoed private key would land in the browser's back/forward cache
and in any HTML the user saves or screenshots.

The material never becomes a form field bound to the model instance either: it
is collected into a payload dict in `clean()` and handed to the service layer,
which passes it to the backend and drops it.
"""

from django import forms
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from netbox.context import current_request
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm, OrganizationalModelForm, PrimaryModelForm
from users.models import Group
from utilities.exceptions import AbortRequest
from utilities.forms import GenericObjectFormMixin
from utilities.forms.fields import CommentField, DynamicModelChoiceField, DynamicModelMultipleChoiceField, SlugField
from utilities.forms.fields.generic import GenericObjectChoiceField
from utilities.forms.rendering import FieldSet

from .backends.exceptions import OpenBaoError
from .choices import (
    AuthMethodChoices,
    CredentialStatusChoices,
    CredentialTypeChoices,
    EngineStatusChoices,
    PurposeChoices,
    SSHKeyTypeChoices,
)
from .config import get_config
from .models import Credential, CredentialAssignment, CredentialPolicy, SecretEngine
from .secrets.generators import generate_ssh_keypair
from .secrets.registry import get_schema
from .services import stage_material, store_credential
from .utils import assignable_content_types, get_default_engine

__all__ = (
    'CredentialAssignmentFilterForm',
    'CredentialAssignmentForm',
    'CredentialFilterForm',
    'CredentialForm',
    'CredentialPolicyFilterForm',
    'CredentialPolicyForm',
    'SecretEngineFilterForm',
    'SecretEngineForm',
)

# Every payload key any built-in credential type accepts. The form offers all
# of them and the type's schema decides which are required or permitted, so
# adding a type does not mean adding a form.
SECRET_INPUT_FIELDS = (
    'password', 'token', 'private_key', 'passphrase', 'public_key', 'certificate', 'chain',
    'auth_password', 'priv_password', 'auth_protocol', 'priv_protocol', 'preshared_key',
)

# Fields whose contents are secret and must never be re-rendered.
SENSITIVE_INPUT_FIELDS = frozenset({
    'password', 'token', 'private_key', 'passphrase', 'auth_password', 'priv_password', 'preshared_key',
})


class SecretEngineForm(PrimaryModelForm):
    slug = SlugField()
    comments = CommentField()

    fieldsets = (
        FieldSet('name', 'slug', 'api_url', 'namespace', 'is_default', 'description', name=_('Engine')),
        FieldSet('kv_mount', 'kv_version', name=_('Key/value mount')),
        FieldSet('auth_method', 'tls_verify', 'ca_cert_path', name=_('Authentication')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = SecretEngine
        fields = (
            'name', 'slug', 'api_url', 'namespace', 'kv_mount', 'kv_version', 'auth_method', 'tls_verify',
            'ca_cert_path', 'is_default', 'description', 'comments', 'tags',
        )
        help_texts = {
            'tls_verify': _(
                'Leave enabled. With verification off, every secret this engine serves is exposed to '
                'anyone who can intercept the connection.'
            ),
        }


class SecretEngineFilterForm(NetBoxModelFilterSetForm):
    model = SecretEngine
    auth_method = forms.MultipleChoiceField(choices=AuthMethodChoices, required=False)
    status = forms.MultipleChoiceField(choices=EngineStatusChoices, required=False)
    tls_verify = forms.NullBooleanField(required=False)
    is_default = forms.NullBooleanField(required=False)


class CredentialPolicyForm(OrganizationalModelForm):
    slug = SlugField()
    engine = DynamicModelChoiceField(queryset=SecretEngine.objects.all())
    groups = DynamicModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        label=_('Groups'),
    )

    fieldsets = (
        FieldSet('name', 'slug', 'engine', 'openbao_policy', 'description', name=_('Policy')),
        FieldSet('approle_env_prefix', 'groups', name=_('Authorization')),
        FieldSet('max_reveal_ttl', 'require_reason', name=_('Reveal controls')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = CredentialPolicy
        fields = (
            'name', 'slug', 'engine', 'openbao_policy', 'approle_env_prefix', 'groups', 'max_reveal_ttl',
            'require_reason', 'description', 'tags',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-select the engine marked as default on a new policy. This is what
        # gives SecretEngine.is_default an effect beyond being a label.
        if not self.instance.pk and not self.initial.get('engine'):
            if (default := get_default_engine()) is not None:
                self.initial['engine'] = default.pk


class CredentialPolicyFilterForm(NetBoxModelFilterSetForm):
    model = CredentialPolicy
    engine_id = DynamicModelMultipleChoiceField(
        queryset=SecretEngine.objects.all(),
        required=False,
        label=_('Engine'),
    )
    require_reason = forms.NullBooleanField(required=False)


class CredentialForm(PrimaryModelForm):
    """
    Create or update a credential together with its material.

    Material is collected from the `SECRET_INPUT_FIELDS` below, validated
    against the credential type's schema, and handed to the service layer. It
    is never assigned to `self.instance`.
    """

    policy = DynamicModelChoiceField(queryset=CredentialPolicy.objects.all())
    engine = DynamicModelChoiceField(
        queryset=SecretEngine.objects.all(),
        required=False,
        help_text=_("Defaults to the policy's engine."),
    )
    comments = CommentField()

    stage_rotation = forms.BooleanField(
        required=False,
        label=_('Stage this change instead of applying it now'),
        help_text=_(
            'Writes the new material alongside the current version and leaves consumers on the '
            'existing one until you promote it.'
        ),
    )
    generate_key = forms.BooleanField(
        required=False,
        label=_('Generate a new keypair'),
        help_text=_('Generate the private key server-side instead of supplying one'),
    )
    generate_key_type = forms.ChoiceField(
        choices=SSHKeyTypeChoices,
        required=False,
        label=_('Generated key type'),
    )

    fieldsets = (
        FieldSet('name', 'credential_type', 'policy', 'engine', 'username', 'description', name=_('Credential')),
        FieldSet('generate_key', 'generate_key_type', name=_('Generation')),
        FieldSet('stage_rotation', name=_('Rotation')),
        FieldSet(*SECRET_INPUT_FIELDS, name=_('Secret material')),
        FieldSet('status', 'rotation_interval', name=_('Lifecycle')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = Credential
        fields = (
            'name', 'credential_type', 'policy', 'engine', 'username', 'status', 'rotation_interval',
            'description', 'comments', 'tags',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for name in SECRET_INPUT_FIELDS:
            if name in SENSITIVE_INPUT_FIELDS:
                # render_value=False: on a validation error the browser gets an
                # empty box, not the key the user just pasted.
                widget = (
                    forms.Textarea(attrs={'rows': 6, 'autocomplete': 'off'})
                    if name in ('private_key',)
                    else forms.PasswordInput(render_value=False, attrs={'autocomplete': 'new-password'})
                )
            else:
                widget = forms.Textarea(attrs={'rows': 4}) if name in ('certificate', 'chain', 'public_key') \
                    else forms.TextInput()
            self.fields[name] = forms.CharField(
                required=False,
                widget=widget,
                label=name.replace('_', ' ').capitalize(),
            )

        self.fields['generate_key_type'].initial = get_config('default_ssh_key_type')

        # Staging only means anything for a credential that already has live
        # material to protect.
        if self.instance.pk is None:
            del self.fields['stage_rotation']
        if not get_config('allow_generation', True):
            del self.fields['generate_key']
            del self.fields['generate_key_type']

        # Material is optional on edit: updating a name or a tag should not
        # require re-supplying the private key.
        self._material_required = self.instance.pk is None

    def clean(self):
        # NetBox's form chain can return None from clean(); NetBox's own
        # GenericObjectFormMixin guards the same way.
        cleaned = super().clean()
        if cleaned is None:
            cleaned = self.cleaned_data
        credential_type = cleaned.get('credential_type')
        if not credential_type:
            return cleaned

        payload = {
            name: value for name in SECRET_INPUT_FIELDS
            if (value := (cleaned.get(name) or '').strip())
        }

        if cleaned.get('generate_key'):
            if credential_type != CredentialTypeChoices.TYPE_SSH_KEYPAIR:
                raise forms.ValidationError({
                    'generate_key': _('Key generation is only supported for SSH keypairs.'),
                })
            if payload.get('private_key'):
                raise forms.ValidationError({
                    'private_key': _('Supply a private key or generate one, not both.'),
                })
            payload.update(generate_ssh_keypair(cleaned.get('generate_key_type')))

        if payload:
            schema = get_schema(credential_type)
            unknown = sorted(set(payload) - set(schema['vault_fields']))
            if unknown and not schema.get('allow_arbitrary_keys'):
                raise forms.ValidationError({
                    field: _('Not accepted for this credential type.') for field in unknown
                })
        elif self._material_required:
            raise forms.ValidationError(
                _('Secret material is required when creating a credential.')
            )

        # Held for save(); deliberately never attached to self.instance.
        self.secret_payload = payload or None
        return cleaned

    def save(self, *args, **kwargs):
        """
        Persist the row and the material together.

        Hooked here rather than in the view because NetBox's `ObjectEditView`
        already wraps `form.save()` in `transaction.atomic()` — so the row and
        the backend write share one transaction without the view having to be
        reimplemented. An earlier version overrode the view's `post()` instead
        and silently dropped `restrict_form_fields()`, `snapshot()`, and
        `alter_object()` along with it.

        Backend failures become `AbortRequest`, which NetBox renders as a form
        error rather than a 500.
        """
        payload = getattr(self, 'secret_payload', None)
        if not payload:
            return super().save(*args, **kwargs)

        request = current_request.get()
        user = getattr(request, 'user', None) if request else None

        if self.cleaned_data.get('stage_rotation') and self.instance.pk:
            # Save the non-secret edits first, then stage the material. The two
            # are separate on purpose: staging must not silently also promote
            # whatever else the operator changed on the form.
            instance = super().save(*args, **kwargs)
            try:
                stage_material(instance, payload, user=user, request=request)
            except OpenBaoError as exc:
                raise AbortRequest(str(exc)) from None
            except DjangoValidationError as exc:
                raise AbortRequest('; '.join(exc.messages)) from None
            return instance

        def persist(metadata):
            for field, value in metadata.items():
                setattr(self.instance, field, value)
            return super(CredentialForm, self).save(*args, **kwargs)

        try:
            credential, _version = store_credential(
                persist,
                self.cleaned_data['credential_type'],
                payload,
                # A new credential must not overwrite anything already at its
                # path; an edit checks against the version we believe is live.
                cas=self.instance.kv_version if self.instance.pk else 0,
                user=user,
                request=request,
                subject=self.instance,
            )
        except OpenBaoError as exc:
            raise AbortRequest(str(exc)) from None
        return credential


class CredentialFilterForm(NetBoxModelFilterSetForm):
    model = Credential
    credential_type = forms.MultipleChoiceField(choices=CredentialTypeChoices, required=False)
    status = forms.MultipleChoiceField(choices=CredentialStatusChoices, required=False)
    policy_id = DynamicModelMultipleChoiceField(
        queryset=CredentialPolicy.objects.all(),
        required=False,
        label=_('Policy'),
    )
    engine_id = DynamicModelMultipleChoiceField(
        queryset=SecretEngine.objects.all(),
        required=False,
        label=_('Engine'),
    )
    expires_within_days = forms.IntegerField(
        required=False,
        min_value=0,
        label=_('Expires within (days)'),
    )
    has_expiry = forms.NullBooleanField(required=False, label=_('Has an expiry date'))


class CredentialAssignmentForm(GenericObjectFormMixin, NetBoxModelForm):
    """
    Assign a credential to an object.

    Uses 4.7's `GenericObjectChoiceField`, which renders the content-type
    selector and the API-backed object selector as one field and re-renders
    the object selector over HTMX when the type changes.
    """

    credential = DynamicModelChoiceField(queryset=Credential.objects.all())
    assigned_object = GenericObjectChoiceField(
        content_type_queryset=ContentType.objects.none(),
        label=_('Object'),
        selector=True,
        hx_target_id='assignment',
    )

    fieldsets = (
        FieldSet('credential', 'assigned_object', 'purpose', 'is_primary', 'description',
                 name=_('Assignment'), html_id='assignment'),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = CredentialAssignment
        fields = ('credential', 'purpose', 'is_primary', 'description', 'tags')

    def __init__(self, *args, **kwargs):
        # Evaluated per-instantiation so a change to `assignable_models` in
        # PLUGINS_CONFIG takes effect on restart without a code change.
        self.base_fields['assigned_object'].content_type_queryset = assignable_content_types()
        super().__init__(*args, **kwargs)


class CredentialAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = CredentialAssignment
    credential_id = DynamicModelMultipleChoiceField(
        queryset=Credential.objects.all(),
        required=False,
        label=_('Credential'),
    )
    purpose = forms.MultipleChoiceField(choices=PurposeChoices, required=False)
    is_primary = forms.NullBooleanField(required=False)
