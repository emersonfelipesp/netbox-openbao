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

from dcim.models import Device
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from netbox.context import current_request
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm, OrganizationalModelForm, PrimaryModelForm
from users.models import Group
from utilities.exceptions import AbortRequest
from utilities.forms.fields import CommentField, DynamicModelChoiceField, DynamicModelMultipleChoiceField, SlugField
from utilities.forms.rendering import FieldSet

from netbox_openbao.compat import (
    HAS_GENERIC_OBJECT_FIELD,
    GenericObjectChoiceField,
    GenericObjectFormMixin,
)

from .backends.exceptions import OpenBaoError
from .choices import (
    AccessActionChoices,
    AuthMethodChoices,
    CredentialStatusChoices,
    CredentialTypeChoices,
    EngineStatusChoices,
    PurposeChoices,
    SSHKeyTypeChoices,
)
from .config import get_config
from .models import Credential, CredentialAssignment, CredentialPolicy, CredentialTypeSchema, SecretEngine
from .rpc import OPENBAO_READ_PROCEDURES, OPENBAO_WRITE_PROCEDURES
from .secrets.generators import generate_ssh_keypair
from .secrets.registry import credential_type_choices, get_schema
from .services import enforce_update_access, stage_material, store_credential
from .utils import assignable_content_types, get_default_engine

__all__ = (
    'CredentialAssignmentFilterForm',
    'CredentialAssignmentForm',
    'CredentialFilterForm',
    'CredentialForm',
    'CredentialPolicyFilterForm',
    'CredentialPolicyForm',
    'QuickAddSSHForm',
    'CredentialTypeSchemaForm',
    'SecretEngineFilterForm',
    'SecretEngineForm',
    'RunProcedureForm',
    'OpenBaoProcedureRunFilterForm',
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
    host_device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_('OpenBao host'),
        help_text=_('Device where OpenBao runs. Required for netbox-rpc host operations.'),
    )

    fieldsets = (
        FieldSet('name', 'slug', 'backend', 'api_url', 'namespace', 'host_device', 'is_default', 'description',
                 name=_('Engine')),
        FieldSet('kv_mount', 'kv_version', name=_('Key/value mount')),
        FieldSet('auth_method', 'tls_verify', 'ca_cert_path', name=_('Authentication')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = SecretEngine
        fields = (
            'name', 'slug', 'backend', 'api_url', 'namespace', 'host_device', 'kv_mount', 'kv_version', 'auth_method',
            'tls_verify', 'ca_cert_path', 'is_default', 'description', 'comments', 'tags',
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


class RunProcedureForm(forms.Form):
    procedure_name = forms.ChoiceField(
        label=_('Procedure'),
        choices=[
            (name, name.removeprefix('service.openbao.1.'))
            for name in sorted(OPENBAO_READ_PROCEDURES | OPENBAO_WRITE_PROCEDURES)
        ],
    )
    restart_netbox = forms.BooleanField(
        label=_('Restart NetBox services after provisioning'),
        required=False,
        initial=True,
        help_text=_(
            'AppRole provisioning writes new credentials; running NetBox processes need a restart to load them.'
        ),
    )


class OpenBaoProcedureRunFilterForm(NetBoxModelFilterSetForm):
    model = None

    def __init__(self, *args, **kwargs):
        from .models import OpenBaoProcedureRun

        kwargs.setdefault('model', OpenBaoProcedureRun)
        super().__init__(*args, **kwargs)
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

        # Built-in types plus every operator-defined one, resolved per
        # instantiation so a new schema shows up without a restart.
        self.fields['credential_type'].choices = credential_type_choices()
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
        request = current_request.get()
        user = getattr(request, 'user', None) if request else None
        payload = getattr(self, 'secret_payload', None)

        # Captured before super().save() assigns a primary key.
        is_create = self.instance.pk is None

        if not is_create:
            # Gate every edit of an existing credential against the tier it is
            # on *now*. Not only the material-bearing ones: `policy` is an
            # editable field, so an edit that changes nothing else could
            # otherwise move a credential to a tier the operator is in and make
            # it revealable to them. `self.instance` is no help here —
            # ModelForm._post_clean() has already written cleaned_data onto it
            # — so the committed row is re-read; see enforce_update_access.
            #
            # Raised as AbortRequest rather than PermissionDenied so
            # ObjectEditView renders it as a form error, the way a backend
            # failure already is, instead of replacing a half-completed edit
            # with Django's bare 403 page.
            try:
                enforce_update_access(
                    self.instance, user, AccessActionChoices.ACTION_WRITE, request=request,
                )
            except PermissionDenied as exc:
                raise AbortRequest(str(exc)) from None

            # An edit carrying material is a rotation whatever the form calls
            # it, so it needs `rotate_credential` and not merely `change`.
            # Covers both branches below, including the staged one. Resolved
            # with restrict() so ObjectPermission constraints apply, and
            # against the committed row for the same reason as above.
            if payload and not Credential.objects.restrict(user, 'rotate').filter(
                pk=self.instance.pk
            ).exists():
                raise AbortRequest(
                    'Replacing secret material requires the rotate permission on this credential.'
                )

        if not payload:
            return super().save(*args, **kwargs)

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
            saved = super(CredentialForm, self).save(*args, **kwargs)

            # NetBox's ObjectEditView performs this same check *after*
            # form.save() returns, and raises PermissionsViolation — which
            # rolls the row back while leaving the OpenBao write stranded,
            # because by then `store_credential` has already returned and its
            # compensator will never run. Doing it here puts it inside the
            # compensated region.
            #
            # Which permissions the *result* must satisfy. A create is governed
            # by `add` — supplying the initial material is part of creating the
            # credential, which is why `rotate` is not required there and is
            # not required by the REST create either. An edit that replaces
            # material is a rotation, and the destination is checked as well as
            # the source: moving a credential into a tier the operator may not
            # rotate would otherwise write the new material through that tier.
            actions = ('add',) if is_create else ('change', 'rotate')
            for action in actions:
                if not Credential.objects.restrict(user, action).filter(pk=saved.pk).exists():
                    raise AbortRequest(
                        'You do not have permission to leave this credential in that state. '
                        f'The {action} permission does not cover the result of this '
                        f'{"creation" if is_create else "edit"}.'
                    )
            return saved

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
    credential_type = forms.MultipleChoiceField(choices=[], required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['credential_type'].choices = credential_type_choices()
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

    On 4.7 this is one field: `GenericObjectChoiceField` renders the
    content-type selector and the API-backed object selector together and
    re-renders the object half over HTMX when the type changes.

    4.6 has no such field, so it declares the two halves separately and binds
    them in `clean()`. The result is the same assignment; what is lost is the
    HTMX re-render, so the object selector on 4.6 lists every object of the
    chosen type rather than narrowing as you pick. That is a worse form, not a
    different outcome, and it is confined to this class.
    """

    credential = DynamicModelChoiceField(queryset=Credential.objects.all())

    if HAS_GENERIC_OBJECT_FIELD:
        assigned_object = GenericObjectChoiceField(
            content_type_queryset=ContentType.objects.none(),
            label=_('Object'),
            selector=True,
            hx_target_id='assignment',
        )
    else:
        assigned_object_type = forms.ModelChoiceField(
            queryset=ContentType.objects.none(),
            label=_('Object type'),
        )
        assigned_object_id = forms.IntegerField(
            label=_('Object ID'),
            help_text=_('Numeric ID of the object this credential belongs to.'),
        )

    _OBJECT_FIELDS = (
        ('assigned_object',) if HAS_GENERIC_OBJECT_FIELD
        else ('assigned_object_type', 'assigned_object_id')
    )

    # `html_id` is 4.7-only, and it exists solely to give the HTMX re-render a
    # target — so it is conditional on exactly the same thing the field is.
    # There is nothing on 4.6 for it to address.
    _ASSIGNMENT_FIELDSET_KWARGS = {'html_id': 'assignment'} if HAS_GENERIC_OBJECT_FIELD else {}

    fieldsets = (
        FieldSet('credential', *_OBJECT_FIELDS, 'purpose', 'is_primary', 'description',
                 name=_('Assignment'), **_ASSIGNMENT_FIELDSET_KWARGS),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = CredentialAssignment
        fields = ('credential', 'purpose', 'is_primary', 'description', 'tags')

    def __init__(self, *args, **kwargs):
        # Evaluated per-instantiation so a saved settings change takes effect
        # immediately rather than freezing the allowlist at module import.
        if HAS_GENERIC_OBJECT_FIELD:
            self.base_fields['assigned_object'].content_type_queryset = assignable_content_types()
        else:
            self.base_fields['assigned_object_type'].queryset = assignable_content_types()
        super().__init__(*args, **kwargs)

        if not HAS_GENERIC_OBJECT_FIELD and self.instance.pk:
            self.fields['assigned_object_type'].initial = self.instance.assigned_object_type_id
            self.fields['assigned_object_id'].initial = self.instance.assigned_object_id

    def clean(self):
        """Bind the two 4.6 halves onto the instance, and reject a dangling ID.

        The type queryset already enforces `assignable_models`; what it cannot
        check is that the *object* exists. Without this, a typo'd ID would
        create an assignment pointing at nothing — which the reveal path would
        later fail on, a long way from the form that accepted it.
        """
        cleaned = super().clean()
        if HAS_GENERIC_OBJECT_FIELD:
            return cleaned

        object_type = cleaned.get('assigned_object_type')
        object_id = cleaned.get('assigned_object_id')
        if not object_type or object_id is None:
            return cleaned

        model = object_type.model_class()
        if model is None or not model.objects.filter(pk=object_id).exists():
            raise forms.ValidationError({
                'assigned_object_id': _(
                    'No %(model)s with ID %(pk)s exists.'
                ) % {'model': object_type.name, 'pk': object_id},
            })

        self.instance.assigned_object_type = object_type
        self.instance.assigned_object_id = object_id
        return cleaned


class CredentialAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = CredentialAssignment
    credential_id = DynamicModelMultipleChoiceField(
        queryset=Credential.objects.all(),
        required=False,
        label=_('Credential'),
    )
    purpose = forms.MultipleChoiceField(choices=PurposeChoices, required=False)
    is_primary = forms.NullBooleanField(required=False)


class QuickAddSSHForm(forms.Form):
    """
    Give a device or VM SSH access in one form.

    Not a ModelForm: it creates three objects, so there is no single instance
    to bind to. Secret inputs reuse the same `render_value=False` discipline as
    `CredentialForm` — a rejected form must not echo the key back into the
    page.
    """

    name = forms.CharField(
        required=False,
        label=_('Credential name'),
        help_text=_('Defaults to "<object> ssh".'),
    )
    username = forms.CharField(label=_('Username'))
    policy = DynamicModelChoiceField(queryset=CredentialPolicy.objects.all(), label=_('Policy'))

    create_service = forms.BooleanField(
        required=False,
        initial=True,
        label=_('Create or update an SSH service'),
    )
    port = forms.IntegerField(initial=22, min_value=1, max_value=65535, label=_('Port'))

    source = forms.ChoiceField(
        label=_('Key material'),
        choices=(
            ('generate', _('Generate a new keypair')),
            ('paste', _('Paste an existing private key')),
            ('reuse', _('Reuse an existing credential')),
        ),
        initial='generate',
        required=False,
    )
    auth_method = forms.ChoiceField(
        label=_('Authentication'),
        choices=(
            ('password', _('Username and password')),
            ('keypair', _('SSH keypair')),
        ),
        initial='password',
    )
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={'autocomplete': 'new-password'}),
        label=_('SSH login password'),
        help_text=_('Stored in OpenBao. This is the password used to log in, not a key passphrase.'),
    )
    key_type = forms.ChoiceField(choices=SSHKeyTypeChoices, required=False, label=_('Generated key type'))
    private_key = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 6, 'autocomplete': 'off'}),
        label=_('Private key'),
    )
    passphrase = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={'autocomplete': 'new-password'}),
        label=_('Passphrase'),
    )
    existing_credential = DynamicModelChoiceField(
        queryset=Credential.objects.all(),
        required=False,
        label=_('Existing credential'),
        query_params={'credential_type': 'ssh-keypair'},
    )

    fieldsets = (
        FieldSet('name', 'username', 'policy', name=_('Credential')),
        FieldSet('create_service', 'port', name=_('Service')),
        FieldSet('auth_method', 'password', name=_('Authentication')),
        FieldSet('source', 'key_type', 'private_key', 'passphrase', 'existing_credential',
                 name=_('Key material')),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['key_type'].initial = get_config('default_ssh_key_type')
        if not get_config('allow_generation', True):
            self.fields['source'].choices = [
                choice for choice in self.fields['source'].choices if choice[0] != 'generate'
            ]
            self.fields['source'].initial = 'paste'

    def clean(self):
        cleaned = super().clean()
        if cleaned is None:
            cleaned = self.cleaned_data

        source = cleaned.get('source')
        auth_method = cleaned.get('auth_method') or 'keypair'
        if auth_method == 'password':
            if not cleaned.get('password'):
                raise forms.ValidationError({'password': _('Enter the SSH login password.')})
            return cleaned
        if source == 'paste' and not cleaned.get('private_key'):
            raise forms.ValidationError({'private_key': _('Paste a private key, or choose another source.')})
        if source == 'reuse' and not cleaned.get('existing_credential'):
            raise forms.ValidationError({
                'existing_credential': _('Choose a credential, or choose another source.'),
            })
        if source == 'generate' and not get_config('allow_generation', True):
            raise forms.ValidationError({'source': _('Key generation is disabled on this installation.')})
        return cleaned
class CredentialTypeSchemaForm(NetBoxModelForm):
    """
    Define a credential type as data.

    `extractor` is rendered as a select over a fixed registry rather than a
    free-text field. That is the point of the design: it is a name chosen from
    a vetted list, never a path that could resolve to arbitrary code.
    """

    slug = SlugField()

    fieldsets = (
        FieldSet('name', 'slug', 'description', name=_('Type')),
        FieldSet('schema', 'secret_fields', 'extractor', name=_('Payload')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = CredentialTypeSchema
        fields = ('name', 'slug', 'description', 'schema', 'secret_fields', 'extractor', 'tags')
        help_texts = {
            'secret_fields': _(
                'Which properties hold secret material. Anything omitted may be mirrored into a '
                'NetBox column, so an omission here is a disclosure rather than a cosmetic slip.'
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .secrets.registry import EXTRACTORS

        self.fields['extractor'] = forms.ChoiceField(
            required=False,
            choices=[('', '---------')] + [(name, name) for name in sorted(EXTRACTORS)],
            label=_('Extractor'),
            help_text=_('Chosen from a fixed list. This is a name, never a path to code.'),
        )
