from django.utils.translation import gettext_lazy as _
from utilities.choices import Choice, ChoiceSet


class AuthMethodChoices(ChoiceSet):
    """How the plugin authenticates to an OpenBao instance."""

    METHOD_APPROLE = 'approle'
    METHOD_KUBERNETES = 'kubernetes'
    METHOD_CERT = 'cert'
    METHOD_TOKEN = 'token'

    CHOICES = [
        Choice(METHOD_APPROLE, _('AppRole'), description=_('RoleID/SecretID delivered via environment')),
        Choice(METHOD_KUBERNETES, _('Kubernetes'), description=_('Service account token from the pod filesystem')),
        Choice(METHOD_CERT, _('TLS certificate'), description=_('Mutual TLS client certificate')),
        Choice(METHOD_TOKEN, _('Token'), description=_('Static token from the environment; development only')),
    ]


class EngineStatusChoices(ChoiceSet):
    """Observed health of an engine. Set by EngineHealthJob, never by a user."""

    STATUS_UNKNOWN = 'unknown'
    STATUS_HEALTHY = 'healthy'
    STATUS_SEALED = 'sealed'
    STATUS_STANDBY = 'standby'
    STATUS_UNREACHABLE = 'unreachable'
    STATUS_UNAUTHORIZED = 'unauthorized'

    CHOICES = [
        Choice(STATUS_UNKNOWN, _('Unknown'), color='gray', description=_('Not yet checked')),
        Choice(STATUS_HEALTHY, _('Healthy'), color='green', description=_('Initialized, unsealed, and active')),
        Choice(STATUS_SEALED, _('Sealed'), color='red', description=_('Reachable but sealed')),
        Choice(STATUS_STANDBY, _('Standby'), color='cyan', description=_('Unsealed standby node')),
        Choice(STATUS_UNREACHABLE, _('Unreachable'), color='red', description=_('Network or TLS failure')),
        Choice(STATUS_UNAUTHORIZED, _('Unauthorized'), color='orange', description=_('Authentication rejected')),
    ]


class CredentialTypeChoices(ChoiceSet):
    """
    Credential shape. Determines which payload fields are accepted and which
    non-secret attributes are extracted into NetBox at write time.
    """

    key = 'Credential.credential_type'

    TYPE_PASSWORD = 'password'
    TYPE_SSH_KEYPAIR = 'ssh-keypair'
    TYPE_SSH_PASSWORD = 'ssh-password'
    TYPE_API_TOKEN = 'api-token'
    TYPE_X509_KEYPAIR = 'x509-keypair'
    TYPE_X509_CA = 'x509-ca'
    TYPE_SNMP_V3 = 'snmp-v3'
    TYPE_WIREGUARD = 'wireguard'
    TYPE_GENERIC_KV = 'generic-kv'

    CHOICES = [
        Choice(TYPE_PASSWORD, _('Password'), color='blue'),
        Choice(TYPE_SSH_KEYPAIR, _('SSH keypair'), color='green'),
        Choice(TYPE_SSH_PASSWORD, _('SSH password'), color='teal'),
        Choice(TYPE_API_TOKEN, _('API token'), color='purple'),
        Choice(TYPE_X509_KEYPAIR, _('X.509 keypair'), color='orange'),
        Choice(TYPE_X509_CA, _('X.509 CA'), color='red'),
        Choice(TYPE_SNMP_V3, _('SNMPv3'), color='cyan'),
        Choice(TYPE_WIREGUARD, _('WireGuard'), color='indigo'),
        Choice(TYPE_GENERIC_KV, _('Generic key/value'), color='gray'),
    ]


class CredentialStatusChoices(ChoiceSet):
    """Lifecycle state. `staged` and `rotating` support break-free rotation."""

    key = 'Credential.status'

    STATUS_ACTIVE = 'active'
    STATUS_STAGED = 'staged'
    STATUS_ROTATING = 'rotating'
    STATUS_EXPIRED = 'expired'
    STATUS_RETIRED = 'retired'
    STATUS_COMPROMISED = 'compromised'

    CHOICES = [
        Choice(STATUS_ACTIVE, _('Active'), color='green', description=_('In service')),
        Choice(STATUS_STAGED, _('Staged'), color='blue', description=_('Written but not yet promoted')),
        Choice(STATUS_ROTATING, _('Rotating'), color='cyan', description=_('Replacement in progress')),
        Choice(STATUS_EXPIRED, _('Expired'), color='orange', description=_('Past its validity window')),
        Choice(STATUS_RETIRED, _('Retired'), color='gray', description=_('Withdrawn from service')),
        Choice(STATUS_COMPROMISED, _('Compromised'), color='red', description=_('Known disclosed; rotate now')),
    ]


class PurposeChoices(ChoiceSet):
    """What an assignment's credential is used *for* on the target object."""

    key = 'CredentialAssignment.purpose'

    PURPOSE_LOGIN = 'login'
    PURPOSE_ENABLE = 'enable'
    PURPOSE_CONSOLE = 'console'
    PURPOSE_OOB = 'oob'
    PURPOSE_API = 'api'
    PURPOSE_AGENT = 'agent'
    PURPOSE_BACKUP = 'backup'

    CHOICES = [
        Choice(PURPOSE_LOGIN, _('Login')),
        Choice(PURPOSE_ENABLE, _('Enable/privileged')),
        Choice(PURPOSE_CONSOLE, _('Console')),
        Choice(PURPOSE_OOB, _('Out-of-band')),
        Choice(PURPOSE_API, _('API')),
        Choice(PURPOSE_AGENT, _('Agent')),
        Choice(PURPOSE_BACKUP, _('Backup')),
    ]


class AccessActionChoices(ChoiceSet):
    """Audited actions. Never records the value, only that it happened."""

    ACTION_REVEAL = 'reveal'
    ACTION_WRITE = 'write'
    ACTION_ROTATE = 'rotate'
    ACTION_STAGE = 'stage'
    ACTION_PROMOTE = 'promote'
    ACTION_DISCARD = 'discard'
    ACTION_DELETE = 'delete'

    CHOICES = [
        Choice(ACTION_REVEAL, _('Reveal'), color='orange'),
        Choice(ACTION_WRITE, _('Write'), color='blue'),
        Choice(ACTION_ROTATE, _('Rotate'), color='cyan'),
        Choice(ACTION_STAGE, _('Stage'), color='blue'),
        Choice(ACTION_PROMOTE, _('Promote'), color='green'),
        Choice(ACTION_DISCARD, _('Discard'), color='gray'),
        Choice(ACTION_DELETE, _('Delete'), color='red'),
    ]


class SSHKeyTypeChoices(ChoiceSet):
    """Key types the plugin can generate server-side."""

    TYPE_ED25519 = 'ed25519'
    TYPE_RSA_4096 = 'rsa-4096'
    TYPE_ECDSA_P256 = 'ecdsa-p256'

    CHOICES = [
        Choice(TYPE_ED25519, _('Ed25519')),
        Choice(TYPE_RSA_4096, _('RSA 4096')),
        Choice(TYPE_ECDSA_P256, _('ECDSA P-256')),
    ]
