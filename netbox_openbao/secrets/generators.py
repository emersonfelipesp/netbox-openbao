"""
Server-side key generation.

Generation happens in the NetBox process, never in browser JavaScript and
never through OpenBao's SSH secrets engine. Both alternatives would put the
private key somewhere this plugin does not control at the moment it exists:
the browser would expose it to every extension on the page, and the SSH engine
would make OpenBao the issuer of a key NetBox is supposed to own the lifecycle
of.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from netbox_openbao.choices import SSHKeyTypeChoices

__all__ = ('generate_ssh_keypair',)


def generate_ssh_keypair(key_type=SSHKeyTypeChoices.TYPE_ED25519):
    """
    Generate an SSH keypair and return `{private_key, public_key}`.

    The private key is returned in OpenSSH PEM form, unencrypted, because it is
    handed straight to the backend write and discarded. Encrypting it here
    would only mean holding the passphrase in the same scope.
    """
    if key_type == SSHKeyTypeChoices.TYPE_ED25519:
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == SSHKeyTypeChoices.TYPE_RSA_4096:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif key_type == SSHKeyTypeChoices.TYPE_ECDSA_P256:
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValidationError({
            'key_type': _('Unsupported key type: {value}.').format(value=key_type),
        })

    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    return {
        'private_key': private_bytes.decode(),
        'public_key': public_bytes.decode(),
    }
