"""
Non-secret metadata extraction.

Every function here is handed plaintext secret material and returns only
attributes that are safe to store in NetBox and render in a template: public
keys, fingerprints, key types, certificate subjects, validity windows.

Extraction runs **once, at write time**. The plaintext exists in the local
scope of the calling request handler, is never assigned to a model field, and
is discarded before the response is rendered. Metadata is persisted; the
material is not.

None of these functions log, and none embed the input in an exception message
— a `ValidationError` carrying a fragment of a private key would end up in a
DRF error payload and in the request log.
"""

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

__all__ = (
    'extract_certificate_metadata',
    'extract_ssh_metadata',
    'ssh_fingerprint',
)


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode()


def ssh_fingerprint(openssh_public_key):
    """
    Return the OpenSSH SHA256 fingerprint of an `ssh-...` public key line.

    OpenSSH hashes the base64-decoded key blob, not the textual line, so the
    result matches `ssh-keygen -lf` exactly.
    """
    parts = _as_bytes(openssh_public_key).split()
    if len(parts) < 2:
        raise ValidationError({'public_key': _('Value is not a valid OpenSSH public key.')})
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        raise ValidationError({'public_key': _('Value is not a valid OpenSSH public key.')})
    digest = hashlib.sha256(blob).digest()
    return 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')


def _ssh_key_type(public_key):
    """Return a human-readable key type, e.g. `ed25519` or `rsa-4096`."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return 'ed25519'
    if isinstance(public_key, rsa.RSAPublicKey):
        return f'rsa-{public_key.key_size}'
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f'ecdsa-{public_key.curve.name}'
    return type(public_key).__name__.replace('PublicKey', '').lower()


def extract_ssh_metadata(private_key_pem, passphrase=None):
    """
    Derive the public half of an SSH keypair.

    Returns `public_key`, `fingerprint`, and `key_type`. The private key is
    parsed, used, and dropped; nothing derived from it beyond the public key is
    retained.
    """
    material = _as_bytes(private_key_pem)
    password = _as_bytes(passphrase) if passphrase else None

    key = None
    for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
        try:
            key = loader(material, password=password)
            break
        except Exception:
            continue

    if key is None:
        raise ValidationError({
            'private_key': _('Unable to parse the private key. Supply an OpenSSH or PEM key, and a '
                             'passphrase if the key is encrypted.'),
        })

    public_key = key.public_key()
    try:
        openssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()
    except Exception:
        raise ValidationError({'private_key': _('Key type is not supported for SSH use.')})

    return {
        'public_key': openssh,
        'fingerprint': ssh_fingerprint(openssh),
        'key_type': _ssh_key_type(public_key),
    }


def extract_certificate_metadata(certificate_pem):
    """
    Derive identity and validity from an X.509 certificate.

    Everything returned here is public by definition — it is transmitted in
    the clear during every TLS handshake — which is what makes storing it in
    NetBox safe, and what makes "certificates expiring in 30 days" answerable
    without a single OpenBao read.
    """
    material = _as_bytes(certificate_pem)
    try:
        cert = x509.load_pem_x509_certificate(material)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(material)
        except Exception:
            raise ValidationError({'certificate': _('Unable to parse the certificate as PEM or DER.')})

    try:
        sans = [str(name.value) for name in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value]
    except x509.ExtensionNotFound:
        sans = []

    return {
        'cert_subject': cert.subject.rfc4514_string(),
        'cert_issuer': cert.issuer.rfc4514_string(),
        'cert_serial': format(cert.serial_number, 'x'),
        'valid_from': cert.not_valid_before_utc,
        'valid_until': cert.not_valid_after_utc,
        'fingerprint': 'SHA256:' + cert.fingerprint(hashes.SHA256()).hex(),
        'key_type': _ssh_key_type(cert.public_key()),
        'public_key': cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
        'subject_alternative_names': sans,
    }
