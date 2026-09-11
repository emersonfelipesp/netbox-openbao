"""Version-bound public SSH identity, independent of optional public display."""

from __future__ import annotations

import hmac
import re
from typing import Any

from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends.exceptions import OpenBaoError

from .extractors import extract_ssh_metadata
from .registry import get_schema


def uses_ssh_identity(credential_type: str) -> bool:
    return get_schema(credential_type).get('extractor') == 'ssh'


@sensitive_variables()
def derive_key_fingerprint(credential_type: str, payload: dict) -> str:
    """Retain only the public-key fingerprint, never private-material hashes."""
    if not uses_ssh_identity(credential_type):
        return ''
    return extract_ssh_metadata(payload.get('private_key', ''), payload.get('passphrase'))['fingerprint']


def live_key_fingerprint(credential: Any, schema: dict | None = None) -> str:
    """Legacy or mismatched identity cannot authorize a metadata-only reveal."""
    schema = schema if schema is not None else get_schema(credential.credential_type)
    if schema.get('extractor') != 'ssh':
        return credential.fingerprint
    fingerprint = credential.live_key_fingerprint
    if credential.live_key_version != credential.live_kv_version or not re.fullmatch(
        r'SHA256:[A-Za-z0-9+/]{43}', fingerprint,
    ):
        raise OpenBaoError('The live credential identity is not verified.')
    return fingerprint


@sensitive_variables()
def verify_bundle_identity(credential: Any, payload: dict, expected_fingerprint: str | None) -> None:
    frozen_ssh_identity = bool(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', expected_fingerprint or ''))
    if not frozen_ssh_identity and not uses_ssh_identity(credential.credential_type):
        return
    try:
        # The approved identity, not a mutable extractor selector, determines
        # whether this private-key bundle must be verified.
        actual = extract_ssh_metadata(payload.get('private_key', ''), payload.get('passphrase'))['fingerprint']
        if not expected_fingerprint or not hmac.compare_digest(actual, expected_fingerprint):
            raise ValueError
    except Exception:
        raise OpenBaoError('The credential bundle identity does not match its authorization.') from None


def record_key_version(credential: Any, fingerprint: str, version: int, *, promote: bool) -> list[str]:
    prefix = 'live' if promote else 'staged'
    setattr(credential, f'{prefix}_key_fingerprint', fingerprint)
    setattr(credential, f'{prefix}_key_version', version if fingerprint else None)
    fields = [f'{prefix}_key_fingerprint', f'{prefix}_key_version']
    if promote:
        fields += clear_staged_key(credential)
    return fields


def clear_staged_key(credential: Any) -> list[str]:
    credential.staged_key_fingerprint = ''
    credential.staged_key_version = None
    return ['staged_key_fingerprint', 'staged_key_version']


def promote_key_identity(credential: Any) -> list[str]:
    fingerprint = ''
    if credential.staged_key_version == credential.staged_kv_version:
        fingerprint = credential.staged_key_fingerprint
    return record_key_version(credential, fingerprint, credential.staged_kv_version, promote=True)
