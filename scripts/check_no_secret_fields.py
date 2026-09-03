#!/usr/bin/env python3
"""
Assert that no model field can hold secret material.

This is the plugin's foundational invariant: `Credential` has no column that
material could be written to, which is what makes the changelog, export
templates, and the REST representation safe structurally rather than by
convention.

**An allowlist, not a name denylist.** The first version of this check looked
for field names containing `password`, `private`, `secret`, `passphrase`, or
`token`. That is a heuristic dressed as a guarantee: `material =
models.JSONField()` or `payload = models.JSONField()` violates the invariant
completely and matches none of those words, and a tuple-assigned name evaded
the AST walk entirely. Sharing one token list with the test suite removed
*drift* between two checks without making either of them true.

So the rule is inverted. Every concrete field on `Credential` is enumerated
below, having been individually reviewed as non-secret. **Any field that is not
on the list fails the check**, whatever it is called — which is the only form
of this check that cannot be walked around by choosing a different word. Adding
a field therefore requires a deliberate edit here, which is the point: that
edit is the review.

`netbox_openbao/tests/test_security.py` enforces the same rule against the live
model, where it can also see inherited and reverse-relation fields. This script
is the dependency-free half, for a CI runner with no NetBox, no database, and
no Redis. It parses the source instead.

By default both the credential inventory and the plugin settings model are
checked. The latter is configuration only: adding an AppRole, SecretID, token,
or any other material-shaped field there would violate the same invariant.

Usage:

    python scripts/check_no_secret_fields.py [path-to-credentials.py]
"""

import ast
import sys
from pathlib import Path

DEFAULT_TARGET = 'netbox_openbao/models/credentials.py'
SETTINGS_TARGET = 'netbox_openbao/models/settings.py'
MODEL = 'Credential'

# Every concrete field on `Credential`, each reviewed as incapable of holding
# secret material. Grouped as the model groups them.
#
# To add a field: add it here, in the same commit, with the review that says
# why it is not secret. A field absent from this list fails the check.
APPROVED_FIELDS = frozenset({
    # Identity and placement
    'name',
    'uuid',              # random identifier; the path derives from it
    'credential_type',
    'policy',
    'engine',
    'path',              # a location, never a value

    # Non-secret identity
    'username',

    # Public material — transmitted in the clear by the protocols that use it
    'public_key',
    'fingerprint',
    'key_type',
    'cert_serial',
    'cert_subject',
    'cert_issuer',
    'valid_from',
    'valid_until',

    # Provenance
    'import_source',     # e.g. "netbox_secrets:142"; an ID, not a value

    # Lifecycle
    'status',
    'rotation_interval',
    'last_rotated',

    # Observed OpenBao state — version numbers and timestamps only
    'kv_version',
    'live_kv_version',
    'staged_kv_version',
    'last_verified',

    # Django/NetBox model machinery, not fields
    'clone_fields',
    'objects',
})

APPROVED_SETTINGS_FIELDS = frozenset({
    'singleton_key',       # fixed singleton discriminator
    'path_prefix',         # a location, never secret material
    'assignable_models',
    'assignable_models_deny',
    'store_public_material',
    'reveal_rate_limit',
    'reveal_ttl',
    'token_cache_ttl',
    'audit_retention_days',
    'allow_generation',
    'default_ssh_key_type',
    'expiry_warning_days',
    'engine_health_interval',
    'expiry_scan_interval',
    'credential_verify_interval',
    'rotation_due_interval',
    'access_log_prune_interval',
})

APPROVED_FIELDS_BY_MODEL = {
    MODEL: APPROVED_FIELDS,
    'OpenBaoSettings': APPROVED_SETTINGS_FIELDS,
}

# Names assigned in the class body that are not fields and need no review.
# `objects` is a manager, not a column, so it can hold no material. Listing it
# here rather than teaching the scan to recognise manager expressions keeps the
# check deliberately broad: anything else new in a class body still has to be
# reviewed, including a field added through a custom descriptor.
NON_FIELD_ASSIGNMENTS = frozenset({'Meta', 'objects'})


def _assigned_names(node):
    """Every name a statement binds, including tuple and annotated targets."""
    targets = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    else:
        return []

    names = []
    stack = list(targets)
    while stack:
        target = stack.pop()
        # `a, b = ...` and `[a, b] = ...` — missed entirely by reading only
        # `target.id`, which is how a tuple-assigned field slipped past before.
        if isinstance(target, (ast.Tuple, ast.List)):
            stack.extend(target.elts)
        elif isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return names


def unapproved_names(source, model=MODEL):
    """Names bound in `model`'s class body that are not on the allowlist."""
    approved_fields = APPROVED_FIELDS_BY_MODEL[model]
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == model:
            found = []
            for statement in node.body:
                for name in _assigned_names(statement):
                    if name.startswith('_'):
                        continue
                    if name in approved_fields or name in NON_FIELD_ASSIGNMENTS:
                        continue
                    found.append(name)
            return found
    raise LookupError(f'No class named {model!r} in the parsed source')


def _check(target, model):
    if not target.is_file():
        return f'No such file: {target}'

    try:
        offenders = unapproved_names(target.read_text(), model=model)
    except LookupError as exc:
        return str(exc)

    if offenders:
        return (
            f'{target}: {model} gained field(s) that have not been reviewed as non-secret:\n  '
            + '\n  '.join(sorted(offenders))
            + '\n\nSecret material must live only in OpenBao. If these are genuinely non-secret, '
            'add them to the model allowlist in this script with the reasoning. See docs/security.md.'
        )

    print(f'{target}: every {model} field is on the reviewed non-secret allowlist.')
    return 0


def main(argv):
    if len(argv) > 1:
        target = Path(argv[1])
        model = 'OpenBaoSettings' if target.name == 'settings.py' else MODEL
        return _check(target, model)

    for target, model in (
        (Path(DEFAULT_TARGET), MODEL),
        (Path(SETTINGS_TARGET), 'OpenBaoSettings'),
    ):
        result = _check(target, model)
        if result:
            return result
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
