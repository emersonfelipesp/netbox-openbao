#!/usr/bin/env python3
"""
Assert that no model field can hold secret material.

This is the plugin's foundational invariant: `Credential` has no column that
material could be written to, which is what makes the changelog, export
templates, and the REST representation safe structurally rather than by
convention.

`netbox_openbao/tests/test_security.py` enforces it properly, by walking
`Credential._meta.get_fields()` on a live model. That needs NetBox, a database,
and Redis. This script is the dependency-free restatement that runs on a CI
runner which has none of them — it parses the source instead.

**It shares its forbidden-token list with the real test**, which imports
`FORBIDDEN_FIELD_TOKENS` from here. An earlier version kept its own shorter
copy and checked only three of the five tokens, and only plain assignments —
so `secret_data = models.JSONField()` or an annotated `token: str = ...` passed
every check the public workflow advertised while violating the invariant it
claimed to protect. Two lists is one list too many for something whose whole
job is to be exhaustive.

Usage:

    python scripts/check_no_secret_fields.py [path ...]
"""

import ast
import sys
from pathlib import Path

# A field whose name contains any of these could hold material. Kept here, and
# imported by tests/test_security.py, so the two can never disagree.
FORBIDDEN_FIELD_TOKENS = ('password', 'private', 'secret', 'passphrase', 'token')

# Names that contain a forbidden token but are demonstrably not secret-bearing.
# Every entry here is a hole in the check, so each one carries its reason and
# the list should be argued over rather than extended.
#
#   secret_fields  CredentialTypeSchema.secret_fields is an ArrayField of
#                  property *names* — it records which keys of an
#                  operator-defined payload are secret so extraction can refuse
#                  to mirror them into a column. It holds no material, and it
#                  is the mechanism that keeps material out of columns rather
#                  than a way in.
#
# The scope of this list differs from the one in tests/test_security.py on
# purpose: that test walks `Credential` alone, which has no such field, while
# this script scans every model so a secret-bearing column cannot be added to a
# *different* model unnoticed. The forbidden-token list is what the two share.
ALLOWED_EXCEPTIONS = frozenset({'secret_fields'})

DEFAULT_TARGETS = ('netbox_openbao/models/',)


def offending_names(source):
    """Return assigned names in `source` that could name a secret-bearing field."""
    offenders = []
    for node in ast.walk(ast.parse(source)):
        # `name = models.CharField(...)`
        if isinstance(node, ast.Assign):
            targets = node.targets
        # `name: SomeType = models.CharField(...)` — missed by an Assign-only
        # walk, which is exactly how an annotated field would have slipped past.
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue

        for target in targets:
            name = getattr(target, 'id', '') or getattr(target, 'attr', '')
            if not name or name in ALLOWED_EXCEPTIONS:
                continue
            if any(token in name.lower() for token in FORBIDDEN_FIELD_TOKENS):
                offenders.append(name)
    return offenders


def main(argv):
    targets = argv[1:] or list(DEFAULT_TARGETS)
    paths = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            paths.extend(sorted(path.rglob('*.py')))
        elif path.is_file():
            paths.append(path)
        else:
            # Fail loudly. A typo'd path that silently checked nothing would
            # leave a green CI step asserting an invariant it never looked at.
            return f'No such path: {target}'

    if not paths:
        return f'No Python sources found in: {", ".join(targets)}'

    failures = []
    for path in paths:
        for name in offending_names(path.read_text()):
            failures.append(f'{path}: {name}')

    if failures:
        return (
            'Model field(s) that may hold secret material:\n  '
            + '\n  '.join(failures)
            + '\n\nSecret material must live only in OpenBao. See docs/security.md.'
        )

    print(f'Checked {len(paths)} module(s): no model field can hold secret material.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
