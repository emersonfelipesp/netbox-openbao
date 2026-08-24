"""
Generate one API-reference page per module, at build time.

Hand-written stubs for forty modules would be forty files to forget to update.
This walks the package instead, so a new module appears in the reference the
moment it exists and a deleted one disappears with it — the reference cannot
drift from the code, because it is not a separate artefact.

`mkdocstrings` reads the source through `griffe`, which parses it statically
and never imports it. That is why the documentation builds without NetBox,
`hvac`, or a database, and why the build cannot start passing merely because
something happened to be importable in the environment.
"""

from pathlib import Path

import mkdocs_gen_files

PACKAGE = 'netbox_openbao'

# Excluded from the reference, with reasons:
#
#   migrations/  — generated schema deltas; the models they build are
#                  documented, and forty auto-generated Django operations are
#                  noise, not reference material.
#   tests/       — the suite is documentation for contributors, not API. It is
#                  covered in the architecture pages where a test *is* the
#                  enforcement mechanism for an invariant.
EXCLUDED_PARTS = {'migrations', 'tests'}

nav = mkdocs_gen_files.Nav()
root = Path(__file__).parent.parent

for path in sorted((root / PACKAGE).rglob('*.py')):
    module_path = path.relative_to(root).with_suffix('')
    parts = tuple(module_path.parts)

    if EXCLUDED_PARTS.intersection(parts):
        continue

    if parts[-1] == '__init__':
        parts = parts[:-1]
        doc_path = module_path.parent / 'index.md'
        # The package root itself, whose __init__ carries the PluginConfig, is
        # worth a page; an empty sub-package __init__ is not.
        if not parts:
            continue
    elif parts[-1].startswith('_'):
        continue
    else:
        doc_path = module_path.with_suffix('.md')

    # SUMMARY.md itself lives in `reference/`, so literate-nav resolves its
    # links relative to that directory — the nav entry must NOT carry the
    # `reference/` prefix, or every link resolves to `reference/reference/…`.
    nav_path = doc_path.relative_to(PACKAGE)
    full_doc_path = Path('reference', nav_path)

    nav[parts[1:] or (PACKAGE,)] = nav_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, 'w') as fd:
        fd.write(f'::: {".".join(parts)}\n')

    mkdocs_gen_files.set_edit_path(full_doc_path, Path('..') / path.relative_to(root))

with mkdocs_gen_files.open('reference/SUMMARY.md', 'w') as fd:
    fd.writelines(nav.build_literate_nav())
