"""
Credential type definitions, payload validation, and metadata extraction.

Every other subpackage here carries an `__init__.py`; this one was the
exception and worked only because Python 3 treats a directory without one as an
implicit namespace package. That is a fragile thing to rely on inside a regular
package — a namespace portion merges with any same-named directory another
distribution installs — and it is invisible to static tooling, which is how the
documentation build first noticed it.

Nothing is re-exported: `registry`, `extractors`, and `generators` are imported
by module path throughout the plugin, and flattening them here would create a
second name for each function without retiring the first.
"""
