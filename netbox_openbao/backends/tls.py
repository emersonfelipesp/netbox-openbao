"""Private temporary files for TLS libraries that require filesystem paths."""

import atexit
import os
import tempfile
import threading

_temporary_paths = set()
_temporary_paths_lock = threading.Lock()


def materialize_private_pem(value, suffix):
    """Write PEM material to a process-private 0600 file and return its path."""
    descriptor, path = tempfile.mkstemp(prefix='netbox-openbao-', suffix=suffix)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(value)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    with _temporary_paths_lock:
        _temporary_paths.add(path)
    return path


def remove_private_files(paths):
    """Remove materialized PEM files without exposing their content in errors."""
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        finally:
            with _temporary_paths_lock:
                _temporary_paths.discard(path)


def _cleanup_private_files():
    with _temporary_paths_lock:
        paths = tuple(_temporary_paths)
    remove_private_files(paths)


atexit.register(_cleanup_private_files)
