"""
Per-request lifetime for the cached settings row.

`config.Config` memoises the settings row on a **thread-local**, which is what
keeps a page render that reads several settings down to one lookup rather than
one per key. That memo is only safe if something discards it, and this is that
something.

Without it the memo outlives the request that created it. A gunicorn worker
thread populates its thread-local on the first request it serves and then keeps
it for the life of the process, so an operator who changes a setting sees the
new value on whichever thread handled the save and the **old** value on every
other thread — indefinitely, with no error and nothing in a log to suggest the
save did not take.

This is not a novel design. NetBox memoises its own dynamic configuration the
same way and discards it in `netbox.middleware.CoreMiddleware` after every
response, for exactly this reason. The plugin declares this middleware through
`PluginConfig.middleware`, which NetBox appends to `MIDDLEWARE` at startup, so
an operator installs nothing and configures nothing for it to apply.
"""

from .config import clear_config

__all__ = ('SettingsCacheMiddleware',)


class SettingsCacheMiddleware:
    """Discard the thread-local settings memo once each request is finished."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        finally:
            # `finally`, not a plain call after `get_response`. A view that
            # raises would otherwise leave the memo in place on this thread,
            # which is the one case where a stale read is most likely to be
            # blamed on something else entirely.
            clear_config()
