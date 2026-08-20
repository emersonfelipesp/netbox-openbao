"""Permission handling for the custom credential actions."""

from netbox.api.authentication import TokenPermissions

__all__ = ('SecretActionPermissions',)


class SecretActionPermissions(TokenPermissions):
    """
    Permission map for `reveal` and `rotate`.

    NetBox maps POST to `add_<model>`, which is wrong for both of these
    actions. Neither creates anything: `reveal` reads an existing credential
    (it accepts POST so the reason stays out of the URL and out of every
    intermediary's access log), and `rotate` replaces material on a credential
    that already exists.

    Left at the default, `add_credential` would become the real gate and the
    dedicated `reveal_credential` / `rotate_credential` permissions would be
    decorative — anyone able to rotate would already be able to create, and a
    role holding only `rotate_credential` could not rotate at all.

    POST therefore maps to `view_<model>`, and the action's own permission is
    enforced separately through `restrict()`. The inherited write-token check
    still applies, so a read-only API token cannot rotate.
    """

    perms_map = {
        **TokenPermissions.perms_map,
        'POST': ['%(app_label)s.view_%(model_name)s'],
    }
