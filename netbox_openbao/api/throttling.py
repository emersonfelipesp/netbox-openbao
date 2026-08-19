"""Rate limiting for secret-revealing endpoints."""

from netbox_openbao.config import get_config
from rest_framework.throttling import UserRateThrottle

__all__ = ('RevealRateThrottle',)


class RevealRateThrottle(UserRateThrottle):
    """
    Per-user ceiling on reveals.

    Bounds the blast radius of a leaked API token: an attacker holding a valid
    token with reveal permission can still only drain credentials at the
    configured rate, which gives the access log time to be noticed.
    """

    scope = 'netbox_openbao_reveal'

    def get_rate(self):
        return get_config('reveal_rate_limit') or '30/hour'
