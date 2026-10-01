from netbox.search import SearchIndex, register_search

from .models import Credential, CredentialPolicy, SecretEngine, ServiceEndpoint, SSHPublicKey


@register_search
class SecretEngineIndex(SearchIndex):
    model = SecretEngine
    fields = (
        ('name', 100),
        ('slug', 110),
        ('api_url', 200),
        ('description', 500),
        ('comments', 5000),
    )
    display_attrs = ('api_url', 'kv_mount', 'status', 'description')


@register_search
class CredentialPolicyIndex(SearchIndex):
    model = CredentialPolicy
    fields = (
        ('name', 100),
        ('slug', 110),
        ('openbao_policy', 200),
        ('description', 500),
    )
    display_attrs = ('engine', 'openbao_policy', 'description')


@register_search
class CredentialIndex(SearchIndex):
    """
    Indexes non-secret attributes only.

    `public_key`, `fingerprint`, and the certificate fields are all public by
    definition, so indexing them is safe and makes "which device trusts key
    fingerprint X" a global-search answer. No field on this model can contain
    secret material.
    """

    model = Credential
    fields = (
        ('name', 100),
        ('username', 200),
        ('fingerprint', 200),
        ('cert_subject', 300),
        ('cert_serial', 300),
        ('description', 500),
        ('comments', 5000),
    )
    display_attrs = ('credential_type', 'username', 'policy', 'status', 'description')


@register_search
class ServiceEndpointIndex(SearchIndex):
    model = ServiceEndpoint
    fields = (('host', 100), ('ssh_known_hosts_entry', 500))
    # The credential is omitted: search results do not apply credential object
    # permissions, so naming it here would leak it to endpoint-only viewers.
    display_attrs = ('assigned_object', 'service_type', 'host', 'port')


@register_search
class SSHPublicKeyIndex(SearchIndex):
    model = SSHPublicKey
    fields = (('fingerprint', 100), ('public_key', 500))
    display_attrs = ('user', 'service_endpoint', 'fingerprint', 'key_type')
