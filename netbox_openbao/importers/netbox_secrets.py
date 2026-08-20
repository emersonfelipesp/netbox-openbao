"""
Migration from `netbox-secrets`.

`netbox-secrets` is the incumbent, and the estates that would benefit most from
this plugin are exactly the ones with hundreds of credentials already modelled
in it. Without a migration path the plugin is realistically greenfield-only.

The import is deliberately shaped around three properties:

* **It never deletes anything.** Migration is a copy. Retiring the source data
  is a separate, human decision made after the copy is verified.
* **It is idempotent**, keyed on the source row's primary key recorded in
  `Credential.import_source`, so an interrupted run is resumable and a repeated
  run is a no-op rather than a duplicate estate.
* **It is per-secret atomic**, never per-batch, for the same reason.

The interesting problem is typing. `netbox-secrets` has no type field — a
secret is just a string — so the type has to be inferred. Guessing wrong would
produce nonsense metadata, so inference is *verified by extraction*: a
candidate type is only accepted if this plugin's own extractors can actually
parse the material as that type. Anything that fails falls back to
`generic-kv`, which stores the value faithfully and claims nothing about it.
"""

import logging
from dataclasses import dataclass, field

from django.db import transaction
from django.utils.text import slugify

from netbox_openbao.choices import CredentialTypeChoices
from netbox_openbao.models import Credential, CredentialAssignment, CredentialPolicy
from netbox_openbao.secrets.extractors import extract_certificate_metadata, extract_ssh_metadata
from netbox_openbao.services import store_credential

__all__ = (
    'SOURCE_SYSTEM',
    'ImportResult',
    'SourceSecret',
    'import_secrets',
    'infer_credential_type',
    'source_marker',
)

logger = logging.getLogger('netbox.plugins.netbox_openbao.import')

# Provenance marker, written to the indexed `Credential.import_source`, so
# recognising an already-migrated secret costs one query for the whole run
# rather than a network round-trip per credential.
SOURCE_SYSTEM = 'netbox_secrets'


def source_marker(pk):
    return f'{SOURCE_SYSTEM}:{pk}'


@dataclass
class SourceSecret:
    """
    One `netbox-secrets` secret, reduced to what the import needs.

    A plain dataclass rather than the ORM model on purpose: the management
    command adapts `netbox-secrets` into this, and the tests construct it
    directly. That keeps the suite from requiring `netbox-secrets` to be
    installed in order to test the code that migrates away from it.
    """

    pk: int
    name: str
    plaintext: str
    role_name: str = ''
    username: str = ''
    assigned_object_type_id: int | None = None
    assigned_object_id: int | None = None


@dataclass
class ImportResult:
    imported: int = 0
    skipped: int = 0
    failed: int = 0
    details: list = field(default_factory=list)
    policies_needing_setup: set = field(default_factory=set)

    def note(self, source, outcome, detail=''):
        self.details.append((source.pk, source.name, outcome, detail))


def infer_credential_type(plaintext):
    """
    Guess a credential type from the material, then prove the guess.

    Returns `(credential_type, payload)`. A candidate is only accepted if the
    corresponding extractor can genuinely parse it, because the whole value of
    typing an imported secret is the metadata that follows — and metadata
    derived from a wrong guess is worse than no metadata at all.
    """
    # Detection ignores surrounding whitespace; storage does not. A migration
    # is a copy, and silently trimming material would change a password whose
    # trailing space is real, or a PEM body whose final newline some parsers
    # insist on. `original` is what gets written, always.
    original = plaintext or ''
    text = original.strip()

    has_certificate = 'BEGIN CERTIFICATE' in text
    has_private_key = 'PRIVATE KEY' in text
    parses_as_key = has_private_key and _parses_as(extract_ssh_metadata, text)

    if has_certificate and _parses_as(extract_certificate_metadata, text):
        if parses_as_key:
            # netbox-secrets stores a key and its certificate concatenated in
            # one string often enough to be worth handling.
            return CredentialTypeChoices.TYPE_X509_KEYPAIR, {
                'private_key': original,
                'certificate': original,
            }
        return CredentialTypeChoices.TYPE_X509_CA, {'certificate': original}

    if parses_as_key:
        return CredentialTypeChoices.TYPE_SSH_KEYPAIR, {'private_key': original}

    # A single line with no structure is almost always a password. Anything
    # else keeps its exact shape under generic-kv rather than being mistyped.
    if text and '\n' not in text:
        return CredentialTypeChoices.TYPE_PASSWORD, {'password': original}

    return CredentialTypeChoices.TYPE_GENERIC_KV, {'value': original}


def _parses_as(extractor, text):
    """
    Whether `extractor` can actually make sense of `text`.

    Broad by design: any failure means "not this type", and the specific reason
    is not interesting — it must not be logged either, because the input is
    secret material.
    """
    try:
        extractor(text)
    except Exception:
        return False
    return True


def _policy_for(source, engine, fallback_policy, map_roles, cache, result):
    """
    Choose the policy for an imported secret.

    Role mapping is opt-in. A `netbox-secrets` role has no counterpart in
    OpenBao, so a policy created from one is only half configured — its
    `openbao_policy` names something that does not exist yet. Creating those
    silently would turn a successful-looking import into a pile of credentials
    that fail at the first reveal, which reads as a plugin bug rather than an
    unfinished migration. So the default is to put everything on one explicitly
    chosen policy, and `--map-roles` opts into the tiers while reporting which
    ones still need creating in OpenBao.
    """
    if not map_roles or not source.role_name:
        return fallback_policy

    slug = (slugify(source.role_name)[:100] or 'imported')
    if slug in cache:
        return cache[slug]

    policy, created = CredentialPolicy.objects.get_or_create(
        slug=slug,
        defaults={
            'name': source.role_name[:100],
            'engine': engine,
            'openbao_policy': f'netbox-{slug}',
            'description': 'Imported from a netbox-secrets role',
        },
    )
    if created:
        result.policies_needing_setup.add(policy.openbao_policy)
        logger.info('Created policy %s for imported role %s', slug, source.role_name)
    cache[slug] = policy
    return policy


def import_secrets(sources, engine, fallback_policy, *, dry_run=False, map_roles=False,
                   user=None, stdout=None):
    """
    Copy `sources` into OpenBao, leaving `netbox-secrets` untouched.

    Args:
        sources: Iterable of `SourceSecret`.
        engine: `SecretEngine` to write to.
        fallback_policy: `CredentialPolicy` everything lands on unless
            `map_roles` is set.
        dry_run: Report what would happen and write nothing — including the
            inferred type per secret, which is what an operator most needs to
            check before committing.
        map_roles: Create a policy per `netbox-secrets` role. See `_policy_for`.
    """
    result = ImportResult()
    policy_cache = {}

    def emit(message):
        if stdout is not None:
            stdout.write(message)

    # One query for the whole run, scoped to this engine so the same source
    # estate can be migrated onto two engines independently.
    already_imported = set(
        Credential.objects.filter(engine=engine, import_source__startswith=f'{SOURCE_SYSTEM}:')
        .values_list('import_source', flat=True)
    )

    for source in sources:
        marker = source_marker(source.pk)
        if marker in already_imported:
            result.skipped += 1
            result.note(source, 'skipped', 'already imported')
            emit(f'  skip  #{source.pk} {source.name} (already imported)')
            continue

        credential_type, payload = infer_credential_type(source.plaintext)
        emit(f'  {"plan" if dry_run else "copy"}  #{source.pk} {source.name} -> {credential_type}')

        if dry_run:
            result.imported += 1
            result.note(source, 'planned', credential_type)
            continue

        policy = _policy_for(source, engine, fallback_policy, map_roles, policy_cache, result)
        credential = Credential(
            name=(source.name or f'netbox-secrets #{source.pk}')[:200],
            credential_type=credential_type,
            policy=policy,
            engine=engine,
            username=(source.username or '')[:200],
            import_source=marker,
        )

        def persist(metadata, credential=credential):
            for name, value in metadata.items():
                setattr(credential, name, value)
            credential.full_clean()
            credential.save()
            return credential

        try:
            with transaction.atomic():
                store_credential(
                    persist, credential_type, payload,
                    cas=0, user=user, subject=credential,
                )
                if source.assigned_object_type_id and source.assigned_object_id:
                    CredentialAssignment.objects.create(
                        credential=credential,
                        assigned_object_type_id=source.assigned_object_type_id,
                        assigned_object_id=source.assigned_object_id,
                    )
        except Exception as exc:
            # One failure must not abandon the rest; the run is resumable
            # precisely because each secret is its own transaction. The
            # exception type is reported, never its message — it may quote the
            # material.
            result.failed += 1
            result.note(source, 'failed', type(exc).__name__)
            logger.error('Failed to import netbox-secrets #%s: %s', source.pk, type(exc).__name__)
            emit(f'  FAIL  #{source.pk} {source.name}: {type(exc).__name__}')
            continue

        already_imported.add(marker)
        result.imported += 1
        result.note(source, 'imported', credential_type)

    return result
