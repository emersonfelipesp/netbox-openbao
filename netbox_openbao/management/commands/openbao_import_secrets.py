"""
Copy `netbox-secrets` data into OpenBao.

The session key is never accepted as a command-line argument. `argv` is
readable by any process on the host through `/proc/<pid>/cmdline`, and it lands
in shell history — so a key passed that way is compromised the moment it is
typed. It comes from the environment or an interactive prompt instead.
"""

import getpass
import os

from django.core.management.base import BaseCommand, CommandError

from netbox_openbao.importers import SourceSecret, import_secrets
from netbox_openbao.models import CredentialPolicy, SecretEngine

SESSION_KEY_ENV = 'NETBOX_SECRETS_SESSION_KEY'


class Command(BaseCommand):
    help = 'Copy credentials from netbox-secrets into OpenBao. Never deletes from the source.'

    def add_arguments(self, parser):
        parser.add_argument('--engine', required=True, help='Slug of the SecretEngine to write to')
        parser.add_argument(
            '--policy', required=True,
            help='Slug of the CredentialPolicy imported credentials land on',
        )
        parser.add_argument(
            '--map-roles', action='store_true',
            help=(
                'Create a CredentialPolicy per netbox-secrets role. Those policies name an OpenBao '
                'policy that does not exist yet and must be created before reveals will work.'
            ),
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Report what would be imported, including the inferred type per secret, and write nothing',
        )
        parser.add_argument('--limit', type=int, default=None, help='Import at most N secrets')
        # Deliberately absent: any flag that would take the session key. See
        # the module docstring.

    def handle(self, *args, **options):
        engine = self._get(SecretEngine, options['engine'], 'engine')
        policy = self._get(CredentialPolicy, options['policy'], 'policy')

        if policy.engine_id != engine.pk:
            raise CommandError(
                f"Policy '{policy.slug}' belongs to engine '{policy.engine.slug}', not '{engine.slug}'. "
                f"A credential's engine must match its policy's."
            )

        sources = list(self._load_sources(limit=options['limit']))
        if not sources:
            self.stdout.write('Nothing to import.')
            return

        self.stdout.write(
            f"{'Planning' if options['dry_run'] else 'Importing'} {len(sources)} secret(s) "
            f"onto engine '{engine.slug}':"
        )
        result = import_secrets(
            sources, engine, policy,
            dry_run=options['dry_run'],
            map_roles=options['map_roles'],
            stdout=self.stdout,
        )

        self.stdout.write('')
        verb = 'would import' if options['dry_run'] else 'imported'
        self.stdout.write(f'{verb}: {result.imported}   skipped: {result.skipped}   failed: {result.failed}')

        if result.policies_needing_setup:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                'These policies were created and name an OpenBao policy that does not exist yet. '
                'Create them in OpenBao, or reveals against these credentials will fail:'
            ))
            for name in sorted(result.policies_needing_setup):
                self.stdout.write(f'  {name}')

        if not options['dry_run'] and result.imported:
            self.stdout.write('')
            self.stdout.write(
                'netbox-secrets was not modified. Verify the imported credentials before '
                'retiring the originals.'
            )

    def _get(self, model, slug, label):
        try:
            return model.objects.get(slug=slug)
        except model.DoesNotExist:
            available = ', '.join(model.objects.values_list('slug', flat=True)) or 'none defined'
            raise CommandError(f"No {label} with slug '{slug}'. Available: {available}") from None

    def _resolve_session_key(self):
        """
        Read the session key from the environment, or prompt for it.

        Never from `argv` — see the module docstring.
        """
        key = os.environ.get(SESSION_KEY_ENV)
        if key:
            return key.strip()
        if not os.isatty(0):
            raise CommandError(
                f'A netbox-secrets session key is required. Set {SESSION_KEY_ENV}, or run '
                f'interactively to be prompted. It is deliberately not accepted as an argument.'
            )
        return getpass.getpass('netbox-secrets session key: ').strip()

    def _load_sources(self, limit=None):
        """
        Adapt `netbox-secrets` rows into `SourceSecret`.

        Resolved through the app registry rather than imported at module level,
        so this plugin does not depend on `netbox-secrets` being installed —
        the command is the only thing that needs it, and only when run.
        """
        from django.apps import apps

        try:
            Secret = apps.get_model('netbox_secrets', 'Secret')
        except LookupError:
            raise CommandError(
                'netbox-secrets does not appear to be installed in this NetBox. There is nothing '
                'to import from.'
            ) from None

        session_key = self._resolve_session_key()

        queryset = Secret.objects.select_related('role').all()
        if limit:
            queryset = queryset[:limit]

        for secret in queryset:
            try:
                secret.decrypt(session_key)
            except Exception as exc:
                # Never surface the exception text: it can quote ciphertext or
                # key material depending on the failure.
                raise CommandError(
                    f'Could not decrypt secret #{secret.pk} ({type(exc).__name__}). '
                    f'Check that the session key is correct and belongs to a user with access.'
                ) from None

            yield SourceSecret(
                pk=secret.pk,
                name=getattr(secret, 'name', '') or '',
                plaintext=secret.plaintext or '',
                role_name=getattr(getattr(secret, 'role', None), 'name', '') or '',
                assigned_object_type_id=getattr(secret, 'assigned_object_type_id', None),
                assigned_object_id=getattr(secret, 'assigned_object_id', None),
            )
