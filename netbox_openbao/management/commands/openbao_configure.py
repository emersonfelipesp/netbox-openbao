"""Configure netbox-openbao without plaintext process configuration."""

import copy
import getpass
import json
import os
import sys

from dcim.models import Device
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from netbox_openbao.backends import get_backend
from netbox_openbao.choices import AuthMethodChoices, BackendChoices
from netbox_openbao.config import MODEL_BACKED_SETTINGS, clear_config, get_config
from netbox_openbao.models import (
    CredentialPolicy,
    EngineAuthMaterial,
    OpenBaoCluster,
    OpenBaoSettings,
    SecretEngine,
)
from netbox_openbao.models.auth import AUTH_MATERIAL_FIELDS, AuthMaterialDecryptionError


class Command(BaseCommand):
    help = 'Show or change OpenBao database configuration and encrypted service identities.'

    def add_arguments(self, parser):
        commands = parser.add_subparsers(dest='action', required=True)
        commands.add_parser('show', help='Show effective settings, engines, and auth status')

        settings_parser = commands.add_parser('settings', help='Set singleton settings')
        settings_parser.add_argument('--set', action='append', default=[], metavar='KEY=VALUE', required=True)

        legacy_settings = commands.add_parser(
            'import-legacy-settings',
            help='Import legacy PLUGINS_CONFIG values once',
        )
        legacy_settings.add_argument(
            '--dry-run',
            action='store_true',
            help='Validate and print the diff without saving it',
        )

        cleanup_prefixes = commands.add_parser(
            'cleanup-legacy-prefixes',
            help='Clear retained policy prefix metadata after imports are verified',
        )
        cleanup_prefixes.add_argument(
            '--confirm-imports-verified',
            action='store_true',
            required=True,
            help='Confirm every policy identity import and authentication test succeeded',
        )

        engine = commands.add_parser('engine', help='Create or update a secret engine')
        engine.add_argument('--slug', required=True)
        engine.add_argument('--name')
        engine.add_argument('--api-url')
        engine.add_argument('--backend', choices=('openbao', 'vault', 'broker'))
        engine.add_argument('--namespace')
        engine.add_argument('--kv-mount')
        engine.add_argument('--kv-version', type=int)
        engine.add_argument('--auth-method', choices=('approle', 'token', 'kubernetes', 'cert'))
        engine.add_argument('--tls-verify', choices=('true', 'false'))
        engine.add_argument('--ca-cert-path')
        engine.add_argument('--host-device', type=int, help='NetBox device primary key')
        default = engine.add_mutually_exclusive_group()
        default.add_argument('--default', action='store_true')
        default.add_argument('--no-default', action='store_true')

        auth = commands.add_parser('auth', help='Set or clear one encrypted auth value')
        self._add_owner_arguments(auth)
        auth.add_argument('--set', dest='set_field', choices=AUTH_MATERIAL_FIELDS)
        auth.add_argument('--clear', dest='clear_field', choices=AUTH_MATERIAL_FIELDS)
        source = auth.add_mutually_exclusive_group()
        source.add_argument('--file', help='Read the new value from a protected file')
        source.add_argument('--stdin', action='store_true', help='Read the new value from standard input')

        import_env = commands.add_parser('import-env', help='Import old NETBOX_BAO_* variables once')
        self._add_owner_arguments(import_env)
        import_env.add_argument('--prefix', help='Old variable prefix; defaults to the owner slug')

        test = commands.add_parser('test', help='Authenticate without printing material')
        self._add_owner_arguments(test)

        reencrypt = commands.add_parser('reencrypt', help='Re-encrypt all auth rows after SECRET_KEY rotation')
        reencrypt.add_argument('--old-secret-key-file', help='Protected file containing the previous SECRET_KEY')

    @staticmethod
    def _add_owner_arguments(parser):
        owner = parser.add_mutually_exclusive_group(required=True)
        owner.add_argument('--engine', help='SecretEngine slug')
        owner.add_argument('--policy', help='CredentialPolicy slug')
        owner.add_argument('--cluster', help='OpenBaoCluster slug')

    def handle(self, *args, **options):
        action = options['action']
        handlers = {
            'show': self._show,
            'settings': self._settings,
            'import-legacy-settings': self._import_legacy_settings,
            'cleanup-legacy-prefixes': self._cleanup_legacy_prefixes,
            'engine': self._engine,
            'auth': self._auth,
            'import-env': self._import_env,
            'test': self._test,
            'reencrypt': self._reencrypt,
        }
        handlers[action](options)

    @staticmethod
    def _display_value(value):
        return json.dumps(value, sort_keys=True)

    def _legacy_settings_candidate(self):
        configured = settings.PLUGINS_CONFIG.get('netbox_openbao', {})
        if not isinstance(configured, dict):
            raise CommandError("PLUGINS_CONFIG['netbox_openbao'] must be a mapping.")
        recognized = set(configured).intersection(MODEL_BACKED_SETTINGS)
        if not recognized:
            raise CommandError('No legacy netbox_openbao settings were found in PLUGINS_CONFIG.')

        row = OpenBaoSettings.objects.first()
        previous = row or OpenBaoSettings()
        candidate = copy.copy(row) if row else OpenBaoSettings()
        for name in MODEL_BACKED_SETTINGS:
            field = OpenBaoSettings._meta.get_field(name)
            value = configured.get(name, getattr(previous, name))
            if value is None:
                value = field.get_default()
            try:
                setattr(candidate, name, field.to_python(value))
            except (TypeError, ValueError, ValidationError):
                raise CommandError(f'Invalid legacy value for OpenBao setting {name}.') from None
        return candidate, previous

    def _print_settings_diff(self, previous, candidate):
        self.stdout.write('Legacy settings diff:')
        for name in MODEL_BACKED_SETTINGS:
            before = getattr(previous, name)
            after = getattr(candidate, name)
            marker = 'changed' if before != after else 'unchanged'
            self.stdout.write(
                f'  {name}: {self._display_value(before)} -> {self._display_value(after)} ({marker})'
            )

    def _print_effective_settings(self, values, *, heading):
        self.stdout.write(heading)
        for name in MODEL_BACKED_SETTINGS:
            value = values[name] if isinstance(values, dict) else getattr(values, name)
            self.stdout.write(f'  {name}: {self._display_value(value)}')

    def _import_legacy_settings(self, options):
        candidate, previous = self._legacy_settings_candidate()
        self._print_settings_diff(previous, candidate)
        if candidate.path_prefix != previous.path_prefix:
            self.stdout.write(self.style.WARNING(
                'WARNING: path_prefix changes are refused when existing credential paths do not match. '
                f'Proposed change: {previous.path_prefix!r} -> {candidate.path_prefix!r}.'
            ))
        try:
            with transaction.atomic():
                candidate.full_clean()
                if options['dry_run']:
                    transaction.set_rollback(True)
                else:
                    candidate.save()
        except ValidationError as exc:
            detail = '; '.join(exc.messages)
            raise CommandError(f'Legacy OpenBao settings failed validation: {detail}') from None

        if options['dry_run']:
            self._print_effective_settings(candidate, heading='Proposed effective settings:')
            self.stdout.write(self.style.SUCCESS('Dry run complete; no settings were changed.'))
            return
        clear_config()
        effective = {name: get_config(name) for name in MODEL_BACKED_SETTINGS}
        self._print_effective_settings(effective, heading='Effective settings after import:')
        self.stdout.write(self.style.SUCCESS(
            'Legacy settings imported. Verify a credential reveal before removing PLUGINS_CONFIG.'
        ))

    def _show(self, options):
        del options
        settings_row = OpenBaoSettings.objects.first()
        effective = settings_row or OpenBaoSettings()
        self.stdout.write(f'Settings source: {"saved" if settings_row else "model defaults"}')
        for field in OpenBaoSettings._meta.fields:
            if field.name in {'id', 'singleton_key', 'created', 'last_updated', 'custom_field_data'}:
                continue
            self.stdout.write(f'{field.name}: {getattr(effective, field.name)}')
        for engine in SecretEngine.objects.order_by('slug'):
            try:
                material = engine.auth_material
            except EngineAuthMaterial.DoesNotExist:
                material = None
            status = ', '.join(
                f'{name}={"configured" if material and material.is_configured(name) else "missing"}'
                for name in AUTH_MATERIAL_FIELDS
            )
            self.stdout.write(f'engine {engine.slug}: {engine.api_url}; {status}')

    def _cleanup_legacy_prefixes(self, options):
        del options
        with transaction.atomic():
            policies = list(
                CredentialPolicy.objects.select_for_update()
                .select_related('engine')
                .exclude(legacy_approle_env_prefix='')
                .order_by('slug')
            )
            missing = [
                policy.slug
                for policy in policies
                if not self._has_usable_identity(
                    EngineAuthMaterial.objects.select_for_update().filter(policy=policy).first(),
                    policy.engine,
                )
            ]
            if missing:
                raise CommandError(
                    'Refusing cleanup because these policies have no complete imported identity '
                    'for the engine\'s authentication method: '
                    f'{", ".join(missing)}.'
                )
            CredentialPolicy.objects.filter(pk__in=[policy.pk for policy in policies]).update(
                legacy_approle_env_prefix=''
            )
        self.stdout.write(self.style.SUCCESS(
            f'Cleared retained legacy prefixes from {len(policies)} verified policy row(s).'
        ))

    def _settings(self, options):
        row = OpenBaoSettings.get_solo()
        for assignment in options['set']:
            if '=' not in assignment:
                raise CommandError('--set requires KEY=VALUE.')
            name, raw = assignment.split('=', 1)
            try:
                field = OpenBaoSettings._meta.get_field(name)
            except Exception:
                raise CommandError(f'Unknown OpenBao setting: {name}.') from None
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = raw
            try:
                setattr(row, name, field.to_python(value))
            except Exception:
                raise CommandError(f'Invalid value for OpenBao setting {name}.') from None
        row.full_clean()
        row.save()
        self.stdout.write(self.style.SUCCESS('OpenBao settings saved.'))

    def _engine(self, options):
        engine = SecretEngine.objects.filter(slug=options['slug']).first()
        creating = engine is None
        if creating:
            if not options.get('name') or not options.get('api_url'):
                raise CommandError('A new engine requires --name and --api-url.')
            engine = SecretEngine(slug=options['slug'])
        mapping = {
            'name': 'name', 'api_url': 'api_url', 'backend': 'backend',
            'namespace': 'namespace', 'kv_mount': 'kv_mount', 'kv_version': 'kv_version',
            'auth_method': 'auth_method', 'ca_cert_path': 'ca_cert_path',
        }
        for option, field in mapping.items():
            if options.get(option) is not None:
                setattr(engine, field, options[option])
        if options.get('tls_verify') is not None:
            engine.tls_verify = options['tls_verify'] == 'true'
        if options.get('host_device') is not None:
            try:
                engine.host_device = Device.objects.get(pk=options['host_device'])
            except Device.DoesNotExist:
                raise CommandError('No Device has the requested primary key.') from None
        if options.get('default'):
            engine.is_default = True
        elif options.get('no_default'):
            engine.is_default = False
        engine.full_clean()
        engine.save()
        verb = 'created' if creating else 'updated'
        self.stdout.write(self.style.SUCCESS(f'Engine {engine.slug} {verb}.'))

    def _owner(self, options):
        choices = (
            ('engine', SecretEngine),
            ('policy', CredentialPolicy),
            ('cluster', OpenBaoCluster),
        )
        for name, model in choices:
            if slug := options.get(name):
                try:
                    return name, model.objects.get(slug=slug)
                except model.DoesNotExist:
                    raise CommandError(f'No {model._meta.verbose_name} has slug {slug!r}.') from None
        raise CommandError('Choose an auth owner.')

    @staticmethod
    def _has_usable_identity(material, engine):
        """
        True only when the row holds what this engine's backend actually needs.

        A bare row, half an AppRole, or a complete identity for a different
        authentication method is not proof that the legacy variables were
        imported, so it must never authorize deleting the only record of which
        variables belong to a policy tier.
        """
        if material is None:
            return False
        configured = material.is_configured
        if engine.backend == BackendChoices.BACKEND_BROKER:
            return configured('client_cert') and configured('client_key')
        required = {
            AuthMethodChoices.METHOD_APPROLE: ('role_id', 'secret_id'),
            AuthMethodChoices.METHOD_TOKEN: ('token',),
            AuthMethodChoices.METHOD_KUBERNETES: ('k8s_role',),
            AuthMethodChoices.METHOD_CERT: ('client_cert', 'client_key'),
        }.get(engine.auth_method)
        return bool(required) and all(configured(name) for name in required)

    def _material(self, options):
        owner_name, owner = self._owner(options)
        material, _created = EngineAuthMaterial.objects.get_or_create(**{owner_name: owner})
        return owner_name, owner, material

    @staticmethod
    def _read_secret(options, prompt):
        if path := options.get('file'):
            try:
                with open(path) as handle:
                    return handle.read().strip()
            except OSError:
                raise CommandError('Could not read the auth material file.') from None
        if options.get('stdin'):
            return sys.stdin.read().strip()
        if not sys.stdin.isatty():
            raise CommandError('Use --file or --stdin when no interactive terminal is available.')
        return getpass.getpass(prompt).strip()

    def _auth(self, options):
        if bool(options.get('set_field')) == bool(options.get('clear_field')):
            raise CommandError('Choose exactly one of --set or --clear.')
        _owner_name, _owner, material = self._material(options)
        if field := options.get('clear_field'):
            material.clear_secret(field)
        else:
            field = options['set_field']
            value = self._read_secret(options, f'{field.replace("_", " ")}: ')
            if not value:
                raise CommandError('An empty value is not accepted; use --clear.')
            material.set_secret(field, value)
        material.full_clean()
        material.save()
        self.stdout.write(self.style.SUCCESS(f'{field} updated.'))

    @staticmethod
    def _legacy_prefix(owner):
        if isinstance(owner, CredentialPolicy):
            if owner.legacy_approle_env_prefix:
                return owner.legacy_approle_env_prefix
            owner = owner.engine
        return f'NETBOX_BAO_{owner.slug.upper().replace("-", "_")}'

    @staticmethod
    def _legacy_value(prefix, suffix, *, pem=False):
        value = os.environ.get(f'{prefix}_{suffix}', '').strip()
        file_path = os.environ.get(f'{prefix}_{suffix}_FILE', '').strip()
        if file_path:
            try:
                with open(file_path) as handle:
                    return handle.read().strip()
            except OSError:
                raise CommandError(f'Could not read {prefix}_{suffix}_FILE.') from None
        if pem and value:
            try:
                with open(value) as handle:
                    return handle.read().strip()
            except OSError:
                raise CommandError(f'Could not read the file named by {prefix}_{suffix}.') from None
        return value

    def _import_env(self, options):
        owner_name, owner = self._owner(options)
        prefix = options.get('prefix') or self._legacy_prefix(owner)
        mapping = {
            'role_id': ('ROLE_ID', False),
            'secret_id': ('SECRET_ID', False),
            'token': ('TOKEN', False),
            'k8s_role': ('K8S_ROLE', False),
            'k8s_jwt_path': ('K8S_JWT_PATH', False),
            'client_cert': ('CLIENT_CERT', True),
            'client_key': ('CLIENT_KEY', True),
        }
        # Read and validate every legacy value before touching the database, so
        # a failed import never leaves an empty authentication row behind.
        found = {}
        for field, (suffix, pem) in mapping.items():
            if value := self._legacy_value(prefix, suffix, pem=pem):
                found[field] = value
        if not found:
            raise CommandError(f'No legacy variables were found for {prefix}.')
        with transaction.atomic():
            material = EngineAuthMaterial.objects.filter(**{owner_name: owner}).first() or EngineAuthMaterial(
                **{owner_name: owner}
            )
            for field, value in found.items():
                material.set_secret(field, value)
            material.full_clean()
            material.save()
        self.stdout.write(self.style.SUCCESS(
            f'Imported {", ".join(found)}. Remove the legacy variables before restarting NetBox.'
        ))

    def _test(self, options):
        owner_name, owner = self._owner(options)
        if owner_name == 'cluster':
            from netbox_openbao.administration import get_administration_backend

            backend = get_administration_backend(owner).backend
        elif owner_name == 'policy':
            backend = get_backend(owner.engine, owner)
        else:
            backend = get_backend(owner)
        try:
            backend.authenticate()
        except Exception:
            raise CommandError('OpenBao authentication failed.') from None
        self.stdout.write(self.style.SUCCESS('OpenBao authentication succeeded.'))

    def _reencrypt(self, options):
        path = options.get('old_secret_key_file')
        if path:
            try:
                with open(path) as handle:
                    old_key = handle.read().strip()
            except OSError:
                raise CommandError('Could not read the previous SECRET_KEY file.') from None
        elif sys.stdin.isatty():
            old_key = getpass.getpass('Previous Django SECRET_KEY: ').strip()
        else:
            raise CommandError('Use --old-secret-key-file when no interactive terminal is available.')
        try:
            with transaction.atomic():
                rows = list(EngineAuthMaterial.objects.select_for_update())
                for material in rows:
                    material.reencrypt(old_key)
        except AuthMaterialDecryptionError:
            raise CommandError('Auth material re-encryption failed; no rows were changed.') from None
        self.stdout.write(self.style.SUCCESS(f'Re-encrypted {len(rows)} auth material row(s).'))
