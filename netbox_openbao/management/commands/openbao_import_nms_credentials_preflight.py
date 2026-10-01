import json

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection

from netbox_openbao.config import get_config
from netbox_openbao.models import CredentialPolicy
from netbox_openbao.models.settings import validate_path_prefix


class Command(BaseCommand):
    help = 'Validate netbox-openbao importer startup, configuration, and database readiness without writes.'

    def handle(self, *args, **options):
        del args, options
        try:
            startup_ready = self._startup_is_ready()
        except Exception:
            startup_ready = False
        if not startup_ready:
            self._fail('startup')
        try:
            database_ready = self._database_is_ready()
        except Exception:
            database_ready = False
        if not database_ready:
            self._fail('database')
        try:
            configuration_ready = self._static_configuration_is_ready()
        except DatabaseError:
            self._fail('database')
        except Exception:
            configuration_ready = False
        if not configuration_ready:
            self._fail('configuration')
        try:
            policy_ready = CredentialPolicy.objects.exists()
        except Exception:
            self._fail('database')
        if not policy_ready:
            self._fail('configuration')
        self._emit('complete')

    @staticmethod
    def _startup_is_ready():
        if not apps.ready:
            return False
        if not apps.is_installed('netbox_openbao') or not apps.is_installed('netbox_rpc'):
            return False
        try:
            return apps.get_app_config('netbox_openbao').name == 'netbox_openbao'
        except LookupError:
            return False

    @staticmethod
    def _static_configuration_is_ready():
        try:
            validate_path_prefix(get_config('path_prefix', 'netbox'))
        except DatabaseError:
            raise
        except Exception:
            return False
        return True

    @staticmethod
    def _database_is_ready():
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            return cursor.fetchone() == (1,)

    def _emit(self, category):
        self.stdout.write(json.dumps({
            'version': 1,
            'action': 'preflight',
            'category': category,
            'process_started': True,
            'summary': None,
        }, separators=(',', ':')))

    def _fail(self, category):
        self._emit(category)
        raise CommandError('netbox-openbao importer preflight failed.')
