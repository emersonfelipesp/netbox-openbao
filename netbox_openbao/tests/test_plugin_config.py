"""
The package attribute `config` must stay the PluginConfig class for the life of
the process.

NetBox reads `importlib.import_module(name).config` once at startup and again on
every request to the plugins page (`core.plugins.get_local_plugins()`). A
submodule named `config` defeats that: importing it binds the module object to
the package attribute of the same name, replacing the class. Startup still
works, because it reads the attribute before `ready()` imports anything, and the
plugins page then fails with "module 'netbox_openbao.config' has no attribute
'version'". These tests run after `ready()`, which is when the damage happens.
"""

import importlib
import pkgutil

from django.test import TestCase

import netbox_openbao
from netbox_openbao import NetBoxOpenBaoConfig


class PluginConfigAttributeTest(TestCase):

    def test_package_config_is_the_plugin_config_class(self):
        # Re-import every submodule first: one of them binding `config` is
        # exactly the failure, so the assertion must follow the imports. Some
        # modules read the settings row at import (serializer field choices),
        # which is why this is a database-backed TestCase.
        for module in pkgutil.walk_packages(netbox_openbao.__path__, 'netbox_openbao.'):
            if '.tests' in module.name:
                continue
            importlib.import_module(module.name)

        self.assertIs(importlib.import_module('netbox_openbao').config, NetBoxOpenBaoConfig)

    def test_package_has_no_config_submodule(self):
        names = {module.name for module in pkgutil.iter_modules(netbox_openbao.__path__)}
        self.assertNotIn('config', names)

    def test_netbox_plugin_listing_reads_this_plugin(self):
        # The exact production path behind the plugins page.
        from core.plugins import get_local_plugins

        plugins = get_local_plugins()

        self.assertIn('netbox_openbao', plugins)
        self.assertEqual(
            plugins['netbox_openbao'].installed_version,
            NetBoxOpenBaoConfig.version,
        )
