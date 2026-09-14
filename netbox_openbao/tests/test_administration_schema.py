"""Fail-closed capability discovery and parity-manifest tests."""

from copy import deepcopy
from unittest import TestCase

from netbox_openbao.administration.parity import BASELINE_VERSION, load_parity_manifest
from netbox_openbao.administration.schema import CapabilitySchemaError, normalize_openapi_document


def _document():
    return {
        'openapi': '3.0.2',
        'info': {
            'title': 'OpenBao',
            'version': '2.6.2',
            'description': 'First line.\nSecond line.',
        },
        'paths': {
            '/v1/sys/health': {
                'get': {
                    'operationId': 'sysHealth',
                    'summary': 'Read cluster health',
                    'tags': ['system'],
                },
            },
            '/v1/auth/approle/login': {
                'post': {
                    'operationId': 'approleLogin',
                    'summary': 'Authenticate with AppRole',
                    'tags': ['auth'],
                },
            },
            '/v1/example/data/{name}': {
                'delete': {
                    'operationId': 'exampleDelete',
                    'summary': 'Delete example data',
                    'tags': ['example'],
                },
            },
        },
    }


class CapabilitySchemaTest(TestCase):

    def test_normalization_is_stable_classified_and_never_executable(self):
        first = normalize_openapi_document(_document())
        reordered = {
            'paths': dict(reversed(list(_document()['paths'].items()))),
            'info': _document()['info'],
            'openapi': '3.0.2',
        }
        second = normalize_openapi_document(reordered)

        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.product_version, '2.6.2')
        self.assertEqual(len(first.operations), 3)
        self.assertFalse(any(operation.executable for operation in first.operations))

        operations = {operation.operation_id: operation for operation in first.operations}
        self.assertEqual(operations['sysHealth'].family, 'cluster')
        self.assertEqual(operations['approleLogin'].family, 'authentication')
        self.assertEqual(operations['approleLogin'].risk_level, 'write')
        self.assertEqual(
            operations['approleLogin'].required_permission,
            'netbox_openbao.operate_openbaocluster',
        )
        self.assertEqual(operations['exampleDelete'].family, 'unclassified')
        self.assertEqual(operations['exampleDelete'].required_permission, '')

    def test_multiline_descriptions_are_allowed_but_nul_is_rejected(self):
        normalize_openapi_document(_document())
        hostile = _document()
        hostile['info']['description'] = 'hidden\x00tail'

        with self.assertRaisesRegex(CapabilitySchemaError, 'invalid string'):
            normalize_openapi_document(hostile)

    def test_path_traversal_is_rejected(self):
        hostile = _document()
        hostile['paths']['/v1/sys/../raw'] = hostile['paths'].pop('/v1/sys/health')

        with self.assertRaisesRegex(CapabilitySchemaError, 'unsafe path'):
            normalize_openapi_document(hostile)

    def test_openbao_generic_mount_regex_path_is_allowed(self):
        document = _document()
        document['paths']['/{secret_mount_path}/^.*$'] = document['paths'].pop('/v1/sys/health')

        normalized = normalize_openapi_document(document)

        operation = next(item for item in normalized.operations if item.operation_id == 'sysHealth')
        self.assertEqual(operation.operation_key, 'GET /{secret_mount_path}/^.*$')

    def test_duplicate_openbao_operation_ids_get_unique_method_path_keys(self):
        document = _document()
        document['paths']['/v1/auth/approle/login']['post']['operationId'] = 'sysHealth'

        normalized = normalize_openapi_document(document)
        duplicates = [operation for operation in normalized.operations if operation.operation_id == 'sysHealth']

        self.assertEqual(len(duplicates), 2)
        self.assertEqual(len({operation.operation_key for operation in duplicates}), 2)

    def test_invalid_operation_id_is_rejected(self):
        hostile = _document()
        hostile['paths']['/v1/sys/health']['get']['operationId'] = '../invalid'

        with self.assertRaisesRegex(CapabilitySchemaError, 'invalid operation ID'):
            normalize_openapi_document(hostile)

    def test_non_openapi_object_is_rejected(self):
        for value in (
            None,
            [],
            {'openapi': '2.0', 'info': {}, 'paths': {}},
            {'openapi': '3.evil', 'info': {}, 'paths': {}},
        ):
            with self.subTest(value=value), self.assertRaises(CapabilitySchemaError):
                normalize_openapi_document(value)

    def test_non_finite_numbers_are_rejected(self):
        hostile = _document()
        hostile['info']['score'] = float('nan')

        with self.assertRaisesRegex(CapabilitySchemaError, 'unsupported value'):
            normalize_openapi_document(hostile)

    def test_excessive_depth_is_rejected(self):
        hostile = _document()
        nested = hostile['info']
        for _ in range(32):
            nested['child'] = {}
            nested = nested['child']

        with self.assertRaisesRegex(CapabilitySchemaError, 'nested too deeply'):
            normalize_openapi_document(hostile)

    def test_unknown_http_members_do_not_become_operations(self):
        document = _document()
        document['paths']['/v1/sys/health']['parameters'] = [{'name': 'standbyok'}]

        normalized = normalize_openapi_document(document)

        self.assertEqual(len(normalized.operations), 3)


class ParityManifestTest(TestCase):

    def test_manifest_pins_every_family_to_a_work_item(self):
        manifest = load_parity_manifest()

        self.assertEqual(manifest['baseline'], BASELINE_VERSION)
        self.assertEqual(len(manifest['families']), 19)
        self.assertEqual(
            {family['owner_issue'] for family in manifest['families']},
            set(range(64, 71)),
        )

    def test_manifest_loader_returns_an_independent_document(self):
        first = load_parity_manifest()
        second = deepcopy(load_parity_manifest())
        second['families'][0]['status'] = 'complete'

        self.assertNotEqual(first, second)
