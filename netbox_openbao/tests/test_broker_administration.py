"""Direct/broker administration conformance and hostile transport tests."""

import io
import json
import os
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from netbox_openbao.administration.backends import BrokerAdministrationBackend, DirectAdministrationBackend
from netbox_openbao.administration.broker import CONTRACT_DIGEST, EXPECTED_FAMILIES, EXPECTED_OPERATIONS
from netbox_openbao.backends.exceptions import (
    BackendConfigurationError,
    OpenBaoMutationUnknown,
    OpenBaoUnavailable,
)


class _Raw:
    def __init__(self, body: bytes, chunks=None):
        self.body = io.BytesIO(body)
        self._chunks = chunks

    def read(self, amount=-1, *, decode_content=False):
        del decode_content
        return self.body.read(amount)

    def stream(self, amount, *, decode_content=False):
        del amount, decode_content
        if self._chunks is not None:
            yield from self._chunks
            return
        while chunk := self.body.read(64 * 1024):
            yield chunk


class _Response:
    def __init__(self, payload=None, *, status=200, headers=None, raw=b"", chunks=None, redirect=None):
        if payload is not None:
            raw = json.dumps(payload).encode()
        self.status_code = status
        self.headers = headers or {}
        self.raw = _Raw(raw, chunks)
        self.is_redirect = 300 <= status < 400 if redirect is None else redirect
        self.closed = False

    def close(self):
        self.closed = True


def _contract(*, digest=CONTRACT_DIGEST, operations=EXPECTED_OPERATIONS):
    return {
        "version": "1",
        "digest": digest,
        "families": sorted(EXPECTED_FAMILIES),
        "operations": [
            {"name": name, "family": family, "framing": framing}
            for name, family, framing in operations
        ],
    }


def _cluster():
    return SimpleNamespace(
        api_url="https://broker.invalid:8201",
        ca_cert_path="/etc/ssl/broker-ca.pem",
        tls_verify=True,
        namespace="",
        slug="test",
        env_prefix="TEST_BROKER",
    )


class _BrokerSession:
    def __init__(self, results=None, *, contract=None, request_failure=None):
        self.results = results or {}
        self.contract = contract or _contract()
        self.request_failure = request_failure
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.request_failure:
            raise self.request_failure
        if url.endswith("/v1/administration/contract"):
            return _Response(self.contract)
        operation = kwargs.get("json", {}).get("operation")
        result = self.results[operation]
        if isinstance(result, _Response):
            return result
        return _Response({"data": result})


class BrokerContractTest(SimpleTestCase):
    def backend(self, session):
        backend = BrokerAdministrationBackend(_cluster())
        backend.backend._get_session = Mock(return_value=session)
        return backend

    def test_contract_is_verified_once_before_execution(self):
        session = _BrokerSession({"initialization_status": {"initialized": True}})
        backend = self.backend(session)

        self.assertTrue(backend.initialization_status())
        self.assertTrue(backend.initialization_status())

        self.assertEqual(sum(call[1].endswith("/contract") for call in session.calls), 1)
        requests = [call for call in session.calls if call[1].endswith("/request")]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0][2]["json"]["contract_digest"], CONTRACT_DIGEST)

    def test_stale_incomplete_and_malformed_contracts_fail_closed(self):
        cases = (
            _contract(digest="0" * 64),
            _contract(operations=frozenset(tuple(EXPECTED_OPERATIONS)[:-1])),
            {"version": "1", "digest": CONTRACT_DIGEST, "families": [], "operations": "invalid"},
        )
        for contract in cases:
            with self.subTest(contract=contract):
                session = _BrokerSession(contract=contract)
                with self.assertRaises(BackendConfigurationError):
                    self.backend(session).initialization_status()
                self.assertEqual(len(session.calls), 1)

    def test_read_outage_and_mutation_outage_have_distinct_safe_semantics(self):
        read_session = _BrokerSession(request_failure=OSError("secret diagnostic"))
        with self.assertRaises(OpenBaoUnavailable) as read_error:
            self.backend(read_session).initialization_status()
        self.assertNotIn("secret diagnostic", str(read_error.exception))

        backend = self.backend(_BrokerSession({"seal": _Response(status=503)}))
        with self.assertRaises(OpenBaoMutationUnknown):
            backend.seal()

    def test_malformed_mutation_response_is_unknown(self):
        response = _Response(raw=b'{"data":')
        backend = self.backend(_BrokerSession({"seal": response}))
        with self.assertRaises(OpenBaoMutationUnknown):
            backend.seal()
        self.assertTrue(response.closed)

    def test_non_redirect_3xx_json_response_fails_closed(self):
        response = _Response({"data": {"initialized": True}}, status=304, redirect=False)
        backend = self.backend(_BrokerSession({"initialization_status": response}))
        with self.assertRaises(OpenBaoUnavailable):
            backend.initialization_status()
        self.assertTrue(response.closed)

    def test_semantically_invalid_cluster_mutation_results_are_unknown(self):
        for operation, invoke in (
            ("initialize", lambda backend: backend.initialize({"secret_shares": 1, "secret_threshold": 1})),
            ("unseal", lambda backend: backend.unseal(key="share")),
        ):
            with self.subTest(operation=operation):
                backend = self.backend(_BrokerSession({operation: {"invalid": True}}))
                with self.assertRaises(OpenBaoMutationUnknown):
                    invoke(backend)

    def test_semantically_invalid_secret_engine_remount_is_unknown(self):
        backend = self.backend(
            _BrokerSession({"execute_secret_engine_operation": {"data": "invalid"}})
        )
        with self.assertRaises(OpenBaoMutationUnknown):
            backend.remount_secret_engine("old", "new")

    def test_mounted_request_carries_the_exact_advertised_contract(self):
        session = _BrokerSession({"execute_mounted_operation": {"data": {"value": "ok"}}})
        result = self.backend(session).execute_mounted_operation(
            "GET",
            "/team-kv/data/service",
            query={"version": 1},
            body={},
            mount_path="team-kv",
            operation_id="kvRead",
            path_template="/{secret_mount_path}/data/{path}",
            mount_parameter="team_kv_mount_path",
        )

        self.assertEqual(result, {"data": {"value": "ok"}})
        arguments = session.calls[-1][2]["json"]["arguments"]
        self.assertEqual(arguments["path_template"], "/{team_kv_mount_path}/data/{path}")
        self.assertNotIn("api_url", arguments)
        self.assertNotIn("token", arguments)

    def test_snapshot_download_stays_streamed_and_bounded(self):
        response = _Response(
            headers={"Content-Length": "8", "Content-Type": "application/octet-stream"},
            chunks=(b"snap", b"shot"),
        )
        session = _BrokerSession()

        def request(method, url, **kwargs):
            session.calls.append((method, url, kwargs))
            if url.endswith("/contract"):
                return _Response(_contract())
            return response

        session.request = request
        snapshot = self.backend(session).download_raft_snapshot()
        self.assertEqual(b"".join(snapshot.chunks()), b"snapshot")
        self.assertTrue(response.closed)
        self.assertEqual(session.calls[-1][2]["headers"]["Accept-Encoding"], "identity")

    def test_partial_snapshot_response_fails_closed(self):
        response = _Response(
            status=206,
            headers={"Content-Length": "4", "Content-Type": "application/octet-stream"},
            chunks=(b"part",),
        )
        session = _BrokerSession()

        def request(method, url, **kwargs):
            if url.endswith("/contract"):
                return _Response(_contract())
            return response

        session.request = request
        with self.assertRaises(OpenBaoUnavailable):
            self.backend(session).download_raft_snapshot()
        self.assertTrue(response.closed)

    def test_snapshot_restore_is_exactly_sized_and_malformed_success_is_unknown(self):
        response = _Response({"restored": True})
        session = _BrokerSession()

        def request(method, url, **kwargs):
            session.calls.append((method, url, kwargs))
            if url.endswith("/contract"):
                return _Response(_contract())
            return response

        session.request = request
        self.backend(session).restore_raft_snapshot(io.BytesIO(b"snapshot"), 8, force=True)
        call = session.calls[-1]
        self.assertEqual(call[2]["headers"]["Content-Length"], "8")
        self.assertEqual(call[2]["params"], {"force": "true"})
        self.assertTrue(response.closed)

        malformed = _Response({"restored": "maybe"})
        session = _BrokerSession()

        def malformed_request(method, url, **kwargs):
            if url.endswith("/contract"):
                return _Response(_contract())
            return malformed

        session.request = malformed_request
        with self.assertRaises(OpenBaoMutationUnknown):
            self.backend(session).restore_raft_snapshot(io.BytesIO(b"snapshot"), 8)


class AdministrationTransportConformanceTest(SimpleTestCase):
    """The direct and broker transports normalize the same reviewed families."""

    CASES = (
        ("cluster", "seal_status", (), {}),
        ("secret-engines", "list_secret_engines", (), {}),
        ("authentication", "list_auth_methods", (), {}),
        (
            "access",
            "execute_access_operation",
            ("GET", "/sys/policies/acl/application"),
            {"payload": {}},
        ),
        (
            "finalization",
            "execute_final_operation",
            ("GET", "/sys/config/ui/headers/X-Frame-Options"),
            {"payload": {}},
        ),
    )

    def direct_backend(self, response):
        backend = DirectAdministrationBackend(_cluster())
        backend.backend._get_client = Mock(return_value=SimpleNamespace(token="ephemeral"))
        backend.backend._get_session = Mock(return_value=SimpleNamespace(request=Mock(return_value=response)))
        return backend

    def broker_backend(self, operation, payload):
        backend = BrokerAdministrationBackend(_cluster())
        session = _BrokerSession({operation: payload})
        backend.backend._get_session = Mock(return_value=session)
        return backend

    def test_json_families_have_matching_normalized_results(self):
        payloads = {
            "cluster": {
                "initialized": True,
                "sealed": True,
                "t": 3,
                "n": 5,
                "progress": 0,
                "version": "2.6.2",
                "type": "shamir",
                "migration": False,
                "recovery_seal": False,
                "storage_type": "raft",
            },
            "secret-engines": {
                "data": {"secret/": {"type": "kv", "accessor": "kv_1", "options": {"version": "2"}}}
            },
            "authentication": {
                "data": {"userpass/": {"type": "userpass", "accessor": "auth_userpass_1"}}
            },
            "access": {"data": {"name": "application", "policy": "path * {}"}},
            "finalization": {"data": {"value": ["DENY"]}},
        }
        operations = {
            "cluster": "seal_status",
            "secret-engines": "execute_secret_engine_operation",
            "authentication": "execute_authentication_operation",
            "access": "execute_access_operation",
            "finalization": "execute_final_operation",
        }
        for family, method, args, kwargs in self.CASES:
            with self.subTest(family=family):
                payload = payloads[family]
                direct = self.direct_backend(_Response(payload))
                broker = self.broker_backend(operations[family], payload)
                self.assertEqual(getattr(direct, method)(*args, **kwargs), getattr(broker, method)(*args, **kwargs))

    def test_every_complete_ui_family_dispatches_through_a_broker_operation(self):
        backend = BrokerAdministrationBackend(_cluster())
        backend.client.execute = Mock(return_value={"data": {}})
        backend._normalize = Mock(side_effect=lambda normalizer, payload: payload)
        backend._normalize_mutation = Mock(side_effect=lambda normalizer, payload: payload)

        def mounted(mount):
            return backend.execute_mounted_operation(
                "GET",
                f"/{mount}/item",
                query={},
                body={},
                mount_path=mount,
                operation_id=f"{mount}Read",
                path_template="/{secret_mount_path}/{path}",
                mount_parameter=f"{mount}_mount_path",
            )
        cases = (
            ("cluster-session", lambda: backend.token_operation("lookup-self", {"token": "request-token"}),
             "execute_authentication_operation"),
            ("cluster-bootstrap", lambda: backend.initialize({"secret_shares": 1, "secret_threshold": 1}),
             "initialize"),
            ("api-explorer", lambda: mounted("explorer"), "execute_mounted_operation"),
            ("auth-methods", backend.list_auth_methods, "execute_authentication_operation"),
            ("mfa", backend.list_mfa_methods, "execute_authentication_operation"),
            ("engine-lifecycle", backend.list_secret_engines, "execute_secret_engine_operation"),
            ("generic-secrets", lambda: mounted("generic"), "execute_mounted_operation"),
            ("kv", lambda: mounted("kv"), "execute_mounted_operation"),
            ("common-engines", lambda: mounted("common"), "execute_mounted_operation"),
            ("pki", lambda: mounted("pki"), "execute_mounted_operation"),
            ("kubernetes", lambda: mounted("kubernetes"), "execute_mounted_operation"),
            ("policies", lambda: backend.execute_access_operation(
                "GET", "/sys/policies/acl/application", payload={}
            ), "execute_access_operation"),
            ("identity", lambda: backend.execute_access_operation(
                "GET", "/identity/entity/id/01234567-89ab-cdef-0123-456789abcdef", payload={}
            ), "execute_access_operation"),
            ("oidc", lambda: backend.execute_access_operation(
                "GET", "/identity/oidc/client/application", payload={}
            ), "execute_access_operation"),
            ("namespaces", lambda: backend.execute_access_operation(
                "GET", "/sys/namespaces/team", payload={}
            ), "execute_access_operation"),
            ("leases", lambda: backend.execute_final_operation(
                "LIST", "/sys/leases/lookup/application", payload={}
            ), "execute_final_operation"),
            ("tools", lambda: backend.execute_final_operation(
                "POST", "/sys/tools/hash/sha2-256", payload={"input": "YQ=="}
            ), "execute_final_operation"),
            ("ui-configuration", lambda: backend.execute_final_operation(
                "GET", "/sys/config/ui/headers/X-Frame-Options", payload={}
            ), "execute_final_operation"),
        )
        for family, invoke, operation in cases:
            with self.subTest(family=family):
                backend.client.execute.reset_mock()
                invoke()
                self.assertEqual(backend.client.execute.call_args.args[0], operation)

        # Raw Raft snapshot framing has dedicated download and restore tests in
        # this class because it deliberately does not use the JSON operation.
        covered_families = {family for family, _invoke, _operation in cases} | {"raft-storage"}
        self.assertEqual(
            covered_families,
            {
                "cluster-session", "cluster-bootstrap", "api-explorer", "raft-storage",
                "auth-methods", "mfa", "engine-lifecycle", "generic-secrets", "kv",
                "common-engines", "pki", "kubernetes", "policies", "identity", "oidc",
                "namespaces", "leases", "tools", "ui-configuration",
            },
        )


BROKER_ADDR = os.environ.get("NETBOX_OPENBAO_BROKER_ADDR")
BROKER_CERT = os.environ.get("NETBOX_OPENBAO_BROKER_CERT")
BROKER_KEY = os.environ.get("NETBOX_OPENBAO_BROKER_KEY")
BROKER_CA = os.environ.get("NETBOX_OPENBAO_BROKER_CA")
BROKER_ADMIN_MOUNT = os.environ.get("NETBOX_OPENBAO_BROKER_ADMIN_MOUNT")


@unittest.skipUnless(
    BROKER_ADDR and BROKER_CERT and BROKER_KEY and BROKER_ADMIN_MOUNT,
    "Set NETBOX_OPENBAO_BROKER_ADDR/_CERT/_KEY/_ADMIN_MOUNT for broker administration integration",
)
class BrokerAdministrationIntegrationTest(SimpleTestCase):
    """Exercise the pinned administration contract through real mTLS and OpenBao 2.6.2."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cert_name = "NETBOX_BAO_BROKER_ADMIN_LIVE_CLIENT_CERT"
        cls.key_name = "NETBOX_BAO_BROKER_ADMIN_LIVE_CLIENT_KEY"
        os.environ[cls.cert_name] = BROKER_CERT
        os.environ[cls.key_name] = BROKER_KEY
        cluster = SimpleNamespace(
            api_url=BROKER_ADDR,
            ca_cert_path=BROKER_CA or "",
            tls_verify=True,
            namespace="",
            slug="broker-admin-live",
            env_prefix="NETBOX_BAO_BROKER_ADMIN_LIVE",
        )
        cls.backend = BrokerAdministrationBackend(cluster)

    @classmethod
    def tearDownClass(cls):
        cls.backend.backend.invalidate_token()
        os.environ.pop(cls.cert_name, None)
        os.environ.pop(cls.key_name, None)
        super().tearDownClass()

    @staticmethod
    def _operation(document, method, suffix):
        matches = [
            operation
            for operation in document.operations
            if operation.method == method and operation.path_template.endswith(suffix)
        ]
        if len(matches) != 1:
            raise AssertionError(f"Expected one {method} mounted operation ending in {suffix!r}.")
        return matches[0]

    def _execute(self, operation, path, *, body=None):
        return self.backend.execute_mounted_operation(
            operation.method,
            path,
            query={},
            body=body or {},
            mount_path=BROKER_ADMIN_MOUNT,
            operation_id=operation.operation_id,
            path_template=operation.path_template,
            mount_parameter=operation.mount_parameter,
        )

    def test_real_broker_contract_discovery_and_mounted_round_trip(self):
        document = self.backend.discover_capabilities()
        self.assertEqual(document.product_version, "2.6.2")
        self.assertTrue(self.backend.seal_status().initialized)
        self.assertIsInstance(self.backend.list_secret_engines(), tuple)
        self.assertIsInstance(self.backend.list_auth_methods(), tuple)
        self.assertIsInstance(
            self.backend.execute_access_operation("LIST", "/sys/policies/acl", payload={}), dict
        )
        self.assertIsInstance(
            self.backend.execute_final_operation("LIST", "/sys/config/ui/headers", payload={}), dict
        )

        name = f"issue82-{uuid.uuid4().hex}"
        write = self._operation(document, "POST", "/data/{path}")
        read = self._operation(document, "GET", "/data/{path}")
        delete = self._operation(document, "DELETE", "/metadata/{path}")
        path = f"/{BROKER_ADMIN_MOUNT}/data/{name}"
        try:
            self._execute(write, path, body={"data": {"canary": "request-scoped"}})
            result = self._execute(read, path)
            self.assertEqual(result["data"]["data"], {"canary": "request-scoped"})
        finally:
            self._execute(delete, f"/{BROKER_ADMIN_MOUNT}/metadata/{name}")
