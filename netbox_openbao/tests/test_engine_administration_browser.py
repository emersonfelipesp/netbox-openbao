"""Opt-in Playwright coverage for the secrets-engine administration workspace."""

from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from netbox_openbao.administration.engines import normalize_secret_engine_mounts
from netbox_openbao.api import engine_views
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster
from netbox_openbao.tests.test_engine_administration import (
    FakeEngineAdministrationBackend,
    capability_document,
    operation,
)

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional local browser gate
    sync_playwright = None


@skipUnless(sync_playwright, "Install Playwright to run secrets-engine browser tests")
class SecretEngineAdministrationBrowserTest(StaticLiveServerTestCase):
    def setUp(self):
        super().setUp()
        suffix = uuid4().hex[:10]
        self.user = get_user_model().objects.create_superuser(
            username=f"issue67-browser-{suffix}",
            email="browser@example.invalid",
            password="issue67-browser-password",
        )
        self.cluster = OpenBaoCluster.objects.create(
            name=f"Browser cluster {suffix}",
            slug=f"browser-{suffix}",
            api_url="https://bao.example.net:8200",
        )
        self.backend = FakeEngineAdministrationBackend(self.cluster)

    def tearDown(self):
        OpenBaoAdministrationLog.objects.filter(cluster=self.cluster).delete()
        self.cluster.delete()
        self.user.delete()
        super().tearDown()

    def _fixture_teardown(self):
        """Avoid the unrelated netbox-gpon cross-app flush defect in the shared test database."""

    def _login(self, page):
        page.goto(f"{self.live_server_url}/login/", wait_until="networkidle")
        page.locator('input[name="username"]').fill(self.user.username)
        page.locator('input[name="password"]').fill("issue67-browser-password")
        page.locator('button[type="submit"]').click()
        page.wait_for_load_state("networkidle")

    @patch.object(engine_views, "get_administration_backend")
    def test_schema_driven_workspace_is_accessible_and_clears_material(self, get_backend):
        self.backend.mounts = normalize_secret_engine_mounts(
            {"data": {"secret/": {"type": "kv", "options": {"version": "2"}}, "transit/": {"type": "transit"}}}
        )
        get_backend.return_value = self.backend
        browser_driver = sync_playwright().start()
        browser = browser_driver.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            page.clock.install()
            self._login(page)
            url = reverse("plugins:netbox_openbao:openbaocluster_secret_engines", kwargs={"pk": self.cluster.pk})
            page.goto(f"{self.live_server_url}{url}", wait_until="networkidle")
            page.get_by_role("heading", name="Mounted engines").wait_for()
            page.get_by_role("cell", name="secret", exact=True).wait_for()

            unlabeled = page.locator(
                '#openbao-secret-engines input:not([type="hidden"]), '
                "#openbao-secret-engines select, #openbao-secret-engines textarea"
            ).evaluate_all(
                "controls => controls.filter(control => control.name "
                '&& !document.querySelector(`label[for="${control.id}"]`) '
                '&& !document.querySelector(`label[for="${control.id}-ts-control"]`))'
                ".map(control => ({id: control.id, name: control.name, type: control.type}))"
            )
            self.assertEqual(unlabeled, [])

            with page.expect_response(lambda response: response.url.endswith("secret-engine-journeys/")):
                page.get_by_role("button", name="Load available journeys").click()
            journey = page.locator("#openbao-journey-key")
            page.wait_for_function(
                "() => Object.values(document.getElementById('openbao-journey-key').tomselect.options)"
                ".some(option => option.text.includes('Read secret version'))"
            )
            read_journey_key = journey.evaluate(
                "select => Object.entries(select.tomselect.options)"
                ".find(([, option]) => option.text.includes('Read secret version'))[0]"
            )
            journey.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                read_journey_key,
            )
            page.locator("#openbao-journey-resource").fill("team/journey")
            page.locator("#openbao-journey-reason").fill("Exercise first-class material handling.")
            self.backend.material_response = "first-class-canary"
            journey_execution_path = "secret-engine-journeys/execute/"
            with page.expect_response(lambda response: response.url.endswith(journey_execution_path)) as execution:
                page.get_by_role("button", name="Run engine task").click()
            self.assertTrue(execution.value.ok, execution.value.text())
            page.locator("#openbao-journey-result").get_by_text("first-class-canary").wait_for()
            self.assertEqual(page.locator("#openbao-journey-resource").input_value(), "")
            self.assertEqual(page.locator("#openbao-journey-reason").input_value(), "")
            self.assertEqual(page.locator("#openbao-journey-body").input_value(), "{}")

            page.evaluate(
                """() => {
                  window.__openbaoOriginalFetch = window.fetch;
                  window.__openbaoPending = [];
                  window.fetch = (url, options) => String(url).endsWith('secret-engine-journeys/execute/')
                    ? new Promise((resolve) => window.__openbaoPending.push(resolve))
                    : window.__openbaoOriginalFetch(url, options);
                }"""
            )
            page.locator("#openbao-journey-resource").fill("team/stale")
            page.locator("#openbao-journey-reason").fill("Prove stale responses stay cleared.")
            page.get_by_role("button", name="Run engine task").click()
            page.wait_for_function("() => window.__openbaoPending.length === 1")
            journey.evaluate("select => select.dispatchEvent(new Event('change'))")
            page.evaluate(
                """() => window.__openbaoPending[0](new Response(
                  JSON.stringify({data: {password: 'stale-response-canary'}}),
                  {status: 200, headers: {'Content-Type': 'application/json'}}
                ))"""
            )
            page.wait_for_timeout(50)
            self.assertNotIn("stale-response-canary", page.locator("body").inner_text())

            page.evaluate("() => { window.__openbaoPending = []; }")
            for resource, reason in (("team/older", "Older request."), ("team/newer", "Newer request.")):
                page.locator("#openbao-journey-resource").fill(resource)
                page.locator("#openbao-journey-reason").fill(reason)
                page.get_by_role("button", name="Run engine task").click()
            page.wait_for_function("() => window.__openbaoPending.length === 2")
            page.evaluate(
                """() => window.__openbaoPending[1](new Response(
                  JSON.stringify({data: {password: 'newer-response-canary'}}),
                  {status: 200, headers: {'Content-Type': 'application/json'}}
                ))"""
            )
            page.locator("#openbao-journey-result").get_by_text("newer-response-canary").wait_for()
            page.evaluate(
                """() => window.__openbaoPending[0](new Response(
                  JSON.stringify({data: {password: 'older-response-canary'}}),
                  {status: 200, headers: {'Content-Type': 'application/json'}}
                ))"""
            )
            page.wait_for_timeout(50)
            self.assertIn("newer-response-canary", page.locator("#openbao-journey-result").inner_text())
            self.assertNotIn("older-response-canary", page.locator("body").inner_text())
            page.evaluate("() => { window.fetch = window.__openbaoOriginalFetch; }")

            with page.expect_response(lambda response: response.url.endswith("secret-engines/")):
                page.get_by_role("button", name="Refresh mounts").click()
            self.assertEqual(page.locator("#openbao-journey-result").inner_text(), "No result.")
            page.locator("#openbao-journey-body").evaluate(
                '(field) => { field.value = \'{"plaintext":"manual-clear-canary"}\'; }'
            )
            page.locator("#openbao-journey-form").get_by_role("button", name="Clear results").click()
            self.assertEqual(page.locator("#openbao-journey-result").inner_text(), "No result.")
            self.assertEqual(page.locator("#openbao-journey-body").input_value(), "{}")

            page.get_by_role("button", name="Load classified operations").click()
            operation = page.locator("#openbao-operation-key")
            read_operation_key = "secret_mount_path :: kv-read-data-path :: GET /{secret_mount_path}/data/{path}"
            page.wait_for_function(
                "value => Object.hasOwn(document.getElementById('openbao-operation-key').tomselect.options, value)",
                arg=read_operation_key,
            )
            operation.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                read_operation_key,
            )
            self.assertEqual(
                operation.input_value(),
                read_operation_key,
                operation.evaluate("select => Object.keys(select.tomselect.options)"),
            )
            self.assertEqual(page.locator("#openbao-operation-mount").input_value(), "secret")
            page.locator("#openbao-operation-resource").fill("team/db")
            page.locator("#openbao-operation-reason").fill("Exercise material handling.")
            self.backend.material_response = "material-canary-one"
            invalid = page.locator("#openbao-operation-form :invalid").evaluate_all(
                "controls => controls.map(control => "
                "({id: control.id, value: control.value, disabled: control.disabled}))"
            )
            self.assertEqual(invalid, [])
            execution_path = "secret-operations/execute/"
            with page.expect_response(lambda response: response.url.endswith(execution_path)) as execution:
                page.get_by_role("button", name="Execute reviewed operation").click()
            self.assertTrue(execution.value.ok, execution.value.text())
            page.locator("#openbao-operation-result").get_by_text("material-canary-one").wait_for()
            page.clock.fast_forward(299_000)
            self.assertIn("material-canary-one", page.locator("body").inner_text())
            self.backend.material_response = "material-canary-two"
            with page.expect_response(lambda response: response.url.endswith(execution_path)) as execution:
                page.get_by_role("button", name="Execute reviewed operation").click()
            self.assertTrue(execution.value.ok, execution.value.text())
            page.locator("#openbao-operation-result").get_by_text("material-canary-two").wait_for()
            page.clock.fast_forward(2_000)
            self.assertIn("material-canary-two", page.locator("body").inner_text())
            page.clock.fast_forward(298_001)
            self.assertNotIn("material-canary-two", page.locator("body").inner_text())
            page.evaluate(
                """() => {
                  window.__openbaoOriginalFetch = window.fetch;
                  window.__openbaoPending = [];
                  window.fetch = (url, options) => String(url).endsWith('secret-operations/execute/')
                    ? new Promise((resolve) => window.__openbaoPending.push(resolve))
                    : window.__openbaoOriginalFetch(url, options);
                }"""
            )
            page.locator("#openbao-operation-resource").fill("team/db")
            page.locator("#openbao-operation-reason").fill("Prove mount changes invalidate in-flight results.")
            page.get_by_role("button", name="Execute reviewed operation").click()
            page.wait_for_function("() => window.__openbaoPending.length === 1")
            page.locator("#openbao-operation-mount").evaluate(
                "select => { select.tomselect.setValue('transit'); select.dispatchEvent(new Event('change')); }"
            )
            page.evaluate(
                """() => window.__openbaoPending[0](new Response(
                  JSON.stringify({data: {password: 'stale-mount-canary'}}),
                  {status: 200, headers: {'Content-Type': 'application/json'}}
                ))"""
            )
            page.wait_for_timeout(50)
            self.assertEqual(page.locator("#openbao-operation-result").inner_text(), "No result.")
            self.assertNotIn("stale-mount-canary", page.locator("body").inner_text())
            page.evaluate("() => { window.fetch = window.__openbaoOriginalFetch; }")
            page.locator("#openbao-operation-mount").evaluate(
                "select => { select.tomselect.setValue('secret'); select.dispatchEvent(new Event('change')); }"
            )
            page.locator("#openbao-operation-resource").fill("team/db")
            page.locator("#openbao-operation-reason").fill("Verify mount transition clearing.")
            self.backend.material_response = "mount-transition-canary"
            with page.expect_response(lambda response: response.url.endswith(execution_path)) as execution:
                page.get_by_role("button", name="Execute reviewed operation").click()
            self.assertTrue(execution.value.ok, execution.value.text())
            page.locator("#openbao-operation-result").get_by_text("mount-transition-canary").wait_for()
            page.locator("#openbao-operation-mount").evaluate(
                "select => { select.tomselect.setValue('transit'); select.dispatchEvent(new Event('change')); }"
            )
            self.assertEqual(page.locator("#openbao-operation-result").inner_text(), "No result.")
            self.assertNotIn("mount-transition-canary", page.locator("body").inner_text())
            page.locator("#openbao-operation-mount").evaluate(
                "select => { select.tomselect.setValue('secret'); select.dispatchEvent(new Event('change')); }"
            )
            self.assertEqual(errors, [])

            self.backend.discover_capabilities = capability_document
            with page.expect_response(lambda response: response.url.endswith("secret-operations/execute/")):
                page.get_by_role("button", name="Execute reviewed operation").click()
            self.assertEqual(page.locator("#openbao-operation-result").inner_text(), "No result.")
            self.assertIn("alert-danger", page.locator("#openbao-engine-status").get_attribute("class"))
            self.assertEqual(len(errors), 1)
            self.assertIn("400 (Bad Request)", errors.pop())

            operation.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                "secret_mount_path :: kv-write-destroy-path :: POST /{secret_mount_path}/destroy/{path}",
            )
            page.locator("#openbao-operation-resource").fill("team/db")
            expected = f"Enter exactly: POST /secret/destroy/team/db ON {self.cluster.slug}"
            page.locator("#openbao-confirmation-help").get_by_text(expected).wait_for()

            page.set_viewport_size({"width": 390, "height": 844})
            self.assertTrue(
                page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            )
            self.assertEqual(errors, [])
        finally:
            context.close()
            browser.close()
            browser_driver.stop()

    @patch.object(engine_views, "get_administration_backend")
    def test_pki_and_kubernetes_journeys_are_first_class_and_download_is_request_scoped(self, get_backend):
        self.backend.mounts = normalize_secret_engine_mounts(
            {"data": {"pki/": {"type": "pki"}, "kubernetes/": {"type": "kubernetes"}}}
        )
        document = capability_document(
            operation(
                "GET",
                "/{secret_mount_path}/cert/{serial}",
                "pki-read-cert",
                path_parameters=("secret_mount_path", "serial"),
                required_path_parameters=("secret_mount_path", "serial"),
                path_parameter_types=(("secret_mount_path", "string"), ("serial", "string")),
                mount_parameter="pki_mount_path",
            ),
            operation(
                "POST",
                "/{secret_mount_path}/creds/{name}",
                "kubernetes-generate-credentials",
                body_fields=("kubernetes_namespace",),
                required_body_fields=("kubernetes_namespace",),
                body_field_types=(("kubernetes_namespace", "string"),),
                path_parameters=("name", "secret_mount_path"),
                required_path_parameters=("name", "secret_mount_path"),
                path_parameter_types=(("name", "string"), ("secret_mount_path", "string")),
                mount_parameter="kubernetes_mount_path",
            ),
        )
        self.backend.discover_capabilities = lambda: document
        get_backend.return_value = self.backend
        browser_driver = sync_playwright().start()
        browser = browser_driver.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        page = context.new_page()
        try:
            self._login(page)
            url = reverse("plugins:netbox_openbao:openbaocluster_secret_engines", kwargs={"pk": self.cluster.pk})
            page.goto(f"{self.live_server_url}{url}", wait_until="networkidle")
            page.get_by_role("button", name="Load available journeys").click()
            journey = page.locator("#openbao-journey-key")
            page.wait_for_function(
                "() => Object.values(document.getElementById('openbao-journey-key').tomselect.options)"
                ".some(option => option.text.includes('PKI certificates'))"
                " && Object.values(document.getElementById('openbao-journey-key').tomselect.options)"
                ".some(option => option.text.includes('Kubernetes credentials'))"
            )
            credential_key = journey.evaluate(
                "select => Object.entries(select.tomselect.options)"
                ".find(([, option]) => option.text.includes('Kubernetes credentials'))[0]"
            )
            journey.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                credential_key,
            )
            self.assertFalse(page.locator("#openbao-journey-download").is_visible())
            page.locator("#openbao-journey-path").fill('{"name":"operator"}')
            page.locator("#openbao-journey-body").fill('{"kubernetes_namespace":"default"}')
            page.locator("#openbao-journey-reason").fill("Verify request-scoped credential download.")
            self.backend.material_response = "kubernetes-browser-canary"
            with page.expect_response(lambda response: response.url.endswith("secret-engine-journeys/execute/")):
                page.get_by_role("button", name="Run engine task").click()
            page.locator("#openbao-journey-result").get_by_text("kubernetes-browser-canary").wait_for()
            download_button = page.locator("#openbao-journey-download")
            self.assertTrue(download_button.is_visible())
            certificate_key = journey.evaluate(
                "select => Object.entries(select.tomselect.options)"
                ".find(([, option]) => option.text.includes('PKI certificates'))[0]"
            )
            journey.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                certificate_key,
            )
            self.assertEqual(page.locator("#openbao-journey-result").inner_text(), "No result.")
            self.assertFalse(download_button.is_visible())
            journey.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                credential_key,
            )
            page.locator("#openbao-journey-path").fill('{"name":"operator"}')
            page.locator("#openbao-journey-body").fill('{"kubernetes_namespace":"default"}')
            page.locator("#openbao-journey-reason").fill("Verify catalog refresh clearing.")
            self.backend.material_response = "kubernetes-refresh-canary"
            with page.expect_response(lambda response: response.url.endswith("secret-engine-journeys/execute/")):
                page.get_by_role("button", name="Run engine task").click()
            page.locator("#openbao-journey-result").get_by_text("kubernetes-refresh-canary").wait_for()
            with page.expect_response(lambda response: response.url.endswith("secret-engine-journeys/")):
                page.get_by_role("button", name="Load available journeys").click()
            self.assertEqual(page.locator("#openbao-journey-result").inner_text(), "No result.")
            self.assertFalse(download_button.is_visible())

            journey.evaluate(
                "(select, value) => { select.tomselect.setValue(value); select.dispatchEvent(new Event('change')); }",
                credential_key,
            )
            page.locator("#openbao-journey-path").fill('{"name":"operator"}')
            page.locator("#openbao-journey-body").fill('{"kubernetes_namespace":"default"}')
            page.locator("#openbao-journey-reason").fill("Verify request-scoped credential download.")
            self.backend.material_response = "kubernetes-download-canary"
            with page.expect_response(lambda response: response.url.endswith("secret-engine-journeys/execute/")):
                page.get_by_role("button", name="Run engine task").click()
            page.locator("#openbao-journey-result").get_by_text("kubernetes-download-canary").wait_for()
            with page.expect_download() as download:
                download_button.click()
            self.assertEqual(download.value.suggested_filename, "openbao-kubernetes-credentials.json")
            page.locator("#openbao-journey-form").get_by_role("button", name="Clear results").click()
            self.assertFalse(download_button.is_visible())
        finally:
            context.close()
            browser.close()
            browser_driver.stop()
