"""Opt-in Playwright coverage for the secrets-engine administration workspace."""

from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from netbox_openbao.api import engine_views
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster
from netbox_openbao.tests.test_engine_administration import (
    FakeEngineAdministrationBackend,
    capability_document,
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
