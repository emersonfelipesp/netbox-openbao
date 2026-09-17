"""Opt-in Playwright coverage for leases, tools, and UI configuration."""

from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from netbox_openbao.api import finalization_views
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster
from netbox_openbao.tests.test_finalization_administration import FakeFinalBackend

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional local browser gate
    sync_playwright = None


@skipUnless(sync_playwright, "Install Playwright to run finalization administration browser tests")
class FinalizationAdministrationBrowserTest(StaticLiveServerTestCase):
    def setUp(self):
        super().setUp()
        suffix = uuid4().hex[:10]
        self.password = "issue70-browser-password"
        self.user = get_user_model().objects.create_superuser(
            username=f"issue70-browser-{suffix}", email="browser@example.invalid", password=self.password
        )
        self.cluster = OpenBaoCluster.objects.create(
            name=f"Browser cluster {suffix}", slug=f"browser-{suffix}", api_url="https://bao.example.net:8200"
        )
        self.backend = FakeFinalBackend()

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
        page.locator('input[name="password"]').fill(self.password)
        page.locator('button[type="submit"]').click()
        page.wait_for_load_state("networkidle")

    @patch.object(finalization_views, "get_administration_backend")
    def test_direct_workspace_is_accessible_and_clears_material(self, get_backend):
        get_backend.return_value = self.backend
        driver = sync_playwright().start()
        browser = driver.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            self._login(page)
            path = reverse("plugins:netbox_openbao:openbaocluster_operations", kwargs={"pk": self.cluster.pk})
            page.goto(f"{self.live_server_url}{path}", wait_until="networkidle")
            page.get_by_role("heading", name="Leases, tools, and UI configuration").wait_for()
            resources = set(
                page.locator("#openbao-final-resource option").evaluate_all(
                    "options => options.map(option => option.value)"
                )
            )
            self.assertEqual(resources, {"leases", "wrapping", "hash", "random", "token-tools", "ui-headers"})

            unlabeled = page.locator(
                '#openbao-final input:not([type="hidden"]), #openbao-final select, #openbao-final textarea'
            ).evaluate_all(
                "controls => controls.filter(control => control.name && control.labels.length === 0)"
                ".map(control => control.id)"
            )
            self.assertEqual(unlabeled, [])

            page.locator("#openbao-final-resource").select_option("random")
            page.locator("#openbao-final-operation").select_option("generate")
            page.locator("#openbao-final-identifier").fill("platform")
            page.locator('[name="bytes"]').fill("8")
            page.locator("#openbao-final-reason").fill("Exercise request-scoped entropy.")
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-final-result").get_by_text("material-canary").wait_for()
            page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
            self.assertNotIn("material-canary", page.locator("body").inner_text())

            page.locator("#openbao-final-resource").select_option("wrapping")
            page.locator("#openbao-final-operation").select_option("wrap")
            page.locator('[name="data"]').fill('{"secret":"wrap-input-canary"}')
            page.get_by_role("button", name="Clear", exact=True).click()
            self.assertEqual(page.locator('[name="data"]').input_value(), "")

            page.locator("#openbao-final-resource").select_option("ui-headers")
            page.locator("#openbao-final-operation").select_option("write")
            page.locator("#openbao-final-identifier").fill("X-Issue70-Browser")
            page.locator('[name="values"]').fill('["created"]')
            page.locator("#openbao-final-reason").fill("Create a reviewed UI header.")
            page.get_by_role("button", name="Preview impact").click()
            page.locator("#openbao-final-impact-output").get_by_text('"state": "absent"').wait_for()
            header_confirmation = f"REPLACE UI header X-Issue70-Browser ON {self.cluster.slug}"
            page.locator("#openbao-final-confirmation").fill(header_confirmation)
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-final-result").get_by_text('"accepted": true').wait_for()

            page.locator("#openbao-final-resource").select_option("leases")
            page.locator("#openbao-final-operation").select_option("list")
            page.locator("#openbao-final-identifier").fill("")
            page.locator("#openbao-final-reason").fill("Browse lease roots.")
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-final-result").get_by_text("database/").wait_for()

            page.locator("#openbao-final-operation").select_option("force-revoke")
            page.locator("#openbao-final-identifier").fill("database")
            page.locator("#openbao-final-reason").fill("Reconcile a failed backend.")
            page.get_by_role("button", name="Preview impact").click()
            expected = f"FORCE REVOKE lease prefix database ON {self.cluster.slug}"
            page.locator("#openbao-final-confirmation-hint").get_by_text(expected).wait_for()
            page.locator("#openbao-final-confirmation").fill(expected)
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-final-result").get_by_text('"accepted": true').wait_for()

            page.set_viewport_size({"width": 390, "height": 844})
            self.assertTrue(
                page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            )
            self.assertEqual(errors, [])
        finally:
            context.close()
            browser.close()
            driver.stop()
