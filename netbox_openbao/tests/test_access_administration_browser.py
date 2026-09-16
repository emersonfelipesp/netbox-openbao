"""Opt-in Playwright coverage for the access administration workspace."""

from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from netbox_openbao.api import access_views
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster
from netbox_openbao.tests.test_access_administration import FakeAccessBackend

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional local browser gate
    sync_playwright = None


@skipUnless(sync_playwright, "Install Playwright to run access administration browser tests")
class AccessAdministrationBrowserTest(StaticLiveServerTestCase):
    def setUp(self):
        super().setUp()
        suffix = uuid4().hex[:10]
        self.user = get_user_model().objects.create_superuser(
            username=f"issue69-browser-{suffix}",
            email="browser@example.invalid",
            password="issue69-browser-password",
        )
        self.cluster = OpenBaoCluster.objects.create(
            name=f"Browser cluster {suffix}",
            slug=f"browser-{suffix}",
            api_url="https://bao.example.net:8200",
        )
        self.backend = FakeAccessBackend(self.cluster)

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
        page.locator('input[name="password"]').fill("issue69-browser-password")
        page.locator('button[type="submit"]').click()
        page.wait_for_load_state("networkidle")

    @patch.object(access_views, "get_administration_backend")
    def test_all_route_families_are_accessible_and_material_is_ephemeral(self, get_backend):
        get_backend.return_value = self.backend
        browser_driver = sync_playwright().start()
        browser = browser_driver.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            self._login(page)
            url = reverse("plugins:netbox_openbao:openbaocluster_access", kwargs={"pk": self.cluster.pk})
            page.goto(f"{self.live_server_url}{url}", wait_until="networkidle")
            page.get_by_role("heading", name="Access administration").wait_for()
            page.get_by_text("Loaded 12 permission-filtered resource families.").wait_for()

            unlabeled = page.locator(
                '#openbao-access input:not([type="hidden"]), #openbao-access select, #openbao-access textarea'
            ).evaluate_all(
                "controls => controls.filter(control => control.name && control.labels.length === 0 "
                "&& !document.querySelector('label[for=\"' + control.id + '-ts-control\"]'))"
                ".map(control => ({id: control.id, name: control.name, type: control.type}))"
            )
            self.assertEqual(unlabeled, [])

            resources = set(page.locator("#openbao-access-resource option").evaluate_all(
                "options => options.map(option => option.value)"
            ))
            self.assertEqual(
                resources,
                {
                    "acl-policies",
                    "password-policies",
                    "entities",
                    "entity-aliases",
                    "groups",
                    "group-aliases",
                    "oidc-clients",
                    "oidc-keys",
                    "oidc-assignments",
                    "oidc-providers",
                    "oidc-scopes",
                    "namespaces",
                },
            )

            resource = page.locator("#openbao-access-resource")
            operation = page.locator("#openbao-access-operation")
            resource.select_option("acl-policies")
            operation.select_option("write")
            page.locator("#openbao-access-identifier").fill("team")
            policy = 'path "secret/data/team" { capabilities = ["read"] }'
            page.locator("#openbao-access-field-policy").fill(policy)
            page.locator("#openbao-access-reason").fill("Exercise inert policy submission.")
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-access-result").get_by_text('"accepted": true').wait_for()
            self.assertEqual(self.backend.calls[-1][2]["policy"], policy)

            resource.select_option("oidc-clients")
            operation.select_option("write")
            page.locator("#openbao-access-identifier").fill("app")
            page.locator("#openbao-access-reason").fill("Create one request-scoped OIDC client.")
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-access-result").get_by_text("client-secret-canary").wait_for()
            self.assertTrue(page.locator("#openbao-access-download").is_visible())
            operation.select_option("list")
            self.assertNotIn("client-secret-canary", page.locator("body").inner_text())
            self.assertFalse(page.locator("#openbao-access-download").is_visible())

            resource.select_option("acl-policies")
            operation.select_option("delete")
            page.locator("#openbao-access-identifier").fill("team")
            page.locator("#openbao-access-reason").fill("Remove the reviewed policy.")
            page.get_by_role("button", name="Preview impact").click()
            page.locator("#openbao-access-impact-output").get_by_text('"name": "team"').wait_for()
            expected = f"DELETE acl-policies team ON {self.cluster.slug}"
            page.locator("#openbao-access-confirmation-hint").get_by_text(expected).wait_for()
            page.locator("#openbao-access-confirmation").fill(expected)
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-access-result").get_by_text('"accepted": true').wait_for()

            resource.select_option("oidc-clients")
            operation.select_option("write")
            page.locator("#openbao-access-identifier").fill("app")
            page.locator("#openbao-access-reason").fill("Verify page lifecycle clearing.")
            page.get_by_role("button", name="Run reviewed operation").click()
            page.locator("#openbao-access-result").get_by_text("client-secret-canary").wait_for()
            page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
            self.assertNotIn("client-secret-canary", page.locator("body").inner_text())

            page.set_viewport_size({"width": 390, "height": 844})
            self.assertTrue(
                page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            )
            self.assertEqual(errors, [])
        finally:
            context.close()
            browser.close()
            browser_driver.stop()
