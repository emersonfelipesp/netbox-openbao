"""Opt-in Playwright coverage for the authentication administration workspace."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from netbox_openbao.api import authentication_views
from netbox_openbao.models import OpenBaoAdministrationLog, OpenBaoCluster
from netbox_openbao.tests.test_authentication_administration import FakeAuthenticationBackend

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional local browser gate
    sync_playwright = None


@skipUnless(sync_playwright, "Install Playwright to run authentication browser tests")
class AuthenticationAdministrationBrowserTest(StaticLiveServerTestCase):
    """Exercise request-scoped auth, OIDC, metadata, and confirmation behavior."""

    def setUp(self):
        super().setUp()
        suffix = uuid4().hex[:10]
        self.user = get_user_model().objects.create_superuser(
            username=f"issue65-browser-{suffix}",
            email="browser@example.invalid",
            password="issue65-browser-password",
        )
        self.cluster = OpenBaoCluster.objects.create(
            name=f"Browser cluster {suffix}",
            slug=f"browser-{suffix}",
            api_url="https://bao.example.net:8200",
        )
        self.backend = FakeAuthenticationBackend(
            self.cluster,
            "auth-list-enabled-methods",
            "userpass-list-users",
            "userpass-login",
            "jwt-read-role",
            "jwt-oidc-request-authorization-url",
            "jwt-write-oidc-poll",
            "mfa-list-methods",
            "mfa-generate-totp-secret",
            "mfa-admin-destroy-totp-secret",
            "token-look-up-self-get",
        )

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
        page.locator('input[name="password"]').fill("issue65-browser-password")
        page.locator('button[type="submit"]').click()
        page.wait_for_load_state("networkidle")

    @patch.object(authentication_views, "get_administration_backend")
    def test_workspace_keeps_material_ephemeral_and_exposes_read_parity(self, get_backend):
        get_backend.return_value = self.backend
        browser_driver = sync_playwright().start()
        browser = browser_driver.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script("window.open = () => ({ opener: null });")
        try:
            self._login(page)
            url = reverse(
                "plugins:netbox_openbao:openbaocluster_authentication",
                kwargs={"pk": self.cluster.pk},
            )
            page.goto(f"{self.live_server_url}{url}", wait_until="networkidle")
            page.get_by_role("heading", name="Auth methods").wait_for()
            unlabeled = page.locator(
                '#openbao-authentication input:not([type="hidden"]), '
                "#openbao-authentication select, #openbao-authentication textarea"
            ).evaluate_all(
                "controls => controls.filter(control => control.name "
                '&& !document.querySelector(`label[for="${control.id}"]`))'
                ".map(control => ({id: control.id, name: control.name, type: control.type}))"
            )
            self.assertEqual(unlabeled, [])

            page.locator("#openbao-refresh-methods").click()
            page.get_by_role("cell", name="userpass", exact=True).first.wait_for()

            resource = page.locator('form[data-operation="auth-resource"]')
            resource.locator('select[name="resource_operation"]').select_option("list")
            resource.locator('input[name="mount_path"]').fill("userpass")
            resource.locator('select[name="resource_key"]').select_option("userpass-users")
            resource.get_by_role("button", name="Run resource operation").click()
            page.locator("#openbao-auth-result").get_by_text('"operation": "list"').wait_for()

            login = page.locator('form[data-operation="login"]')
            login.locator('input[name="mount_path"]').fill("userpass")
            login.locator('select[name="method_type"]').select_option("userpass")
            login.locator('input[name="username"]').fill("alice")
            login.locator('input[name="password"]').fill("password-canary")
            login.locator('input[name="reason"]').fill("Exercise the browser login flow.")
            login.get_by_role("button", name="Authenticate once").click()
            page.locator("#openbao-auth-result").get_by_text("issued-token-canary").wait_for()
            page.locator("#openbao-clear-result").click()
            self.assertNotIn("issued-token-canary", page.locator("body").inner_text())

            oidc = page.locator('form[data-operation="oidc-start"]')
            oidc.locator('input[name="mount_path"]').fill("oidc")
            oidc.locator('input[name="role"]').fill("people")
            oidc.locator('input[name="reason"]').fill("Exercise direct OIDC in the browser.")
            oidc.get_by_role("button", name="Open identity provider").click()
            page.get_by_text("The identity provider opened in a separate tab.").wait_for()
            self.assertNotIn("state-canary", page.locator("#openbao-auth-result").inner_text())
            page.evaluate(
                """
                Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
                document.dispatchEvent(new Event('visibilitychange'));
                Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
                document.dispatchEvent(new Event('visibilitychange'));
                """
            )
            page.locator("#openbao-oidc-poll").click()
            page.locator("#openbao-auth-result").get_by_text("oidc-token-canary").wait_for()
            page.locator("#openbao-clear-result").click()

            mfa = page.locator('form[data-operation="mfa-method"]')
            mfa.locator('select[name="mfa_operation"]').select_option("list")
            mfa.get_by_role("button", name="Save MFA method").click()
            page.locator("#openbao-auth-result").get_by_text("method-id").wait_for()

            totp = page.locator('form[data-operation="mfa-totp-self"]')
            totp.locator('input[name="method_id"]').fill("11111111-1111-4111-8111-111111111111")
            totp.locator('input[name="token"]').fill("submitted-token-canary")
            totp.locator('input[name="reason"]').fill("Enroll the current token entity.")
            totp.get_by_role("button", name="Generate my TOTP setup").click()
            page.locator("#openbao-auth-qr").wait_for(state="visible")
            qr_source = page.locator("#openbao-auth-qr").get_attribute("src")
            self.assertTrue(qr_source.startswith("data:image/png;base64,"))
            self.assertNotIn("barcode", page.locator("#openbao-auth-result").inner_text())
            page.evaluate(
                """
                Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
                document.dispatchEvent(new Event('visibilitychange'));
                Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
                document.dispatchEvent(new Event('visibilitychange'));
                """
            )
            self.assertEqual(page.locator("#openbao-auth-qr").get_attribute("src"), qr_source)

            reset = page.locator('form[data-operation="mfa-totp-self-reset"]')
            reset.locator('input[name="method_id"]').fill("11111111-1111-4111-8111-111111111111")
            reset.locator('input[name="token"]').fill("submitted-token-canary")
            reset.locator('input[name="reason"]').fill("Restart the current token entity enrollment.")
            reset.locator('input[name="confirmation"]').fill(f"RESET MY TOTP ON {self.cluster.slug}")
            reset.get_by_role("button", name="Reset my TOTP setup").click()
            page.locator("#openbao-auth-result").get_by_text('"reset": true').wait_for()
            self.assertFalse(page.locator("#openbao-auth-qr").is_visible())
            self.assertIsNone(page.locator("#openbao-auth-qr").get_attribute("src"))
            self.assertEqual(reset.locator('input[name="token"]').input_value(), "")

            resource.locator('select[name="resource_operation"]').select_option("delete")
            resource.locator('input[name="name"]').fill("alice")
            expected = f"Type exactly: DELETE AUTH RESOURCE userpass-users/alice ON {self.cluster.slug}"
            page.locator("#openbao-resource-confirmation").get_by_text(expected).wait_for()

            page.set_viewport_size({"width": 390, "height": 844})
            self.assertTrue(
                page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            )
            page.locator("#openbao-clear-result").click()
            screenshot_target = os.getenv("NETBOX_OPENBAO_BROWSER_SCREENSHOT")
            if screenshot_target:
                screenshot = Path(screenshot_target)
                page.screenshot(path=screenshot, full_page=True)
                self.assertTrue(screenshot.is_file())
            else:
                with TemporaryDirectory() as screenshot_directory:
                    screenshot = Path(screenshot_directory) / "authentication.png"
                    page.screenshot(path=screenshot, full_page=True)
                    self.assertTrue(screenshot.is_file())
            self.assertEqual(errors, [])
        finally:
            context.close()
            browser.close()
            browser_driver.stop()
