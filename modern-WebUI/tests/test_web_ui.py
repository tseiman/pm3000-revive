#!/usr/bin/env python3
"""Focused Stage 5 production-asset and fake-adapter gates."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
FAKE_PATH = ROOT / "tools" / "fake_ui_server.py"


class WebUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (WEB / "index.html").read_text()
        cls.css = (WEB / "styles.css").read_text()
        cls.javascript = (WEB / "app.js").read_text()
        spec = importlib.util.spec_from_file_location("fake_ui_server", FAKE_PATH)
        assert spec is not None and spec.loader is not None
        cls.fake = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fake)

    def test_production_web_assets_are_dependency_free_and_allowlisted(self) -> None:
        assets = [WEB / "index.html", WEB / "styles.css", WEB / "app.js"]
        manifest = {}
        for line in (WEB / "release-files.txt").read_text().splitlines():
            name, mime = line.split("\t", 1)
            manifest[name] = mime
        self.assertEqual(
            {"index.html": "text/html; charset=utf-8", "styles.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"},
            manifest,
        )
        self.assertEqual({path.name for path in assets}, set(manifest))
        self.assertIn('href="styles.css"', self.html)
        self.assertIn('type="module" src="app.js"', self.html)
        self.assertNotRegex(self.html, r"https?://")
        self.assertNotRegex(self.javascript, r"https?://")
        self.assertNotIn("import ", self.javascript)

    def test_api_values_use_safe_dom_sinks_and_browser_stores_no_credentials(self) -> None:
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function"):
            self.assertNotIn(unsafe, self.javascript)
        self.assertIn("textContent", self.javascript)
        self.assertNotIn("localStorage", self.javascript)
        self.assertNotIn("sessionStorage", self.javascript)
        self.assertNotRegex(self.javascript, r"state\.token\s*=")
        self.assertNotIn('headers.set("Authorization"', self.javascript)
        self.assertIn('autocomplete="current-password"', self.html)
        self.assertIn('state.csrf = ""', self.javascript)
        self.assertIn('credentials: "same-origin"', self.javascript)

    def test_session_transitions_are_serialized_and_fail_closed(self) -> None:
        self.assertIn("serializeTransition", self.javascript)
        self.assertIn("loginPending", self.javascript)
        self.assertIn("logoutPending", self.javascript)
        self.assertIn("bootstrapPending", self.javascript)
        self.assertIn("if (bootstrapPending || tokenIssuancePending || loginPending || logoutPending) return", self.javascript)
        self.assertRegex(
            self.javascript,
            r"setLoginDisabled\(true\);\s*serializeTransition\(bootstrapTransition\)\.finally",
        )
        self.assertRegex(
            self.javascript,
            r'const requestBody = JSON\.stringify\(\{ username, password \}\);\s*'
            r'password = "";\s*\$\("password-input"\)\.value = "";\s*'
            r'const session = await api',
        )
        logout = re.search(r"async function logoutTransition\(\) \{(.+?)\n\}", self.javascript, re.S)
        self.assertIsNotNone(logout)
        assert logout is not None
        self.assertLess(logout.group(1).index("disconnectLocal"), logout.group(1).index("await request"))
        self.assertIn("const generation = state.generation", self.javascript)
        self.assertIn("if (generation !== state.generation) return", self.javascript)

    def test_outlet_refresh_and_one_time_token_delivery_are_race_safe(self) -> None:
        self.assertIn("const request = ++state.outletRequest", self.javascript)
        self.assertIn("if (request === state.outletRequest) renderOutlets(payload)", self.javascript)
        self.assertIn("tokenIssuancePending = true", self.javascript)
        self.assertIn("if (tokenIssuancePending)", self.javascript)
        self.assertIn("enableLogin && !tokenIssuancePending", self.javascript)
        self.assertRegex(
            self.javascript,
            r"tokenIssuancePending = false;.+if \(!state\.session\) \{ setLoginDisabled\(false\)",
        )
        self.assertIn("deliverAfterSessionChange: true", self.javascript)
        self.assertIn("&& !options.deliverAfterSessionChange", self.javascript)

    def test_token_rows_offer_confirmed_delete_action(self) -> None:
        self.assertIn('button.textContent = action === "delete" ? "Delete"', self.javascript)
        self.assertIn('action === "delete" ? "DELETE" : "POST"', self.javascript)
        self.assertIn('window.confirm(`Delete token ${record.label}?`)', self.javascript)
        self.assertIn('toast(action === "delete" ? "Token deleted."', self.javascript)

    def test_ui_exposes_rights_gated_power_control_with_stale_revision_guard(self) -> None:
        self.assertIn("outlet.state", self.javascript)
        self.assertNotIn("outlet.status", self.javascript)
        self.assertIn('$("token-outlets").value.split', self.javascript)
        self.assertIn("outlets.sort()", self.javascript)
        self.assertIn("new Set(outlets).size", self.javascript)
        self.assertIn("/actions`,", self.javascript)
        self.assertIn("inventoryRevision: state.inventoryRevision", self.javascript)
        self.assertIn("const powerActionsEnabled = true", self.javascript)
        self.assertIn("powerActionsEnabled && state.session.navigation.canControlPower", self.javascript)
        self.assertIn('actionButton(outlet, "on")', self.javascript)
        self.assertIn('actionButton(outlet, "off")', self.javascript)
        self.assertIn('actionButton(outlet, "cycle")', self.javascript)
        self.assertIn('if (outlet.state === "off" && (action === "off" || action === "cycle")) return true', self.javascript)
        self.assertIn('if (outlet.state === "on" && action === "on") return true', self.javascript)
        self.assertIn('if (outlet.state !== "on" && outlet.state !== "off") return true', self.javascript)
        self.assertIn('article.className = `outlet-card state-${outlet.state}`', self.javascript)
        self.assertIn('status-chip${outlet.state === "off" ? " off"', self.javascript)
        self.assertRegex(self.css, r"\.outlet-card\.state-on\{[^}]*border-left-color:var\(--accent\)")
        self.assertRegex(self.css, r"\.outlet-card\.state-off\{[^}]*border-left-color:var\(--red\)")

    def test_ui_exposes_rights_gated_pdu_inventory_and_actions(self) -> None:
        self.assertIn('id="pdus-view"', self.html)
        self.assertIn('id="pdu-grid"', self.html)
        self.assertIn('path === "units.powermanagement.pdu_management" ? "pdus"', self.javascript)
        self.assertIn('api("/api/v1/pdus")', self.javascript)
        self.assertIn('`/api/v1/pdus/${encodeURIComponent(pdu.id)}/actions`', self.javascript)
        self.assertIn("inventoryRevision: state.pduInventoryRevision", self.javascript)
        self.assertIn("Array.isArray(pdu.availableActions)", self.javascript)
        self.assertIn("state.session.navigation.canControlPower", self.javascript)

    def test_ui_exposes_rights_gated_nis_complete_setting(self) -> None:
        self.assertIn('id="nis-view"', self.html)
        self.assertIn('id="nis-form"', self.html)
        self.assertIn('path === "units.authentication.authenticationservers.nis" ? "nis"', self.javascript)
        self.assertIn('api("/api/v1/settings/authentication/nis")', self.javascript)
        self.assertIn('domainName: $("nis-domain").value', self.javascript)
        self.assertIn('$("nis-domain").value = ""; $("nis-address").value = ""', self.javascript)
        self.assertIn('button.disabled = !loaded', self.javascript)
        self.assertIn('await loadNisSetting()', self.javascript)

    def test_ui_exposes_rights_gated_dsview_boolean_setting(self) -> None:
        self.assertIn('id="dsview-view"', self.html)
        self.assertIn('id="dsview-form"', self.html)
        self.assertIn('path === "units.applianceSettings.security.SecurityDSView" ? "dsview"', self.javascript)
        self.assertIn('api("/api/v1/settings/security/dsview")', self.javascript)
        self.assertIn('JSON.stringify({ allowDSView:', self.javascript)
        self.assertIn('$("allow-dsview").checked = false', self.javascript)
        self.assertIn('await loadDsviewSetting()', self.javascript)

    def test_revisioned_setting_forms_are_disabled_until_a_successful_get(self) -> None:
        for form, save, load, request_counter in (
            ("help-language-form", "save-help-language", "loadHelpLanguageSetting", "helpLanguageRequest"),
            ("data-buffering-form", "save-data-buffering", "loadDataBufferingSetting", "dataBufferingRequest"),
            ("appliance-logging-form", "save-appliance-logging", "loadApplianceLoggingSetting", "applianceLoggingRequest"),
            ("time-zone-form", "save-time-zone", "loadTimeZoneSetting", "timeZoneRequest"),
        ):
            with self.subTest(form=form):
                self.assertIn(f'id="{form}"', self.html)
                self.assertRegex(self.html, rf'id="{save}"[^>]*disabled')
                self.assertIn(f"async function {load}(writeReadback = false)", self.javascript)
                self.assertIn(f"++state.{request_counter}", self.javascript)
        self.assertIn('path === "units.applianceSettings.help" ? "help-language"', self.javascript)
        self.assertIn('path === "units.event_notification.global_settings_databuffering" ? "data-buffering"', self.javascript)
        self.assertIn('path === "units.event_notification.sessions" ? "appliance-logging"', self.javascript)
        self.assertIn('path === "units.applianceSettings.date_and_time.time_zone" ? "time-zone"', self.javascript)
        self.assertIn('setHelpLanguageLoaded(false)', self.javascript)
        self.assertIn('setDataBufferingLoaded(false)', self.javascript)
        self.assertIn('setApplianceLoggingLoaded(false)', self.javascript)
        self.assertIn('setTimeZoneLoaded(false)', self.javascript)

    def test_revisioned_settings_keep_revisions_in_memory_and_send_if_match(self) -> None:
        self.assertIn('helpLanguageRevision: ""', self.javascript)
        self.assertIn('dataBufferingRevision: ""', self.javascript)
        self.assertIn('applianceLoggingRevision: ""', self.javascript)
        self.assertIn('timeZoneRevision: ""', self.javascript)
        self.assertIn('state.helpLanguageRevision = payload.revision', self.javascript)
        self.assertIn('state.dataBufferingRevision = payload.revision', self.javascript)
        self.assertIn('state.applianceLoggingRevision = payload.revision', self.javascript)
        self.assertIn('state.timeZoneRevision = payload.revision', self.javascript)
        self.assertIn('headers: { "If-Match": state.helpLanguageRevision }', self.javascript)
        self.assertIn('headers: { "If-Match": state.dataBufferingRevision }', self.javascript)
        self.assertIn('headers: { "If-Match": state.applianceLoggingRevision }', self.javascript)
        self.assertIn('headers: { "If-Match": state.timeZoneRevision }', self.javascript)
        self.assertIn('if (method !== "GET" && options.csrf !== false && state.csrf)', self.javascript)
        self.assertNotRegex(self.javascript, r'(localStorage|sessionStorage)\s*\.')

    def test_revisioned_setting_saves_always_reload_without_automatic_retry(self) -> None:
        help_submit = re.search(r'\$\("help-language-form"\)\.addEventListener\("submit".+?\n\}\);', self.javascript, re.S)
        data_submit = re.search(r'\$\("data-buffering-form"\)\.addEventListener\("submit".+?\n\}\);', self.javascript, re.S)
        logging_submit = re.search(r'\$\("appliance-logging-form"\)\.addEventListener\("submit".+?\n\}\);', self.javascript, re.S)
        time_zone_submit = re.search(r'\$\("time-zone-form"\)\.addEventListener\("submit".+?\n\}\);', self.javascript, re.S)
        self.assertIsNotNone(help_submit)
        self.assertIsNotNone(data_submit)
        self.assertIsNotNone(logging_submit)
        self.assertIsNotNone(time_zone_submit)
        assert help_submit is not None and data_submit is not None and logging_submit is not None and time_zone_submit is not None
        for source, loader, route in (
            (help_submit.group(0), "loadHelpLanguageSetting", "/api/v1/settings/help-language"),
            (data_submit.group(0), "loadDataBufferingSetting", "/api/v1/settings/data-buffering"),
            (logging_submit.group(0), "loadApplianceLoggingSetting", "/api/v1/settings/appliance-logging"),
            (time_zone_submit.group(0), "loadTimeZoneSetting", "/api/v1/settings/time-zone"),
        ):
            with self.subTest(route=route):
                self.assertEqual(1, source.count(f'api("{route}"'))
                self.assertIn(f"await {loader}(true)", source)
                self.assertIn("const generation = state.generation;", source)
                self.assertIn("message && state.session && generation === state.generation", source)
                self.assertRegex(source, rf"(?s)finally\s*\{{.+?await {loader}\(true\);.+?state\.(?:helpLanguage|dataBuffering|applianceLogging|timeZone)WritePending = false;")

    def test_revisioned_setting_writes_block_reload_and_second_submit_until_readback(self) -> None:
        for prefix, loader, reload_id, save_id in (
            ("helpLanguage", "loadHelpLanguageSetting", "reload-help-language", "save-help-language"),
            ("dataBuffering", "loadDataBufferingSetting", "reload-data-buffering", "save-data-buffering"),
            ("applianceLogging", "loadApplianceLoggingSetting", "reload-appliance-logging", "save-appliance-logging"),
            ("timeZone", "loadTimeZoneSetting", "reload-time-zone", "save-time-zone"),
        ):
            with self.subTest(prefix=prefix):
                self.assertIn(f"{prefix}WritePending: false", self.javascript)
                self.assertIn(f"if (state.{prefix}WritePending && !writeReadback) return;", self.javascript)
                self.assertIn(f"state.{prefix}WritePending = true", self.javascript)
                self.assertIn(f"state.{prefix}WritePending = false", self.javascript)
                self.assertIn(f'$("{reload_id}").disabled = true', self.javascript)
                self.assertIn(f'$("{reload_id}").disabled = false', self.javascript)
                self.assertIn(f'$("{save_id}").disabled = true', self.javascript)
                self.assertRegex(self.javascript, rf"(?s)await {loader}\(true\);\s*state\.{prefix}WritePending = false")

    def test_revisioned_setting_runtime_blocks_reload_submit_race(self) -> None:
        for setting in ("help-language", "data-buffering", "appliance-logging", "time-zone"):
            with self.subTest(setting=setting):
                result = subprocess.run(
                    ["node", str(ROOT / "tests" / "ui_settings_write_lock.js"), str(WEB / "app.js"), setting],
                    check=True, capture_output=True, text=True,
                )
                payload = json.loads(result.stdout)
                self.assertEqual(setting, payload["setting"])
                self.assertEqual(1, payload["pendingPuts"])
                self.assertEqual(1, sum(call["method"] == "PUT" for call in payload["settingsCalls"]))
                if setting == "appliance-logging":
                    put = next(call for call in payload["settingsCalls"] if call["method"] == "PUT")
                    self.assertEqual(
                        {"sessionLoggingEnabled": True, "destination": "local", "timestampEnabled": True, "alertsEnabled": False},
                        json.loads(put["body"]),
                    )
                if setting == "time-zone":
                    put = next(call for call in payload["settingsCalls"] if call["method"] == "PUT")
                    self.assertEqual({"mode": "predefined", "predefinedZone": "UTC"}, json.loads(put["body"]))
                self.assertEqual([], payload["logoutCalls"])

    def test_appliance_logging_unknown_outcome_reloads_without_put_retry(self) -> None:
        result = subprocess.run(
            [
                "node", str(ROOT / "tests" / "ui_settings_write_lock.js"),
                str(WEB / "app.js"), "appliance-logging", "unknown",
            ],
            check=True, capture_output=True, text=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual("unknown", payload["outcome"])
        methods = [call["method"] for call in payload["settingsCalls"]]
        self.assertEqual(["GET", "PUT", "GET"], methods)
        self.assertEqual([], payload["logoutCalls"])

    def test_time_zone_unknown_outcome_reloads_without_put_retry(self) -> None:
        result = subprocess.run(
            ["node", str(ROOT / "tests" / "ui_settings_write_lock.js"), str(WEB / "app.js"), "time-zone", "unknown"],
            check=True, capture_output=True, text=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(["GET", "PUT", "GET"], [call["method"] for call in payload["settingsCalls"]])
        self.assertEqual([], payload["logoutCalls"])

    def test_revisioned_setting_dynamic_values_use_text_content_and_no_html_sink(self) -> None:
        self.assertIn('option.textContent = language', self.javascript)
        self.assertIn('option.textContent = facility', self.javascript)
        self.assertIn('option.textContent = destination', self.javascript)
        self.assertIn("document.createElement(\"option\")", self.javascript)
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML"):
            self.assertNotIn(unsafe, self.javascript)

    def test_acme_ui_is_capability_gated_localized_and_accessible(self) -> None:
        self.assertIn('id="acme-view"', self.html)
        self.assertIn('id="acme-form"', self.html)
        self.assertIn('id="acme-ca-form"', self.html)
        self.assertIn('id="acme-renew"', self.html)
        self.assertRegex(self.html, r'id="save-acme"[^>]*disabled')
        self.assertRegex(self.html, r'id="acme-ca-file"[^>]*disabled')
        self.assertRegex(self.html, r'id="acme-renew"[^>]*disabled')
        self.assertIn("canManageAcme", self.javascript)
        self.assertIn('button.dataset.view = "acme"', self.javascript)
        self.assertIn('state.session.navigation.canManageAcme', self.javascript)
        self.assertIn("navigator.languages", self.javascript)
        self.assertIn('document.documentElement.lang = locale', self.javascript)
        self.assertIn('de: {', self.javascript)
        self.assertIn('aria-live="polite"', self.html)

    def test_acme_contract_is_bounded_and_keeps_ca_path_read_only(self) -> None:
        self.assertIn('id="acme-ca-path"', self.html)
        self.assertNotRegex(self.html, r'<input[^>]+id="acme-ca-path"')
        self.assertRegex(self.html, r'id="acme-directory-url"[^>]+maxlength="1291"')
        self.assertRegex(self.html, r'id="acme-dns-names"[^>]+maxlength="4063"')
        self.assertIn("ACME_MAX_DNS_NAMES = 16", self.javascript)
        self.assertIn("ACME_MAX_DNS_NAME_BYTES = 253", self.javascript)
        self.assertIn("ACME_MAX_CA_BYTES = 65536", self.javascript)
        self.assertIn('"application/x-pem-file"', self.javascript)
        self.assertIn('{ "If-Match": state.acmeRevision }', self.javascript)
        self.assertIn('body: JSON.stringify({ enabled:', self.javascript)
        self.assertIn('directoryUrl:', self.javascript)
        self.assertIn('dnsNames', self.javascript)
        self.assertIn('{ "If-None-Match": "*"', self.javascript)
        self.assertIn("payload.configured === false", self.javascript)

    def test_acme_statuses_are_closed_and_unknown_values_fail_closed(self) -> None:
        for status in ("never_run", "starting", "running", "succeeded", "failed", "durability_uncertain", "unknown"):
            self.assertIn(f'"{status}"', self.javascript)
        self.assertIn("ACME_RENEWAL_STATES", self.javascript)
        self.assertIn('throw new Error(t("acme.invalidResponse"))', self.javascript)
        self.assertNotIn("acmeRevision: localStorage", self.javascript)

    def test_acme_runtime_state_machine_covers_write_upload_renewal_and_teardown(self) -> None:
        for scenario in ("bootstrap", "save", "stale", "ca", "renew", "teardown", "german"):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    ["node", str(ROOT / "tests" / "ui_acme_state.js"), str(WEB / "app.js"), scenario],
                    check=True, capture_output=True, text=True,
                )
                payload = json.loads(result.stdout)
                self.assertEqual(scenario, payload["scenario"])
                self.assertTrue(payload["passed"])

    def test_ui_exposes_rights_gated_password_change_without_browser_storage(self) -> None:
        self.assertIn('id="password-change-view"', self.html)
        self.assertIn('id="password-change-form"', self.html)
        self.assertIn('autocomplete="current-password"', self.html)
        self.assertIn('autocomplete="new-password"', self.html)
        self.assertIn('path === "units.change_password" ? "password"', self.javascript)
        self.assertIn('api("/api/v1/session/password"', self.javascript)
        self.assertIn('$("old-password").value = ""', self.javascript)
        self.assertIn('$("new-password").value = ""', self.javascript)
        self.assertIn('$("confirm-password").value = ""', self.javascript)

    def test_enabled_power_action_buttons_use_semantic_colors(self) -> None:
        self.assertIn('button.className = `small-button action-${action}${action === "off" ? " danger" : ""}`', self.javascript)
        self.assertIn('.small-button.action-on:not(:disabled){color:#21b43b}', self.css)
        self.assertIn('.small-button.action-cycle:not(:disabled){color:#ccab00}', self.css)

    def test_disabled_small_buttons_have_no_interactive_effects(self) -> None:
        self.assertIn('.small-button:not(:disabled):hover', self.css)
        self.assertIn('.small-button:not(:disabled):focus-visible', self.css)
        self.assertIn('.small-button:not(:disabled):active', self.css)
        self.assertIn('.small-button:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;transition:none;animation:none}', self.css)
        self.assertNotIn('.small-button:hover', self.css)

    def test_navigation_is_collapsible_and_preserves_the_active_path(self) -> None:
        self.assertIn('button.setAttribute("aria-expanded", "false")', self.javascript)
        self.assertIn("children.hidden = true", self.javascript)
        self.assertIn("toggleNavigationGroup(button, children)", self.javascript)
        self.assertIn("expandNavigationPath(path)", self.javascript)
        self.assertIn('className = "nav-children"', self.javascript)
        self.assertIn('.nav-item[aria-expanded]::after', self.css)
        self.assertIn('.nav-children[hidden]{display:none}', self.css)
        self.assertIn('@media(max-width:700px){.shell{display:block}', self.css)
        self.assertIn('.sidebar{position:static;height:auto;max-height:none', self.css)

    def test_navigation_and_dialog_controls_are_native_and_labelled(self) -> None:
        self.assertIn('aria-label="Primary navigation"', self.html)
        self.assertIn('<dialog id="create-token-dialog"', self.html)
        self.assertIn('<dialog id="token-secret-dialog"', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn(':focus-visible', self.css)
        self.assertIn('@media(max-width:700px)', self.css)
        self.assertIn('#disconnect{display:inline-flex', self.css)
        self.assertEqual(58, len(set(re.findall(r'\["(units\.[^"]+)",', self.javascript))))
        self.assertIn("Legacy feature", self.html)
        self.assertIn("canManageTokens", self.javascript)

    def test_token_create_cancel_payload_and_secret_cleanup_invariants(self) -> None:
        self.assertIn('id="close-create-title" class="icon-button" type="button"', self.html)
        self.assertIn('if (outlets !== null) payload.outlets = outlets', self.javascript)
        self.assertNotIn('scope: $("token-scope").value, outlets', self.javascript)
        self.assertIn('if ($("token-secret-dialog").open) $("token-secret-dialog").close()', self.javascript)
        self.assertIn("clearOneTimeSecret();", self.javascript)
        self.assertIn('if (!button || button.type !== "submit" || button.disabled) return', self.javascript)
        fake_source = FAKE_PATH.read_text()
        self.assertIn("object_pairs_hook=closed_object", fake_source)
        self.assertIn("not 1 <= len(label) <= 64", fake_source)
        self.assertIn('len(label.encode("utf-8")) > 128', fake_source)

    def test_fake_adapter_values_match_closed_identifier_shapes(self) -> None:
        opaque = re.compile(r"^[A-Za-z0-9_-]{22}$")
        token_id = re.compile(r"^tok_[A-Za-z0-9_-]{22}$")
        self.assertEqual(8, len(self.fake.OUTLETS))
        for outlet in self.fake.OUTLETS:
            self.assertEqual({"id", "pduId", "position", "name", "state", "availableActions"}, set(outlet))
            self.assertRegex(outlet["id"], opaque)
            self.assertRegex(outlet["pduId"], opaque)
            self.assertIn(outlet["state"], {"on", "off", "unknown"})
            self.assertEqual([], outlet["availableActions"])
        for token in self.fake.TOKENS:
            self.assertRegex(token["id"], token_id)
            self.assertRegex(token["createdAt"], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
            self.assertNotIn("digest", token)
            self.assertNotIn("token", token)


if __name__ == "__main__":
    unittest.main()
