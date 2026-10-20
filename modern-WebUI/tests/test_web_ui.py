#!/usr/bin/env python3
"""Focused Stage 5 production-asset and fake-adapter gates."""

from __future__ import annotations

import importlib.util
import re
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

    def test_production_assets_are_dependency_free_and_within_budget(self) -> None:
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
        self.assertLess(sum(path.stat().st_size for path in assets), 400 * 1024)
        self.assertIn('href="styles.css"', self.html)
        self.assertIn('type="module" src="app.js"', self.html)
        self.assertNotRegex(self.html, r"https?://")
        self.assertNotRegex(self.javascript, r"https?://")
        self.assertNotIn("import ", self.javascript)

    def test_api_values_use_safe_dom_sinks_and_token_is_volatile(self) -> None:
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function"):
            self.assertNotIn(unsafe, self.javascript)
        self.assertIn("textContent", self.javascript)
        self.assertNotIn("localStorage", self.javascript)
        self.assertNotIn("sessionStorage", self.javascript)
        self.assertIn('state.token = ""', self.javascript)
        self.assertIn('autocomplete="off"', self.html)

    def test_ui_uses_the_openapi_outlet_field_and_exposes_no_power_control(self) -> None:
        self.assertIn("outlet.state", self.javascript)
        self.assertNotIn("outlet.status", self.javascript)
        self.assertIn('$("token-outlets").value.split', self.javascript)
        self.assertIn("outlets.sort()", self.javascript)
        self.assertIn("new Set(outlets).size", self.javascript)
        self.assertNotIn("/actions", self.javascript)
        self.assertIn("Outlet switching is disabled", self.html)
        self.assertNotIn("Switch on", self.html)
        self.assertNotIn("Switch off", self.html)
        self.assertNotIn("Cycle outlet", self.html)

    def test_navigation_and_dialog_controls_are_native_and_labelled(self) -> None:
        self.assertIn('aria-label="Primary navigation"', self.html)
        self.assertIn('<dialog id="create-token-dialog"', self.html)
        self.assertIn('<dialog id="token-secret-dialog"', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn(':focus-visible', self.css)
        self.assertIn('@media(max-width:700px)', self.css)
        self.assertIn('#disconnect{display:inline-flex', self.css)

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
