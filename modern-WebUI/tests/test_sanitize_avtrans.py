#!/usr/bin/env python3
"""Tests for the local Avtrans capture sanitizer."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
OBSERVED_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "observed"
sys.path.insert(0, str(TOOLS))

import sanitize_avtrans  # noqa: E402


class SanitizeAvtransTests(unittest.TestCase):
    def test_redacts_session_and_login_values_while_preserving_schema(self) -> None:
        source = b"""<?xml version="1.0"?>
<avtrans>
  <sid>live-session-value</sid>
  <action>login</action>
  <payload>
    <section structure="login">
      <parameter id="username" structure="text"><value>operator</value></parameter>
      <parameter id="password" structure="password"><value>not-for-git</value></parameter>
    </section>
  </payload>
</avtrans>
"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        self.assertIn("<sid>[REDACTED-SID]</sid>", sanitized)
        self.assertIn('parameter id="username"', sanitized)
        self.assertIn('parameter id="password"', sanitized)
        self.assertIn("<value>[REDACTED-USERNAME]</value>", sanitized)
        self.assertIn("<value>[REDACTED]</value>", sanitized)
        self.assertNotIn("live-session-value", sanitized)
        self.assertNotIn("operator", sanitized)
        self.assertNotIn("not-for-git", sanitized)

    def test_redacts_entire_sid_subtree_attributes_and_tail(self) -> None:
        source = b"""<avtrans><sid value="sid-attribute">sid-text<child note="sid-child-attribute">sid-child-text</child>sid-child-tail</sid>sid-root-tail<action>get</action></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        for secret in (
            "sid-attribute",
            "sid-text",
            "sid-child-attribute",
            "sid-child-text",
            "sid-child-tail",
            "sid-root-tail",
        ):
            self.assertNotIn(secret, sanitized)

    def test_redacts_login_values_when_backend_field_ids_are_opaque(self) -> None:
        source = b"""<avtrans><payload><section structure="login">
          <parameter id="SYNTHETIC_FIELD_A" structure="RWtext"><value>operator-name</value></parameter>
          <parameter id="SYNTHETIC_FIELD_B" structure="password"><value>operator-password</value></parameter>
        </section></payload></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        self.assertNotIn("operator-name", sanitized)
        self.assertNotIn("operator-password", sanitized)
        self.assertIn('id="SYNTHETIC_FIELD_A"', sanitized)
        self.assertIn('id="SYNTHETIC_FIELD_B"', sanitized)

    def test_rejects_unknown_root_element(self) -> None:
        with self.assertRaisesRegex(ValueError, "root element"):
            sanitize_avtrans.sanitize_xml(b"<html><body>not avtrans</body></html>")

    def test_rejects_doctype_and_entities(self) -> None:
        source = b'<!DOCTYPE avtrans [<!ENTITY x "expanded">]><avtrans><action>&x;</action></avtrans>'
        with self.assertRaisesRegex(ValueError, "DTD"):
            sanitize_avtrans.sanitize_xml(source)

    def test_rejects_utf16_doctype_and_entities(self) -> None:
        source = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE avtrans [<!ENTITY x "expanded">]><avtrans><action>&x;</action></avtrans>'.encode(
            "utf-16"
        )
        with self.assertRaisesRegex(ValueError, "DTD"):
            sanitize_avtrans.sanitize_xml(source)

    def test_redacts_private_network_credentials_and_certificate_values(self) -> None:
        source = b"""<avtrans><sid>session</sid><payload><section structure="form">
          <parameter id="server" structure="text"><value>pdu.private.lan</value></parameter>
          <parameter id="ipaddress" structure="text"><value>192.168.2.55</value></parameter>
          <parameter id="api_token" structure="password"><value>opaque-token</value></parameter>
          <parameter id="certificate" structure="textarea"><value>-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----</value></parameter>
        </section></payload></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        for secret in ("pdu.private.lan", "192.168.2.55", "opaque-token", "BEGIN CERTIFICATE"):
            self.assertNotIn(secret, sanitized)
        self.assertIn('parameter id="server"', sanitized)
        self.assertGreaterEqual(sanitized.count("[REDACTED]"), 4)

    def test_redacts_sensitive_direct_elements_attributes_and_mixed_content(self) -> None:
        source = b"""<avtrans authorization="opaque-header">
          <token>opaque-token</token>root-tail-secret
          <certificate value="certificate-attribute">certificate-body<part>nested-secret</part>tail-secret</certificate>
          <metadata password="opaque-password" />
        </avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        for secret in (
            "opaque-header",
            "opaque-token",
            "root-tail-secret",
            "certificate-attribute",
            "certificate-body",
            "nested-secret",
            "tail-secret",
            "opaque-password",
        ):
            self.assertNotIn(secret, sanitized)

    def test_redacts_namespaced_value_subtree_for_sensitive_parameter(self) -> None:
        source = b"""<avtrans xmlns:ns="urn:synthetic"><payload>
          <ns:parameter ns:id="password" ns:structure="password" value="root-attribute-secret"><ns:value note="attribute-secret">text-secret<ns:part>nested-secret</ns:part>tail-secret</ns:value></ns:parameter>
        </payload></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        for secret in ("root-attribute-secret", "attribute-secret", "text-secret", "nested-secret", "tail-secret"):
            self.assertNotIn(secret, sanitized)
        self.assertIn('id="password"', sanitized)
        self.assertIn('structure="password"', sanitized)

    def test_redacts_private_literals_and_explicit_values_without_hiding_public_values(self) -> None:
        source = b"""<avtrans><action>get</action><payload>
          <parameter id="target" label="device-serial-123">
            <value>pdu.private.mdn 10.23.4.5 172.31.8.9 192.168.1.7 8.8.8.8</value>
          </parameter>
        </payload></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source, explicit_values=("device-serial-123",))

        for secret in ("pdu.private.mdn", "10.23.4.5", "172.31.8.9", "192.168.1.7", "device-serial-123"):
            self.assertNotIn(secret, sanitized)
        self.assertIn("8.8.8.8", sanitized)

    def test_redacts_operator_assigned_name_parameter_values(self) -> None:
        source = b"""<avtrans><payload><section structure="table"><array id="SYNTHETIC_OUTLET_1">
          <parameter id="name" icon="outlet" structure="ROtext" label="Name">
            <value label="private-rack-device">private-rack-device</value>
          </parameter>
          <parameter id="serialnumber" structure="ROtext" label="Serial Number">
            <value label="private-device-serial">private-device-serial</value>
          </parameter>
        </array></section></payload></avtrans>"""

        sanitized = sanitize_avtrans.sanitize_xml(source)

        self.assertNotIn("private-rack-device", sanitized)
        self.assertNotIn("private-device-serial", sanitized)
        self.assertIn('parameter id="name"', sanitized)
        self.assertIn('parameter id="serialnumber"', sanitized)
        self.assertIn('structure="ROtext"', sanitized)
        self.assertGreaterEqual(sanitized.count("[REDACTED-NAME]"), 2)

    def test_rejects_input_larger_than_one_mebibyte(self) -> None:
        source = b"<avtrans>" + (b" " * (1024 * 1024)) + b"</avtrans>"
        with self.assertRaisesRegex(ValueError, "size"):
            sanitize_avtrans.sanitize_xml(source)

    def test_rejects_xml_deeper_than_thirty_two_levels(self) -> None:
        source = ("<avtrans>" + ("<section>" * 32) + ("</section>" * 32) + "</avtrans>").encode()
        with self.assertRaisesRegex(ValueError, "depth"):
            sanitize_avtrans.sanitize_xml(source)

    def test_cli_writes_private_sanitized_output_and_honors_explicit_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.xml"
            output = Path(directory) / "sanitized.xml"
            source.write_text("<avtrans><sid>live</sid><payload>device-serial-123</payload></avtrans>")

            completed = subprocess.run(
                [sys.executable, str(TOOLS / "sanitize_avtrans.py"), str(source), str(output), "--redact", "device-serial-123"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertNotIn("device-serial-123", output.read_text())
            self.assertEqual(0o600, output.stat().st_mode & 0o777)

    def test_cli_rejects_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.xml"
            source = Path(directory) / "source-link.xml"
            output = Path(directory) / "sanitized.xml"
            raw.write_text("<avtrans><sid>live</sid></avtrans>")
            source.symlink_to(raw)

            completed = subprocess.run(
                [sys.executable, str(TOOLS / "sanitize_avtrans.py"), str(source), str(output)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertFalse(output.exists())

    def test_cli_rejects_fifo_without_waiting_for_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.fifo"
            output = Path(directory) / "sanitized.xml"
            os.mkfifo(source)

            completed = subprocess.run(
                [sys.executable, str(TOOLS / "sanitize_avtrans.py"), str(source), str(output)],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertFalse(output.exists())


class SyntheticFixtureTests(unittest.TestCase):
    def test_fixture_allowlist_is_parseable_and_contains_no_obvious_secrets(self) -> None:
        expected = {
            "authorization-denied-response.xml",
            "initial-login-request.xml",
            "login-failure-response.xml",
            "login-submit-request.xml",
            "navigation-request.xml",
            "navigation-response.xml",
            "outlet-inventory-response.xml",
            "outlet-status-response.xml",
        }
        actual = {path.name for path in FIXTURES.glob("*.xml")}
        self.assertEqual(expected, actual)

        forbidden = re.compile(
            r"(?:BEGIN [A-Z ]*PRIVATE KEY|(?:10|127)\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|Authorization:\s*Bearer)"
        )
        for path in sorted(FIXTURES.glob("*.xml")):
            with self.subTest(path=path.name):
                content = path.read_text()
                self.assertEqual("avtrans", ET.fromstring(content).tag)
                self.assertIsNone(forbidden.search(content))

    def test_manifest_marks_every_xml_fixture_as_synthetic(self) -> None:
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        declared = {entry["file"] for entry in manifest["fixtures"]}
        actual = {path.name for path in FIXTURES.glob("*.xml")}

        self.assertEqual(actual, declared)
        self.assertTrue(all(entry["evidence"] == "synthetic" for entry in manifest["fixtures"]))
        self.assertEqual("no-response", manifest["transport_timeout"]["representation"])


class ObservedFixtureTests(unittest.TestCase):
    def test_observed_fixture_allowlist_is_parseable_and_redacted(self) -> None:
        expected = {
            "initial-login-request.xml",
            "initial-login-response.xml",
            "login-submit-request.xml",
            "login-submit-response.xml",
            "navigation-request.xml",
            "navigation-response.xml",
            "topology-get-request.xml",
            "topology-get-response.xml",
            "pdu-management-get-request.xml",
            "pdu-management-get-response.xml",
            "logout-request.xml",
            "logout-response.xml",
        }
        actual = {path.name for path in OBSERVED_FIXTURES.glob("*.xml")}
        self.assertEqual(expected, actual)

        forbidden = re.compile(
            r"(?:BEGIN [A-Z ]*PRIVATE KEY|(?:10|127)\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|(?:[A-Za-z0-9_-]+\.)+(?:local|lan|internal|home|mdn)\b)",
            re.IGNORECASE,
        )
        for path in sorted(OBSERVED_FIXTURES.glob("*.xml")):
            with self.subTest(path=path.name):
                content = path.read_text()
                root = ET.fromstring(content)
                self.assertEqual("avtrans", root.tag)
                self.assertIsNone(forbidden.search(content))
                for element in root.iter():
                    tag = element.tag.rsplit("}", 1)[-1]
                    if tag == "sid" and "".join(element.itertext()).strip():
                        self.assertIn("[REDACTED-SID]", ET.tostring(element, encoding="unicode"))
                    normalized_id = "".join(character for character in element.get("id", "").lower() if character.isalnum())
                    if tag == "parameter" and normalized_id in {"name", "serialnumber"}:
                        self.assertIn("[REDACTED-NAME]", ET.tostring(element, encoding="unicode"))

    def test_observed_manifest_covers_every_fixture(self) -> None:
        manifest = json.loads((OBSERVED_FIXTURES / "manifest.json").read_text())
        declared = {entry["file"] for entry in manifest["fixtures"]}
        actual = {path.name for path in OBSERVED_FIXTURES.glob("*.xml")}

        self.assertEqual(actual, declared)
        self.assertEqual("2.0.1.23", manifest["source_firmware"])
        self.assertTrue(all(entry["evidence"] == "observed-sanitized" for entry in manifest["fixtures"]))


if __name__ == "__main__":
    unittest.main()
