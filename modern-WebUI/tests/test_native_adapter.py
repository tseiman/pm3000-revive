#!/usr/bin/env python3
"""Host-side tests for the native PM3000 REST adapter."""

from __future__ import annotations

import json
import fcntl
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
BINARY = NATIVE / "build" / "pm3000-rest-host"
OBSERVED = ROOT / "fixtures" / "observed" / "topology-get-response.xml"
PDU_OBSERVED = ROOT / "fixtures" / "observed" / "pdu-management-get-response.xml"
LOGIN_RESPONSE = ROOT / "fixtures" / "observed" / "login-submit-response.xml"
NAVIGATION_RESPONSE = ROOT / "fixtures" / "observed" / "navigation-response.xml"
LOGOUT_RESPONSE = ROOT / "fixtures" / "observed" / "logout-response.xml"
SYSINFO_RESPONSE = ROOT / "fixtures" / "synthetic" / "system-information-response.xml"
MEMORY_RESPONSE = ROOT / "fixtures" / "synthetic" / "memory-usage-response.xml"
FLASH_RESPONSE = ROOT / "fixtures" / "synthetic" / "flash-usage-response.xml"
NETDEV_RESPONSE = ROOT / "fixtures" / "synthetic" / "netdev-monitoring-response.xml"
IPV4_ROUTES_RESPONSE = ROOT / "fixtures" / "synthetic" / "ipv4-routes-response.xml"
IPV6_ROUTES_RESPONSE = ROOT / "fixtures" / "synthetic" / "ipv6-routes-response.xml"
SERIAL_RESPONSE = ROOT / "fixtures" / "synthetic" / "serial-stats-response.xml"
TIME_ZONE_RESPONSE = ROOT / "fixtures" / "synthetic" / "time-zone-response.xml"
VENDOR_XML_PREAMBLE = (
    b'<?xml version="1.0"?>'
    b'<?xml-stylesheet type="text/xsl" href="transformation.xsl"?>'
)
sys.path.insert(0, str(ROOT / "tools"))
import token_store  # noqa: E402


class FakeAvtransController:
    def __init__(self, path: Path, responses: Sequence[bytes | None]) -> None:
        self.path = path
        self.responses = responses
        self.requests: list[tuple[bytes, bytes]] = []
        self.error: BaseException | None = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(self.path))
                listener.listen(1)
                self.ready.set()
                for response in self.responses:
                    connection, _ = listener.accept()
                    with connection:
                        header = bytearray()
                        while len(header) < 59:
                            chunk = connection.recv(59 - len(header))
                            if not chunk:
                                raise AssertionError("controller header ended early")
                            header.extend(chunk)
                        payload = bytearray()
                        while b"\0" not in payload:
                            chunk = connection.recv(65536)
                            if not chunk:
                                raise AssertionError("controller request ended without NUL")
                            payload.extend(chunk)
                        terminator = payload.index(0)
                        self.requests.append((bytes(header), bytes(payload[:terminator])))
                        if response is not None:
                            connection.sendall(response + b"\0")
        except BaseException as error:
            self.error = error
            self.ready.set()

    def __enter__(self) -> "FakeAvtransController":
        self.thread.start()
        if not self.ready.wait(5):
            raise AssertionError("fake controller did not start")
        if self.error is not None:
            raise self.error
        return self

    def __exit__(self, *_args: object) -> None:
        self.thread.join(5)
        if self.thread.is_alive():
            raise AssertionError("fake controller did not receive all requests")
        if self.error is not None:
            raise self.error


class NativeAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["make", "-C", str(NATIVE), "host"],
            check=True,
            text=True,
        )

    def run_adapter(self, *arguments: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(BINARY), *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_native_reader_rejects_noncanonical_record_anywhere(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            issued = store.create_token(
                administrator.plaintext,
                label="Reader",
                scope="read",
            )
            original = path.read_bytes()
            created = json.loads(original)["tokens"][0]["createdAt"]
            invalid_created = created[:5] + "13" + created[7:]
            for old, new in (
                (b'"label":"Administrator"', b'"label":" Administrator"'),
                (f'"createdAt":"{created}"'.encode(), f'"createdAt":"{invalid_created}"'.encode()),
            ):
                path.write_bytes(original.replace(old, new, 1))
                path.chmod(0o600)

                result = self.run_adapter("--authorize", str(path), issued.plaintext, "read")

                self.assertEqual(3, result.returncode)
                self.assertEqual(b"", result.stdout)

    def test_native_reader_rejects_malformed_utf8_and_python_trim_whitespace(self) -> None:
        whitespace = ("\u0085", "\u00a0", "\u1680", "\u2000", "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            original = path.read_bytes()
            for edge in whitespace:
                path.write_bytes(original.replace(b'"label":"Administrator"', ('"label":"' + edge + 'Administrator"').encode(), 1))
                path.chmod(0o600)
                result = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
                self.assertEqual(3, result.returncode, edge)
            for malformed in (b"\xc0\xaf", b"\xe0\x80\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\x80"):
                path.write_bytes(original.replace(b"Administrator", malformed, 1))
                path.chmod(0o600)
                result = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
                self.assertEqual(3, result.returncode, malformed)

    def test_native_reader_combines_only_valid_json_surrogate_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            original = path.read_bytes()
            escaped = original.replace(b"Administrator", b"Smile \\ud83d\\ude00", 1)
            path.write_bytes(escaped)
            path.chmod(0o600)
            accepted = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            for invalid in (b"\\ud83d", b"\\ude00", b"\\ude00\\ud83d", b"\\ud83dA"):
                path.write_bytes(original.replace(b"Administrator", invalid, 1))
                path.chmod(0o600)
                rejected = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
                self.assertEqual(3, rejected.returncode, invalid)

    def test_native_reader_enforces_scope_enabled_state_and_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            issued = store.create_token(
                administrator.plaintext,
                label="Read one outlet",
                scope="read",
                outlets=["XDmSGmQaZ6o7iRBWKUnpVg"],
            )

            allowed = self.run_adapter(
                "--authorize", str(path), issued.plaintext, "read", "XDmSGmQaZ6o7iRBWKUnpVg"
            )
            denied_outlet = self.run_adapter(
                "--authorize", str(path), issued.plaintext, "read", "niRcjzKfdPHmzgYMv2BzfB"
            )
            denied_scope = self.run_adapter(
                "--authorize", str(path), issued.plaintext, "control"
            )
            store.set_enabled(administrator.plaintext, issued.record.id, False)
            disabled = self.run_adapter("--authorize", str(path), issued.plaintext, "read")

            self.assertEqual(0, allowed.returncode, allowed.stderr)
            self.assertEqual({"authorized": True}, json.loads(allowed.stdout))
            for result in (denied_outlet, denied_scope, disabled):
                self.assertEqual(4, result.returncode)
                self.assertEqual(b"", result.stdout)

    def run_cgi(
        self,
        method: str,
        path: str,
        *,
        https: str = "on",
        authorization: str | None = None,
        cookie: str | None = None,
        csrf: str | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment.update({
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "HTTPS": https,
            "REMOTE_ADDR": "192.0.2.1",
        })
        if authorization is not None:
            environment["HTTP_AUTHORIZATION"] = authorization
        if cookie is not None:
            environment["HTTP_COOKIE"] = cookie
        if csrf is not None:
            environment["HTTP_X_CSRF_TOKEN"] = csrf
        if body is not None:
            environment["CONTENT_LENGTH"] = str(len(body))
        if content_type is not None:
            environment["CONTENT_TYPE"] = content_type
        if extra_environment is not None:
            environment.update(extra_environment)
        return subprocess.run(
            [str(BINARY)],
            input=body,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def cgi_json(self, result: subprocess.CompletedProcess[bytes]) -> tuple[bytes, dict[str, object]]:
        headers, body = result.stdout.split(b"\r\n\r\n", 1)
        parsed = json.loads(body)
        self.assertIsInstance(parsed, dict)
        return headers, parsed

    def token_environment(self, root: Path, store_path: Path) -> dict[str, str]:
        return {
            "PM3000_TOKEN_STORE": str(store_path),
            "PM3000_CREDENTIALS": str(root / "must-not-open.credentials"),
            "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
        }

    @staticmethod
    def session_cookie(headers: bytes) -> tuple[str, str]:
        line = next(item for item in headers.split(b"\r\n") if item.startswith(b"Set-Cookie: pm3000_session="))
        value = line.decode().split(";", 1)[0].split("=", 1)[1]
        return f"pm3000_session={value}", value

    def login_session(
        self,
        root: Path,
        navigation: bytes | None = None,
        topology: bytes | None = None,
        login_response: bytes | None = None,
    ) -> tuple[str, dict[str, object], FakeAvtransController, subprocess.CompletedProcess[bytes]]:
        socket_path = root / "avtrans.sock"
        session_dir = root / "sessions"
        body = b'{"username":"operator","password":"p&<secret"}'
        controller = FakeAvtransController(
            socket_path,
            [
                login_response or LOGIN_RESPONSE.read_bytes(),
                navigation or NAVIGATION_RESPONSE.read_bytes(),
                topology if topology is not None else OBSERVED.read_bytes(),
            ],
        )
        with controller:
            result = self.run_cgi(
                "POST", "/api/v1/session", body=body, content_type="application/json",
                extra_environment={
                    "PM3000_SESSION_DIR": str(session_dir),
                    "PM3000_AVTRANS_SOCKET": str(socket_path),
                },
            )
        headers, response = self.cgi_json(result)
        cookie, _value = self.session_cookie(headers)
        return cookie, response, controller, result

    def test_session_login_sets_hardened_cookie_and_persists_only_server_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, response, controller, result = self.login_session(root)
            headers = result.stdout.split(b"\r\n\r\n", 1)[0]
            self.assertIn(b"Status: 201", headers)
            self.assertIn(b"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900", headers)
            self.assertEqual({"identity", "csrfToken", "navigation"}, set(response))
            self.assertEqual({"username": "operator"}, response["identity"])
            self.assertEqual(
                {"paths", "canManageTokens", "canControlPower"},
                set(response["navigation"]),
            )
            self.assertTrue(response["navigation"]["canManageTokens"])
            self.assertTrue(response["navigation"]["canControlPower"])
            self.assertIn("units.topology", response["navigation"]["paths"])
            response_body = result.stdout.split(b"\r\n\r\n", 1)[1]
            self.assertNotIn(b"pm3000_session", response_body)
            self.assertNotIn(b"[REDACTED-SID]", response_body)
            self.assertEqual(3, len(controller.requests))
            self.assertIn(b"<action>login</action>", controller.requests[0][1])
            self.assertIn(b"<value>p&amp;&lt;secret</value>", controller.requests[0][1])
            self.assertIn(b"<action>navigation</action>", controller.requests[1][1])
            self.assertIn(b"<action>get</action>", controller.requests[2][1])
            self.assertIn(b"<path>units.topology</path>", controller.requests[2][1])
            session_dir = root / "sessions"
            self.assertEqual(0o700, session_dir.stat().st_mode & 0o777)
            files = list(session_dir.iterdir())
            self.assertEqual(1, len(files))
            self.assertEqual(0o600, files[0].stat().st_mode & 0o777)
            persisted = files[0].read_bytes()
            self.assertNotIn(b"p&<secret", persisted)
            self.assertNotIn(cookie.encode(), persisted)

    def test_session_login_accepts_exact_vendor_stylesheet_preamble(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preamble = VENDOR_XML_PREAMBLE

            _cookie, _response, controller, result = self.login_session(
                root,
                login_response=preamble + LOGIN_RESPONSE.read_bytes(),
                navigation=preamble + NAVIGATION_RESPONSE.read_bytes(),
                topology=preamble + OBSERVED.read_bytes(),
            )

            self.assertIn(b"Status: 201", result.stdout)
            self.assertEqual(3, len(controller.requests))

    def test_session_login_rejects_other_stylesheet_processing_instructions(self) -> None:
        declaration = b'<?xml version="1.0"?>'
        candidates = (
            declaration + b'<?xml-stylesheet type="text/xsl" href="https://example.test/x.xsl"?>',
            declaration + b'<?xml-stylesheet href="transformation.xsl" type="text/xsl"?>',
            declaration + b'<?xml-stylesheet type="text/xsl" href="transformation.xsl" media="all"?>',
            VENDOR_XML_PREAMBLE + b'<?xml-stylesheet type="text/xsl" href="transformation.xsl"?>',
        )
        for preamble in candidates:
            with self.subTest(preamble=preamble), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                socket_path = root / "avtrans.sock"
                with FakeAvtransController(
                    socket_path, [preamble + LOGIN_RESPONSE.read_bytes()]
                ):
                    result = self.run_cgi(
                        "POST", "/api/v1/session",
                        body=b'{"username":"operator","password":"secret"}',
                        content_type="application/json",
                        extra_environment={
                            "PM3000_SESSION_DIR": str(root / "sessions"),
                            "PM3000_AVTRANS_SOCKET": str(socket_path),
                        },
                    )
                self.assertIn(b"Status: 401", result.stdout)
                self.assertFalse((root / "sessions").exists())

    def test_session_login_ignores_inherited_basic_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "avtrans.sock"
            body = b'{"username":"operator","password":"p&<secret"}'
            with FakeAvtransController(socket_path, [
                LOGIN_RESPONSE.read_bytes(), NAVIGATION_RESPONSE.read_bytes(), OBSERVED.read_bytes(),
            ]) as controller:
                result = self.run_cgi(
                    "POST", "/api/v1/session", authorization="Basic Zm9vOmJhcg==",
                    body=body, content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            self.assertIn(b"Status: 201", result.stdout)
            self.assertEqual(3, len(controller.requests))

    def test_session_login_escapes_maximum_length_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "avtrans.sock"
            username = "'" * 128
            password = "'" * 256
            body = json.dumps({"username": username, "password": password}).encode()
            with FakeAvtransController(socket_path, [
                LOGIN_RESPONSE.read_bytes(), NAVIGATION_RESPONSE.read_bytes(), OBSERVED.read_bytes(),
            ]) as controller:
                result = self.run_cgi(
                    "POST", "/api/v1/session", body=body, content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            self.assertIn(b"Status: 201", result.stdout)
            self.assertEqual(3, len(controller.requests))
            self.assertIn(b"<value>" + b"&apos;" * 128 + b"</value>", controller.requests[0][1])
            self.assertIn(b"<value>" + b"&apos;" * 256 + b"</value>", controller.requests[0][1])

    def test_session_login_rejects_non_printable_ascii_credentials_before_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
            }
            cases = (
                b'{"username":"op\\nname","password":"secret"}',
                b'{"username":"operator","password":"sec\\u007fret"}',
                b'{"username":"operator","password":"sec\\u0001ret"}',
            )
            for body in cases:
                with self.subTest(body=body):
                    result = self.run_cgi(
                        "POST", "/api/v1/session", body=body,
                        content_type="application/json", extra_environment=environment,
                    )
                    headers, response = self.cgi_json(result)
                    self.assertIn(b"Status: 400", headers)
                    self.assertEqual("bad_request", response["code"])

    def test_session_login_escapes_maximum_expansion_controller_sids(self) -> None:
        entities = {b"&": b"&amp;", b"<": b"&lt;", b'"': b"&quot;", b"'": b"&apos;"}
        template = LOGIN_RESPONSE.read_bytes()
        for decoded, entity in entities.items():
            with self.subTest(decoded=decoded), tempfile.TemporaryDirectory() as temporary:
                encoded_sid = entity * 128
                login_response = template.replace(b"[REDACTED-SID]", encoded_sid)
                _cookie, _response, controller, result = self.login_session(
                    Path(temporary), login_response=login_response,
                )
                self.assertIn(b"Status: 201", result.stdout)
                self.assertEqual(3, len(controller.requests))
                expected = b"<sid>" + encoded_sid + b"</sid>"
                self.assertIn(expected, controller.requests[1][1])
                self.assertIn(expected, controller.requests[2][1])
                self.assertNotIn(b"<sid>" + decoded * 128 + b"</sid>", controller.requests[1][1])

    def test_session_get_restores_public_metadata_and_refreshes_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, created, _controller, _result = self.login_session(root)
            restored = self.run_cgi(
                "GET", "/api/v1/session", cookie=cookie,
                extra_environment={"PM3000_SESSION_DIR": str(root / "sessions")},
            )
            headers, response = self.cgi_json(restored)
            self.assertIn(b"Status: 200", headers)
            self.assertIn(b"Max-Age=900", headers)
            self.assertEqual(created, response)
            self.assertNotIn("[REDACTED-SID]", restored.stdout.decode())

    def test_session_route_rejects_bearer_and_malformed_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            environment = {"PM3000_SESSION_DIR": str(root / "sessions")}
            for method, authorization, csrf in (
                ("GET", "malformed", None),
                ("DELETE", "Bearer malformed", str(session["csrfToken"])),
            ):
                rejected = self.run_cgi(
                    method, "/api/v1/session", cookie=cookie,
                    authorization=authorization, csrf=csrf,
                    extra_environment=environment,
                )
                headers, response = self.cgi_json(rejected)
                self.assertIn(b"Status: 401", headers)
                self.assertEqual("unauthorized", response["code"])
            self.assertEqual(1, len(list((root / "sessions").iterdir())))

    def test_login_rejects_comments_denials_duplicates_and_trailing_xml(self) -> None:
        valid = LOGIN_RESPONSE.read_bytes()
        attacks = (
            b"<avtrans><action>login</action><paths><path>login</path></paths>"
            b"<error>denied</error><!-- <action>header</action><sid>forged</sid> --></avtrans>",
            b"<avtrans><action>header</action><paths><path>units</path></paths>"
            b"<error>denied with SID-like text &lt;sid&gt;forged&lt;/sid&gt;</error></avtrans>",
            valid.replace(b"</avtrans>", b"<sid>duplicate</sid></avtrans>", 1),
            valid + b"<avtrans />",
        )
        for response in attacks:
            with self.subTest(response=response[:80]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                socket_path = root / "avtrans.sock"
                with FakeAvtransController(socket_path, [response]):
                    result = self.run_cgi(
                        "POST", "/api/v1/session",
                        body=b'{"username":"operator","password":"secret"}',
                        content_type="application/json",
                        extra_environment={
                            "PM3000_SESSION_DIR": str(root / "sessions"),
                            "PM3000_AVTRANS_SOCKET": str(socket_path),
                        },
                    )
                self.assertIn(b"Status: 401", result.stdout)
                self.assertFalse((root / "sessions").exists())

    def test_navigation_and_control_capability_comments_are_rejected(self) -> None:
        navigation = NAVIGATION_RESPONSE.read_bytes().replace(
            b'path="units.users.local_accounts.user_names"',
            b'path="units.users.local_accounts.denied"',
        ).replace(b"</payload>", b'<!-- path="units.users.local_accounts.user_names" --></payload>')
        topology = OBSERVED.read_bytes()
        for control in (b"targPowerOn", b"targPowerOff", b"targCycle"):
            topology = topology.replace(control, b"deniedPower")
        topology = topology.replace(
            b"</payload>",
            b'<!-- id="targPowerOn" id="targPowerOff" id="targCycle" --></payload>',
        )
        for candidate_navigation, candidate_topology in (
            (navigation, OBSERVED.read_bytes()),
            (NAVIGATION_RESPONSE.read_bytes(), topology),
        ):
            with self.subTest(topology=candidate_topology is topology), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                socket_path = root / "avtrans.sock"
                with FakeAvtransController(
                    socket_path,
                    [LOGIN_RESPONSE.read_bytes(), candidate_navigation, candidate_topology,
                     LOGOUT_RESPONSE.read_bytes()],
                ):
                    result = self.run_cgi(
                        "POST", "/api/v1/session",
                        body=b'{"username":"operator","password":"secret"}',
                        content_type="application/json",
                        extra_environment={
                            "PM3000_SESSION_DIR": str(root / "sessions"),
                            "PM3000_AVTRANS_SOCKET": str(socket_path),
                        },
                    )
                self.assertIn(b"Status: 503", result.stdout)
                self.assertEqual([], list((root / "sessions").glob("*")))

    def test_session_logout_requires_csrf_and_tears_down_locally_on_backend_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(root / "missing.sock"),
            }
            denied = self.run_cgi("DELETE", "/api/v1/session", cookie=cookie, extra_environment=environment)
            self.assertIn(b"Status: 403", denied.stdout)
            self.assertEqual(1, len(list((root / "sessions").iterdir())))
            failed = self.run_cgi(
                "DELETE", "/api/v1/session", cookie=cookie,
                csrf=str(session["csrfToken"]), extra_environment=environment,
            )
            self.assertIn(b"Status: 503", failed.stdout)
            self.assertIn(b"Set-Cookie: pm3000_session=;", failed.stdout)
            self.assertIn(b"Max-Age=0", failed.stdout)
            self.assertEqual([], list((root / "sessions").iterdir()))

    def test_logout_does_not_claim_local_teardown_when_verified_delete_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            failed = self.run_cgi(
                "DELETE", "/api/v1/session", cookie=cookie,
                csrf=str(session["csrfToken"]),
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-contact.sock"),
                    "PM3000_SESSION_FAULT": "replace_before_delete",
                },
            )
            headers, response = self.cgi_json(failed)
            self.assertIn(b"Status: 503", headers)
            self.assertNotIn(b"Max-Age=0", headers)
            self.assertEqual("logout_incomplete", response["code"])
            self.assertNotIn("local session ended", response["message"].lower())
            self.assertEqual(1, len(list((root / "sessions").glob("[A-Za-z0-9_-]" * 43))))

    def test_refresh_rejects_a_path_replacement_without_overwriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _controller, _result = self.login_session(root)
            refreshed = self.run_cgi(
                "GET", "/api/v1/session", cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_SESSION_FAULT": "replace_before_refresh",
                },
            )
            self.assertIn(b"Status: 401", refreshed.stdout)
            records = list((root / "sessions").glob("[A-Za-z0-9_-]" * 43))
            self.assertEqual(1, len(records))
            self.assertEqual(b"replaced\n", records[0].read_bytes())

    def test_logout_confirmation_is_structural(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            socket_path = root / "logout.sock"
            forged = (
                b"<avtrans><!-- <action>login</action><path>login</path> -->"
                b"<action>logout</action><paths><path>login</path></paths></avtrans>"
            )
            with FakeAvtransController(socket_path, [forged]):
                result = self.run_cgi(
                    "DELETE", "/api/v1/session", cookie=cookie,
                    csrf=str(session["csrfToken"]),
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            headers, response = self.cgi_json(result)
            self.assertIn(b"Status: 503", headers)
            self.assertIn(b"Max-Age=0", headers)
            self.assertEqual("logout_incomplete", response["code"])
            self.assertEqual([], list((root / "sessions").glob("*")))

    def test_session_rights_gate_token_admin_and_power_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            restricted_navigation = NAVIGATION_RESPONSE.read_bytes().replace(
                b'path="units.users.local_accounts.user_names"',
                b'path="units.users.local_accounts.denied"',
            )
            restricted_topology = OBSERVED.read_bytes()
            for control in (b"targPowerOn", b"targPowerOff", b"targCycle"):
                restricted_topology = restricted_topology.replace(control, b"deniedPower")
            cookie, session, _controller, _result = self.login_session(
                root, restricted_navigation, restricted_topology
            )
            environment = self.token_environment(root, root / "missing-tokens.json")
            environment["PM3000_SESSION_DIR"] = str(root / "sessions")
            denied_tokens = self.run_cgi("GET", "/api/v1/tokens", cookie=cookie, extra_environment=environment)
            denied_power = self.run_cgi(
                "POST", "/api/v1/outlets/AAAAAAAAAAAAAAAAAAAAAA/actions",
                cookie=cookie, csrf=str(session["csrfToken"]),
                body=b'{"action":"on","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}',
                content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 403", denied_tokens.stdout)
            self.assertIn(b"Status: 403", denied_power.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())

    def test_session_can_administer_tokens_and_bearer_auth_remains_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            cookie, session, _controller, _result = self.login_session(root)
            environment = self.token_environment(root, store_path)
            environment["PM3000_SESSION_DIR"] = str(root / "sessions")
            listed = self.run_cgi("GET", "/api/v1/tokens", cookie=cookie, extra_environment=environment)
            self.assertIn(b"Status: 200", listed.stdout)
            created = self.run_cgi(
                "POST", "/api/v1/tokens", cookie=cookie, csrf=str(session["csrfToken"]),
                body=b'{"label":"Session reader","scope":"read"}',
                content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 201", created.stdout)
            bearer = self.run_cgi(
                "GET", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                extra_environment=environment,
            )
            self.assertIn(b"Status: 200", bearer.stdout)

    def test_token_administration_success_returns_plaintext_once_without_digest_or_avtrans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)
            request = json.dumps(
                {"label": "Restricted reader", "scope": "read", "outlets": []},
                separators=(",", ":"),
            ).encode()

            created = self.run_cgi(
                "POST", "/api/v1/tokens",
                authorization=f"Bearer {administrator.plaintext}", body=request,
                content_type="application/json", extra_environment=environment,
            )
            created_headers, created_body = self.cgi_json(created)
            self.assertIn(b"Status: 201", created_headers)
            self.assertEqual(
                {"id", "label", "createdAt", "enabled", "scope", "outlets", "token"},
                set(created_body),
            )
            self.assertRegex(created_body["token"], r"^pm3_[A-Za-z0-9_-]{43}$")
            self.assertNotIn("digest", created.stdout.decode())
            self.assertNotIn(created_body["token"], store_path.read_text())

            listed = self.run_cgi(
                "GET", "/api/v1/tokens",
                authorization=f"Bearer {administrator.plaintext}", extra_environment=environment,
            )
            listed_headers, listed_body = self.cgi_json(listed)
            self.assertIn(b"Status: 200", listed_headers)
            self.assertEqual(2, len(listed_body["tokens"]))
            self.assertNotIn("digest", listed.stdout.decode())
            self.assertNotIn(created_body["token"], listed.stdout.decode())

            token_id = created_body["id"]
            for suffix, expected in (("disable", False), ("enable", True)):
                changed = self.run_cgi(
                    "POST", f"/api/v1/tokens/{token_id}/{suffix}",
                    authorization=f"Bearer {administrator.plaintext}",
                    extra_environment=environment,
                )
                self.assertIn(b"Status: 204", changed.stdout)
                self.assertTrue(changed.stdout.endswith(b"\r\n\r\n"))
                records = store.list_tokens(administrator.plaintext)
                self.assertEqual(expected, next(item.enabled for item in records if item.id == token_id))

            revoked = self.run_cgi(
                "DELETE", f"/api/v1/tokens/{token_id}",
                authorization=f"Bearer {administrator.plaintext}", extra_environment=environment,
            )
            self.assertIn(b"Status: 204", revoked.stdout)
            self.assertNotIn(token_id, store_path.read_text())
            self.assertFalse((root / "must-not-open.sock").exists())
            self.assertFalse((root / "must-not-open.credentials").exists())

    def test_token_administration_denies_non_admin_scope_without_avtrans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            reader = store.create_token(administrator.plaintext, label="Reader", scope="read")
            environment = self.token_environment(root, store_path)

            for method, path, body in (
                ("GET", "/api/v1/tokens", None),
                ("POST", "/api/v1/tokens", b'{"label":"X","scope":"read"}'),
                ("POST", f"/api/v1/tokens/{reader.record.id}/disable", None),
                ("DELETE", f"/api/v1/tokens/{reader.record.id}", None),
            ):
                denied = self.run_cgi(
                    method, path, authorization=f"Bearer {reader.plaintext}", body=body,
                    content_type="application/json" if body is not None else None,
                    extra_environment=environment,
                )
                headers, response = self.cgi_json(denied)
                self.assertIn(b"Status: 403", headers)
                self.assertEqual("forbidden", response["code"])
            self.assertFalse((root / "must-not-open.sock").exists())

    def test_token_create_rejects_malformed_closed_bodies_media_type_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)
            original = store_path.read_bytes()
            bad_requests = (
                (b'{"label":"X","label":"Y","scope":"read"}', "application/json", b"Status: 400"),
                (b'{"label":"X","scope":"read","extra":true}', "application/json", b"Status: 400"),
                (b'{"label":" X","scope":"read"}', "application/json", b"Status: 400"),
                (b'{"label":"X","scope":"owner"}', "application/json", b"Status: 400"),
                (b'{"label":"X","scope":"read","outlets":["bad"]}', "application/json", b"Status: 400"),
                (b'{"label":"X","scope":"read"}', "text/plain", b"Status: 415"),
                (b" " * 2049, "application/json", b"Status: 413"),
            )
            for body, content_type, expected_status in bad_requests:
                result = self.run_cgi(
                    "POST", "/api/v1/tokens",
                    authorization=f"Bearer {administrator.plaintext}", body=body,
                    content_type=content_type, extra_environment=environment,
                )
                self.assertIn(expected_status, result.stdout)
                self.assertEqual(original, store_path.read_bytes())
                self.assertNotIn(b"pm3_", result.stdout)

            for edge in ("\u0085", "\u00a0", "\u1680", "\u2000", "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"):
                body = json.dumps({"label": edge + "Reader", "scope": "read"}, ensure_ascii=False).encode()
                result = self.run_cgi(
                    "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                    body=body, content_type="application/json", extra_environment=environment,
                )
                self.assertIn(b"Status: 400", result.stdout, edge)
                self.assertEqual(original, store_path.read_bytes())

    def test_token_json_surrogate_pairs_are_canonical_utf8_and_invalid_pairs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)

            valid = self.run_cgi(
                "POST", "/api/v1/tokens",
                authorization=f"Bearer {administrator.plaintext}",
                body=b'{"label":"Smile \\ud83d\\ude00","scope":"read"}',
                content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 201", valid.stdout)
            self.assertIn("Smile 😀", store_path.read_text())
            self.assertNotIn("\\ud83d", store_path.read_text())

            before_invalid = store_path.read_bytes()
            invalid_labels = (
                b"\\ud83d", b"\\ude00", b"\\ude00\\ud83d",
                b"\\ud83dA", b"\\ud83d\\ud83d", b"\\ud83d\\u0000",
            )
            for label in invalid_labels:
                body = b'{"label":"' + label + b'","scope":"read"}'
                result = self.run_cgi(
                    "POST", "/api/v1/tokens",
                    authorization=f"Bearer {administrator.plaintext}", body=body,
                    content_type="application/json", extra_environment=environment,
                )
                self.assertIn(b"Status: 400", result.stdout, label)
                self.assertEqual(before_invalid, store_path.read_bytes(), label)

            boundary = b'{"label":"' + (b"\\ud83d\\ude00" * 32) + b'","scope":"read"}'
            accepted = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=boundary, content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 201", accepted.stdout)
            too_many_bytes = b'{"label":"' + (b"\\ud83d\\ude00" * 33) + b'","scope":"read"}'
            rejected = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=too_many_bytes, content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 400", rejected.stdout)

    def test_token_mutations_protect_last_admin_and_enforce_record_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)
            for method, path in (
                ("POST", f"/api/v1/tokens/{administrator.record.id}/disable"),
                ("DELETE", f"/api/v1/tokens/{administrator.record.id}"),
            ):
                result = self.run_cgi(
                    method, path, authorization=f"Bearer {administrator.plaintext}",
                    extra_environment=environment,
                )
                headers, response = self.cgi_json(result)
                self.assertIn(b"Status: 409", headers)
                self.assertEqual("last_administrator", response["code"])

            document = json.loads(store_path.read_text())
            base = document["tokens"][0].copy()
            for index in range(1, 128):
                record = base.copy()
                record.update({
                    "id": "tok_" + f"{index:022d}",
                    "digest": f"{index:064x}",
                    "label": f"Reader {index}",
                    "scope": "read",
                })
                document["tokens"].append(record)
            store_path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
            store_path.chmod(0o600)
            result = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=b'{"label":"Too many","scope":"read"}', content_type="application/json",
                extra_environment=environment,
            )
            headers, response = self.cgi_json(result)
            self.assertIn(b"Status: 409", headers)
            self.assertEqual("token_limit_reached", response["code"])
            self.assertNotIn(b"pm3_", result.stdout)

            document["generation"] = (1 << 63) - 1
            document["tokens"] = [document["tokens"][0]]
            store_path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
            store_path.chmod(0o600)
            at_generation_limit = store_path.read_bytes()
            overflow = self.run_cgi(
                "POST", f"/api/v1/tokens/{administrator.record.id}/enable",
                authorization=f"Bearer {administrator.plaintext}", extra_environment=environment,
            )
            overflow_headers, overflow_body = self.cgi_json(overflow)
            self.assertIn(b"Status: 503", overflow_headers)
            self.assertEqual("token_store_unavailable", overflow_body["code"])
            self.assertEqual(at_generation_limit, store_path.read_bytes())

    def test_token_create_is_atomic_and_never_returns_uncommitted_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)
            original = store_path.read_bytes()

            before_rename = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=b'{"label":"Atomic reader","scope":"read"}', content_type="application/json",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "before_rename"},
            )
            self.assertIn(b"Status: 503", before_rename.stdout)
            self.assertNotIn(b"pm3_", before_rename.stdout)
            self.assertEqual(original, store_path.read_bytes())
            self.assertEqual([], list(store_path.parent.glob(".tokens.*")))

            post_commit = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=b'{"label":"Committed reader","scope":"read"}', content_type="application/json",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "after_rename"},
            )
            self.assertNotEqual(0, post_commit.returncode)
            self.assertEqual(1, post_commit.stdout.count(b"Status:"))
            self.assertIn(b"Status: 201", post_commit.stdout)
            _headers, committed_body = self.cgi_json(post_commit)
            self.assertNotEqual(original, store_path.read_bytes())
            self.assertIsNotNone(store.authenticate(committed_body["token"]))
            self.assertEqual([], list(store_path.parent.glob(".tokens.*")))

            original = store_path.read_bytes()
            output_failure_environment = os.environ.copy()
            body = b'{"label":"Undeliverable reader","scope":"read"}'
            output_failure_environment.update({
                "REQUEST_METHOD": "POST", "PATH_INFO": "/api/v1/tokens", "HTTPS": "on",
                "HTTP_AUTHORIZATION": f"Bearer {administrator.plaintext}", "CONTENT_TYPE": "application/json",
                "CONTENT_LENGTH": str(len(body)), **environment,
            })
            with open("/dev/full", "wb") as full:
                undeliverable = subprocess.run([str(BINARY)], input=body, env=output_failure_environment,
                                               stdout=full, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, undeliverable.returncode)
            self.assertEqual(original, store_path.read_bytes())
            self.assertEqual([], list(store_path.parent.glob(".tokens.*")))

            reader = store.create_token(administrator.plaintext, label="Mutable reader", scope="read")
            before_disable = store_path.read_bytes()
            failed_disable = self.run_cgi(
                "POST", f"/api/v1/tokens/{reader.record.id}/disable",
                authorization=f"Bearer {administrator.plaintext}",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "before_rename"},
            )
            self.assertIn(b"Status: 503", failed_disable.stdout)
            self.assertEqual(before_disable, store_path.read_bytes())
            self.assertTrue(store.authenticate(reader.plaintext).enabled)

            uncertain_disable = self.run_cgi(
                "POST", f"/api/v1/tokens/{reader.record.id}/disable",
                authorization=f"Bearer {administrator.plaintext}",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "after_rename"},
            )
            self.assertIn(b"Status: 503", uncertain_disable.stdout)
            self.assertNotEqual(before_disable, store_path.read_bytes())
            self.assertFalse(store.authenticate(reader.plaintext).enabled)
            self.assertEqual([], list(store_path.parent.glob(".tokens.*")))

    def test_parent_fsync_barrier_and_real_post_delivery_rename_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            environment = self.token_environment(root, store_path)
            original = store_path.read_bytes()
            body = b'{"label":"Barrier reader","scope":"read"}'

            parent_failure = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=body, content_type="application/json",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "parent_fsync"},
            )
            self.assertIn(b"Status: 503", parent_failure.stdout)
            self.assertNotIn(b"pm3_", parent_failure.stdout)
            self.assertEqual(original, store_path.read_bytes())

            rename_failure = self.run_cgi(
                "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                body=body, content_type="application/json",
                extra_environment={**environment, "PM3000_TOKEN_FAULT": "rename_failure"},
            )
            self.assertNotEqual(0, rename_failure.returncode)
            self.assertEqual(1, rename_failure.stdout.count(b"Status:"))
            self.assertIn(b"Status: 201", rename_failure.stdout)
            _headers, delivered = self.cgi_json(rename_failure)
            self.assertEqual(original, store_path.read_bytes())
            self.assertIsNone(store.authenticate(delivered["token"]))
            self.assertEqual([], list(store_path.parent.glob(".tokens.*")))

    def test_pdu_inventory_and_session_action_use_observed_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            socket_path = root / "pdu-read.sock"
            with FakeAvtransController(socket_path, [PDU_OBSERVED.read_bytes()]):
                result = self.run_cgi(
                    "GET", "/api/v1/pdus", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            _headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 200", result.stdout)
            self.assertEqual("v1", payload["apiVersion"])
            self.assertEqual(1, len(payload["pdus"]))
            pdu = payload["pdus"][0]
            self.assertEqual("Avocent", pdu["vendor"])
            self.assertEqual("PM3000/10/16A", pdu["model"])
            self.assertEqual(1, pdu["outletsOn"])
            self.assertEqual(10, pdu["outletCount"])
            self.assertEqual(["on", "off", "cycle"], pdu["availableActions"])
            self.assertNotIn("thresholds", pdu)

            socket_path = root / "pdu-action.sock"
            body = json.dumps({
                "action": "cycle",
                "inventoryRevision": payload["inventoryRevision"],
            }).encode()
            with FakeAvtransController(socket_path, [PDU_OBSERVED.read_bytes(), PDU_OBSERVED.read_bytes()]) as controller:
                action_result = self.run_cgi(
                    "POST", f"/api/v1/pdus/{pdu['id']}/actions", cookie=cookie,
                    body=body, content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                        "HTTP_X_CSRF_TOKEN": session["csrfToken"],
                    },
                )
            _headers, outcome = self.cgi_json(action_result)
            self.assertIn(b"Status: 503", action_result.stdout)
            self.assertEqual("action_outcome_unknown", outcome["code"])
            self.assertEqual(2, len(controller.requests))
            request = controller.requests[1][1].decode("utf-8")
            self.assertIn("<action>cycle</action>", request)
            self.assertIn("<path>units.powermanagement.pdu_management</path>", request)
            self.assertIn('<section structure="table" id="pdu_devices_table">', request)
            self.assertIn('<array id="[REDACTED]"></array>', request)

    def test_pdu_bearer_action_requires_unrestricted_control_and_logs_out(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            credentials_path = root / "service.credentials"
            socket_path = root / "pdu-service.sock"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            restricted = store.create_token(administrator.plaintext, label="Restricted", scope="control", outlets=[])
            unrestricted = store.create_token(administrator.plaintext, label="PDU Controller", scope="control")
            credentials_path.write_text("service-user\nservice-password\n")
            credentials_path.chmod(0o600)

            denied = self.run_cgi(
                "POST", "/api/v1/pdus/AAAAAAAAAAAAAAAAAAAAAA/actions",
                authorization=f"Bearer {restricted.plaintext}",
                body=json.dumps({"action": "off", "inventoryRevision": "A" * 22}).encode(),
                content_type="application/json",
                extra_environment={
                    "PM3000_TOKEN_STORE": str(store_path),
                    "PM3000_CREDENTIALS": str(credentials_path),
                    "PM3000_AVTRANS_SOCKET": str(socket_path),
                },
            )
            self.assertIn(b"Status: 403", denied.stdout)

            pdu_id = self.run_adapter("--derive", "pdu", "[REDACTED]").stdout.decode().strip()
            revision = self.run_adapter("--revision", "[REDACTED]").stdout.decode().strip()
            confirmed_off = PDU_OBSERVED.read_bytes().replace(b'label="1/10">1/10</value>', b'label="0/10">0/10</value>', 1)
            responses = [
                LOGIN_RESPONSE.read_bytes(), NAVIGATION_RESPONSE.read_bytes(),
                PDU_OBSERVED.read_bytes(), confirmed_off, LOGOUT_RESPONSE.read_bytes(),
            ]
            with FakeAvtransController(socket_path, responses) as controller:
                result = self.run_cgi(
                    "POST", f"/api/v1/pdus/{pdu_id}/actions",
                    authorization=f"Bearer {unrestricted.plaintext}",
                    body=json.dumps({"action": "off", "inventoryRevision": revision}).encode(),
                    content_type="application/json",
                    extra_environment={
                        "PM3000_TOKEN_STORE": str(store_path),
                        "PM3000_CREDENTIALS": str(credentials_path),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            self.assertIn(b"Status: 204", result.stdout)
            self.assertEqual(5, len(controller.requests))
            requests = [request for _, request in controller.requests]
            self.assertIn(b"<action>off</action>", requests[3])
            self.assertIn(b"<action>logout</action>", requests[4])
            self.assertNotIn(unrestricted.plaintext.encode(), b"".join(requests))

    def test_outlet_action_uses_firmware_derived_topology_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            credentials_path = root / "service.credentials"
            socket_path = root / "avtrans.sock"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            inventory = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)
            outlet_id = inventory["outlets"][0]["id"]
            revision = inventory["inventoryRevision"]
            controller_token = store.create_token(
                administrator.plaintext, label="Controller", scope="control", outlets=[outlet_id]
            )
            service_username = "'" * 128
            service_password = "'" * 256
            credentials_path.write_text(f"{service_username}\n{service_password}\n")
            credentials_path.chmod(0o600)
            responses = [
                LOGIN_RESPONSE.read_bytes(),
                OBSERVED.read_bytes(),
                OBSERVED.read_bytes(),
                LOGOUT_RESPONSE.read_bytes(),
            ]
            with FakeAvtransController(socket_path, responses) as controller:
                result = self.run_cgi(
                    "POST", f"/api/v1/outlets/{outlet_id}/actions",
                    authorization=f"Bearer {controller_token.plaintext}",
                    body=json.dumps({"action": "on", "inventoryRevision": revision}).encode(),
                    content_type="application/json",
                    extra_environment={
                        "PM3000_TOKEN_STORE": str(store_path),
                        "PM3000_CREDENTIALS": str(credentials_path),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            self.assertIn(b"Status: 204", result.stdout)
            self.assertEqual(4, len(controller.requests))
            requests = [request.decode("utf-8") for _, request in controller.requests]
            self.assertIn("<action>login</action>", requests[0])
            self.assertIn("<value>" + "&apos;" * 128 + "</value>", requests[0])
            self.assertIn("<value>" + "&apos;" * 256 + "</value>", requests[0])
            self.assertIn("<action>get</action>", requests[1])
            self.assertIn("<path>units.topology</path>", requests[1])
            self.assertIn("<action>targPowerOn</action>", requests[2])
            self.assertIn('<section structure="table" id="topologyTable">', requests[2])
            self.assertIn("<array id=", requests[2])
            self.assertNotIn("<action>on</action>", requests[2])
            self.assertIn("<action>logout</action>", requests[3])
            self.assertNotIn(controller_token.plaintext, "".join(requests))

    def test_service_credential_flow_escapes_maximum_expansion_controller_sids(self) -> None:
        entities = {b"&": b"&amp;", b"<": b"&lt;", b'"': b"&quot;", b"'": b"&apos;"}
        login_template = LOGIN_RESPONSE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            credentials_path = root / "service.credentials"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            inventory = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)
            outlet_id = inventory["outlets"][0]["id"]
            controller_token = store.create_token(
                administrator.plaintext, label="Controller", scope="control", outlets=[outlet_id]
            )
            credentials_path.write_text("service-user\nservice-password\n")
            credentials_path.chmod(0o600)
            for index, (decoded, entity) in enumerate(entities.items()):
                with self.subTest(decoded=decoded):
                    socket_path = root / f"service-sid-{index}.sock"
                    encoded_sid = entity * 128
                    login_response = login_template.replace(b"[REDACTED-SID]", encoded_sid)
                    with FakeAvtransController(socket_path, [
                        login_response, OBSERVED.read_bytes(), OBSERVED.read_bytes(),
                        LOGOUT_RESPONSE.read_bytes(),
                    ]) as controller:
                        result = self.run_cgi(
                            "POST", f"/api/v1/outlets/{outlet_id}/actions",
                            authorization=f"Bearer {controller_token.plaintext}",
                            body=json.dumps({
                                "action": "on",
                                "inventoryRevision": inventory["inventoryRevision"],
                            }).encode(),
                            content_type="application/json",
                            extra_environment={
                                "PM3000_TOKEN_STORE": str(store_path),
                                "PM3000_CREDENTIALS": str(credentials_path),
                                "PM3000_AVTRANS_SOCKET": str(socket_path),
                            },
                        )
                    self.assertIn(b"Status: 204", result.stdout)
                    expected = b"<sid>" + encoded_sid + b"</sid>"
                    self.assertEqual(4, len(controller.requests))
                    for _header, request in controller.requests[1:]:
                        self.assertIn(expected, request)
                        self.assertNotIn(b"<sid>" + decoded * 128 + b"</sid>", request)

    def test_outlet_action_rejects_controller_error_wrong_action_path_and_missing_payload(self) -> None:
        observed = OBSERVED.read_bytes()
        rejected_responses = (
            observed.replace(b"<payload", b'<error severity="error" label="Denied"/><payload', 1),
            observed.replace(b"<action>content</action>", b"<action>navigation</action>", 1),
            observed.replace(b"<path>units.topology</path>", b"<path>units.overview</path>", 1),
            b"<avtrans><action>content</action><paths><path>units.topology</path></paths></avtrans>",
        )
        for action_response in rejected_responses:
            with self.subTest(response=action_response[:80]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                store_path = root / "rest" / "tokens.json"
                credentials_path = root / "service.credentials"
                socket_path = root / "avtrans.sock"
                store = token_store.TokenStore(store_path)
                administrator = store.bootstrap("Administrator")
                inventory = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)
                outlet_id = inventory["outlets"][0]["id"]
                controller_token = store.create_token(
                    administrator.plaintext, label="Controller", scope="control", outlets=[outlet_id]
                )
                credentials_path.write_text("service-user\nservice-password\n")
                credentials_path.chmod(0o600)
                with FakeAvtransController(socket_path, [
                    LOGIN_RESPONSE.read_bytes(), OBSERVED.read_bytes(),
                    action_response, LOGOUT_RESPONSE.read_bytes(),
                ]) as controller:
                    result = self.run_cgi(
                        "POST", f"/api/v1/outlets/{outlet_id}/actions",
                        authorization=f"Bearer {controller_token.plaintext}",
                        body=json.dumps({
                            "action": "off",
                            "inventoryRevision": inventory["inventoryRevision"],
                        }).encode(),
                        content_type="application/json",
                        extra_environment={
                            "PM3000_TOKEN_STORE": str(store_path),
                            "PM3000_CREDENTIALS": str(credentials_path),
                            "PM3000_AVTRANS_SOCKET": str(socket_path),
                        },
                    )
                _headers, response = self.cgi_json(result)
                self.assertIn(b"Status: 503", result.stdout)
                self.assertEqual("action_outcome_unknown", response["code"])
                self.assertEqual(4, len(controller.requests))
                self.assertIn(b"<action>targPowerOff</action>", controller.requests[2][1])

    def test_session_password_change_uses_closed_firmware_form_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            socket_path = root / "password.sock"
            response = (
                b'<avtrans><action>content</action><paths><path>units.change_password.changedPassword</path></paths>'
                b'<payload><section id="changedPassword" structure="standard">'
                b'<section id="infoForm" structure="form"><parameter id="title" structure="title">'
                b'<parameter id="message" structure="notice"></parameter>'
                b'</parameter></section></section></payload></avtrans>'
            )
            body = json.dumps({
                "oldPassword": "old&<password",
                "newPassword": "new>password",
                "confirmation": "new>password",
            }).encode()
            with FakeAvtransController(socket_path, [response]) as controller:
                result = self.run_cgi(
                    "POST", "/api/v1/session/password", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body,
                    content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                    },
                )
            self.assertIn(b"Status: 204", result.stdout)
            self.assertEqual(1, len(controller.requests))
            request = controller.requests[0][1]
            self.assertIn(b"<action>save</action>", request)
            self.assertIn(b"<path>units.change_password</path>", request)
            self.assertIn(b'<section structure="form">', request)
            self.assertIn(b'<parameter id="oldpassword" structure="password"><value>old&amp;&lt;password</value></parameter>', request)
            self.assertIn(b'<parameter id="newpassword" structure="password"><value>new&gt;password</value></parameter>', request)
            self.assertIn(b'<parameter id="confirmpassword" structure="password"><value>new&gt;password</value></parameter>', request)
            self.assertNotIn(b"old&<password", result.stdout)
            self.assertNotIn(b"new>password", result.stdout)

            maximum_socket = root / "password-maximum-expansion.sock"
            printable_ascii = "".join(chr(value) for value in range(0x20, 0x7f))
            xml_entities = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;"}
            with FakeAvtransController(maximum_socket, [response] * len(printable_ascii)) as maximum_controller:
                for character in printable_ascii:
                    maximum_password = character * 256
                    maximum_body = json.dumps({
                        "oldPassword": maximum_password,
                        "newPassword": maximum_password,
                        "confirmation": maximum_password,
                    }, separators=(",", ":")).encode()
                    maximum_result = self.run_cgi(
                        "POST", "/api/v1/session/password", cookie=cookie,
                        csrf=str(session["csrfToken"]), body=maximum_body,
                        content_type="application/json",
                        extra_environment={
                            "PM3000_SESSION_DIR": str(root / "sessions"),
                            "PM3000_AVTRANS_SOCKET": str(maximum_socket),
                        },
                    )
                    self.assertIn(b"Status: 204", maximum_result.stdout, character)
            self.assertEqual(len(printable_ascii), len(maximum_controller.requests))
            for character, request in zip(printable_ascii, maximum_controller.requests):
                escaped = xml_entities.get(character, character).encode() * 256
                self.assertEqual(3, request[1].count(b"<value>" + escaped + b"</value>"), character)

            invalid_socket = root / "password-invalid-response.sock"
            invalid_environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(invalid_socket),
            }
            invalid_response = b'<avtrans><action>content</action><paths><path>units.change_password.changedPassword</path></paths><payload/></avtrans>'
            with FakeAvtransController(invalid_socket, [invalid_response]):
                invalid = self.run_cgi(
                    "POST", "/api/v1/session/password", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body,
                    content_type="application/json", extra_environment=invalid_environment,
                )
            _headers, error = self.cgi_json(invalid)
            self.assertIn(b"Status: 503", invalid.stdout)
            self.assertEqual("action_outcome_unknown", error["code"])

    def test_dsview_setting_get_and_put_use_closed_boolean_form(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            assert isinstance(session, dict)
            self.assertIn("units.applianceSettings.security.SecurityDSView", session["navigation"]["paths"])
            socket_path = root / "dsview.sock"
            page = (
                b'<avtrans><action>content</action><paths><path>units.applianceSettings.security.SecurityDSView</path></paths>'
                b'<payload><section id="dsviewControl" structure="form"><parameter id="dsview" structure="title">'
                b'<parameter id="allowDSView" structure="checkbox"><value>true</value></parameter>'
                b'</parameter></section></payload></avtrans>'
            )
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(socket_path),
            }
            with FakeAvtransController(socket_path, [page]) as controller:
                get_result = self.run_cgi(
                    "GET", "/api/v1/settings/security/dsview", cookie=cookie,
                    extra_environment=environment,
                )
            get_headers, get_body = self.cgi_json(get_result)
            self.assertIn(b"Status: 200", get_headers)
            self.assertEqual({"allowDSView": True}, get_body)
            self.assertEqual(1, len(controller.requests))
            self.assertIn(b"<action>get</action>", controller.requests[0][1])
            self.assertIn(b"<path>units.applianceSettings.security.SecurityDSView</path>", controller.requests[0][1])

            malformed_socket = root / "dsview-malformed.sock"
            malformed_environment = dict(environment)
            malformed_environment["PM3000_AVTRANS_SOCKET"] = str(malformed_socket)
            malformed_page = page.replace(b'id="dsview" structure="title"', b'id="unexpected" structure="title"')
            with FakeAvtransController(malformed_socket, [malformed_page]):
                malformed = self.run_cgi(
                    "GET", "/api/v1/settings/security/dsview", cookie=cookie,
                    extra_environment=malformed_environment,
                )
            headers, error = self.cgi_json(malformed)
            self.assertIn(b"Status: 502", headers)
            self.assertEqual("backend_protocol_error", error["code"])

            saved_page = page.replace(b"<value>true</value>", b"<value>false</value>")
            put_socket_path = root / "dsview-put.sock"
            put_environment = dict(environment)
            put_environment["PM3000_AVTRANS_SOCKET"] = str(put_socket_path)
            with FakeAvtransController(put_socket_path, [saved_page]) as controller:
                put_result = self.run_cgi(
                    "PUT", "/api/v1/settings/security/dsview", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=b'{"allowDSView":false}',
                    content_type="application/json", extra_environment=put_environment,
                )
            self.assertIn(b"Status: 204", put_result.stdout)
            self.assertEqual(1, len(controller.requests))
            request = controller.requests[0][1]
            self.assertIn(b"<action>save</action>", request)
            self.assertIn(b"<path>units.applianceSettings.security.SecurityDSView</path>", request)
            self.assertIn(
                b'<section structure="form"><parameter id="allowDSView" structure="checkbox"><value>false</value></parameter></section>',
                request,
            )

            mismatch_socket = root / "dsview-mismatch.sock"
            put_environment["PM3000_AVTRANS_SOCKET"] = str(mismatch_socket)
            with FakeAvtransController(mismatch_socket, [page]):
                mismatch = self.run_cgi(
                    "PUT", "/api/v1/settings/security/dsview", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=b'{"allowDSView":false}',
                    content_type="application/json", extra_environment=put_environment,
                )
            self.assertIn(b"Status: 503", mismatch.stdout)

    def test_nis_setting_get_and_put_use_closed_complete_form(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            assert isinstance(session, dict)
            permission = "units.authentication.authenticationservers.nis"
            navigation = session["navigation"]
            assert isinstance(navigation, dict)
            self.assertIn(permission, navigation["paths"])
            page = (
                b'<avtrans><action>content</action><paths><path>units.authentication.authenticationservers.nis</path></paths>'
                b'<payload><section id="nisserver" structure="form">'
                b'<parameter id="domainname" structure="text"><value>example</value></parameter>'
                b'<parameter id="address" structure="text"><value>nis.example.test</value></parameter>'
                b'</section></payload></avtrans>'
            )
            get_socket = root / "nis-get.sock"
            environment = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(get_socket)}
            with FakeAvtransController(get_socket, [page]) as controller:
                result = self.run_cgi("GET", "/api/v1/settings/authentication/nis", cookie=cookie, extra_environment=environment)
            headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            self.assertEqual({"domainName": "example", "address": "nis.example.test"}, payload)
            self.assertIn(b"<action>get</action>", controller.requests[0][1])

            malformed_pages = (
                page.replace(
                    b'<parameter id="domainname" structure="text"><value>example</value></parameter><parameter id="address" structure="text"><value>nis.example.test</value></parameter>',
                    b'<parameter id="address" structure="text"><value>nis.example.test</value></parameter><parameter id="domainname" structure="text"><value>example</value></parameter>',
                ),
                page.replace(b'id="domainname" structure="text"', b'id="domainname" structure="checkbox"'),
                page.replace(b'<parameter id="domainname"', b'<section structure="title"><parameter id="domainname"').replace(
                    b'</parameter><parameter id="address"', b'</parameter></section><parameter id="address"', 1
                ),
            )
            for index, malformed_page in enumerate(malformed_pages):
                malformed_socket = root / f"nis-malformed-{index}.sock"
                malformed_environment = dict(environment)
                malformed_environment["PM3000_AVTRANS_SOCKET"] = str(malformed_socket)
                with FakeAvtransController(malformed_socket, [malformed_page]):
                    malformed = self.run_cgi(
                        "GET", "/api/v1/settings/authentication/nis", cookie=cookie,
                        extra_environment=malformed_environment,
                    )
                headers, error = self.cgi_json(malformed)
                self.assertIn(b"Status: 502", headers)
                self.assertEqual("backend_protocol_error", error["code"])

            put_socket = root / "nis-put.sock"
            environment["PM3000_AVTRANS_SOCKET"] = str(put_socket)
            body = b'{"domainName":"example2","address":"broadcast"}'
            saved_page = page.replace(
                b"<value>example</value>", b"<value>example2</value>"
            ).replace(
                b"<value>nis.example.test</value>", b"<value>broadcast</value>"
            )
            with FakeAvtransController(put_socket, [saved_page]) as controller:
                result = self.run_cgi(
                    "PUT", "/api/v1/settings/authentication/nis", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body,
                    content_type="application/json", extra_environment=environment,
                )
            self.assertIn(b"Status: 204", result.stdout)
            request = controller.requests[0][1]
            self.assertIn(b"<path>units.authentication.authenticationservers.nis</path>", request)
            self.assertIn(b'<parameter id="domainname" structure="text"><value>example2</value></parameter>', request)
            self.assertIn(b'<parameter id="address" structure="text"><value>broadcast</value></parameter>', request)

            mismatch_socket = root / "nis-mismatch.sock"
            environment["PM3000_AVTRANS_SOCKET"] = str(mismatch_socket)
            with FakeAvtransController(mismatch_socket, [page]):
                mismatch = self.run_cgi(
                    "PUT", "/api/v1/settings/authentication/nis", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body,
                    content_type="application/json", extra_environment=environment,
                )
            self.assertIn(b"Status: 503", mismatch.stdout)

            for invalid_body in (
                b'{"domainName":"bad domain","address":"broadcast"}',
                b'{"domainName":"example","address":"bad/address"}',
                b'{"domainName":"' + (b"a" * 100) + b'","address":"broadcast"}',
            ):
                rejected = self.run_cgi(
                    "PUT", "/api/v1/settings/authentication/nis", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=invalid_body,
                    content_type="application/json", extra_environment=environment,
                )
                self.assertIn(b"Status: 400", rejected.stdout)

    @staticmethod
    def help_language_page(language: bytes = b"en", url: bytes = b"https://help.example.test/a&amp;b") -> bytes:
        return (
            b'<avtrans><action>content</action><paths><path>units.applianceSettings.help</path></paths><payload>'
            b'<controls><control id="save" structure="button"/></controls>'
            b'<section id="sessionform" structure="form">'
            b'<parameter id="applanguage" structure="combo"><value>' + language +
            b'</value><option label="English">en</option><option label="Deutsch">de</option></parameter>'
            b'<parameter id="url" structure="RWtext"><value>' + url +
            b'</value></parameter></section></payload></avtrans>'
        )

    @staticmethod
    def data_buffering_page(values: tuple[bytes, ...] = (
        b"1024", b"4", b"nfs.example.test", b"/buffer", b"4096", b"8", b"LOG_LOCAL2"
    )) -> bytes:
        local_size, local_segments, nfs_server, nfs_path, nfs_size, nfs_segments, facility = values
        return (
            b'<avtrans><action>content</action><paths><path>units.event_notification.global_settings_databuffering</path></paths><payload>'
            b'<controls><control id="save" structure="button"/></controls>'
            b'<section id="global_settings_form" structure="form">'
            b'<parameter id="local" structure="title">'
            b'<parameter id="local_size" structure="RWtext"><value>' + local_size + b'</value></parameter>'
            b'<parameter id="local_segments" structure="RWtext"><value>' + local_segments + b'</value></parameter></parameter>'
            b'<parameter id="nfs" structure="title"><parameter id="nfs_notice" structure="notice"/>'
            b'<parameter id="nfs_server" structure="RWtext"><value>' + nfs_server + b'</value></parameter>'
            b'<parameter id="nfs_path" structure="RWtext"><value>' + nfs_path + b'</value></parameter>'
            b'<parameter id="nfs_size" structure="RWtext"><value>' + nfs_size + b'</value></parameter>'
            b'<parameter id="nfs_segments" structure="RWtext"><value>' + nfs_segments + b'</value></parameter></parameter>'
            b'<parameter id="syslog" structure="title"><parameter id="syslog_facility" structure="combo"><value>' + facility +
            b'</value><option>LOG_LOCAL0</option><option>LOG_LOCAL1</option><option>LOG_LOCAL2</option>'
            b'<option>LOG_LOCAL3</option><option>LOG_LOCAL4</option><option>LOG_LOCAL5</option></parameter></parameter>'
            b'</section></payload></avtrans>'
        )

    @staticmethod
    def appliance_logging_page(
        enabled: bool = True, destination: bytes = b"local", timestamp: bool = True,
        alerts_enabled: bool = True, alert_strings: tuple[bytes, ...] = (b"alert one", b"", b"", b"", b"", b"", b"", b"", b"", b""),
    ) -> bytes:
        assert len(alert_strings) == 10
        strings = b"".join(
            b'<parameter id="alertstring' + str(index + 1).encode() +
            b'" structure="RWtext"><value>' + value + b"</value></parameter>"
            for index, value in enumerate(alert_strings)
        )
        return (
            b'<avtrans><action>content</action><paths><path>units.event_notification.sessions</path></paths><payload>'
            b'<controls><control id="save" structure="button"/></controls>'
            b'<section id="sessionform" structure="form"><parameter id="sessiontitle" structure="title">'
            b'<parameter id="sessionlogenable" structure="checkbox"><value>' +
            (b"true" if enabled else b"false") + b'</value><parameter id="notice" structure="notice"/>'
            b'<parameter id="destination" structure="combo"><value>' + destination +
            b'</value><option>local</option><option>nfs</option><option>syslog</option><option>dsview</option></parameter>'
            b'<parameter id="enabletimestamp" structure="combo"><value>' +
            (b"yes" if timestamp else b"no") + b'</value><option>yes</option><option>no</option></parameter>'
            b'<parameter id="alertenable" structure="checkbox"><value>' +
            (b"true" if alerts_enabled else b"false") + b'</value>' + strings +
            b'</parameter></parameter></parameter></section></payload></avtrans>'
        )

    @staticmethod
    def time_zone_page(
        mode: bytes = b"no", selected: bytes = b"UTC", dst_enabled: bool = False,
        choices: tuple[bytes, ...] = (b"Europe/Berlin", b"UTC"),
    ) -> bytes:
        options = b"".join(b'<option label="zone">' + value + b"</option>" for value in choices)
        months = b"".join(b"<option>" + str(value).encode() + b"</option>" for value in range(1, 13))
        weeks = b"".join(b"<option>" + str(value).encode() + b"</option>" for value in range(1, 6))
        days = b"".join(b"<option>" + str(value).encode() + b"</option>" for value in range(1, 8))
        return (
            b'<avtrans><action>content</action><paths><path>units.applianceSettings.date_and_time.time_zone</path></paths><payload>'
            b'<controls><control id="save" structure="button"/></controls>'
            b'<section id="time_zoneform" structure="form">'
            b'<parameter id="customtimezone" structure="radiobox"><value>' + mode + b'</value>'
            b'<parameter value="no" structure="radio"><parameter id="timezone_list" structure="combo"><value>' +
            selected + b'</value>' + options + b'</parameter></parameter>'
            b'<parameter value="yes" structure="radio">'
            b'<parameter id="tzName" structure="RWtext"><value>Example</value></parameter>'
            b'<parameter id="stdTimeAcronym" structure="RWtext"><value>EX</value></parameter>'
            b'<parameter id="gmtOffset" structure="RWtext"><value>-7:00</value></parameter>'
            b'<parameter id="enableDst" structure="checkbox"><value>' +
            (b"true" if dst_enabled else b"false") + b'</value>'
            b'<parameter id="dstAcronym" structure="RWtext"><value>EDT</value></parameter>'
            b'<parameter id="saveTime" structure="RWtext"><value>1:00</value></parameter>'
            b'<parameter id="startMonth" structure="combo"><value>3</value>' + months + b'</parameter>'
            b'<parameter id="startWeek" structure="combo"><value>2</value>' + weeks + b'</parameter>'
            b'<parameter id="startWeekday" structure="combo"><value>1</value>' + days + b'</parameter>'
            b'<parameter id="startHour" structure="RWtext"><value>2:00</value></parameter>'
            b'<parameter id="endMonth" structure="combo"><value>11</value>' + months + b'</parameter>'
            b'<parameter id="endWeek" structure="combo"><value>1</value>' + weeks + b'</parameter>'
            b'<parameter id="endWeekday" structure="combo"><value>1</value>' + days + b'</parameter>'
            b'<parameter id="endHour" structure="RWtext"><value>2:00</value></parameter>'
            b'</parameter></parameter></parameter></section></payload></avtrans>'
        )

    def setting_get(self, root: Path, cookie: str, route: str, page: bytes, name: str):
        socket_path = root / f"{name}-get.sock"
        with FakeAvtransController(socket_path, [page]) as controller:
            result = self.run_cgi(
                "GET", route, cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(socket_path),
                },
            )
        return result, controller

    def test_fixed_settings_require_exact_navigation_write_capabilities(self) -> None:
        cases = (
            (b'accessPath="configuration.appliance.language" accessRights="w"',
             b'accessPath="configuration.appliance.language.other" accessRights="w"',
             "/api/v1/settings/help-language"),
            (b'accessPath="configuration.event-notify" accessRights="w"',
             b'accessPath="configuration.event-notify" accessRights="r"',
             "/api/v1/settings/data-buffering"),
            (b'accessPath="configuration.event-notify" accessRights="w"',
             b'accessPath="configuration.event-notify" accessRights="r"',
             "/api/v1/settings/appliance-logging"),
            (b'accessPath="management.date" accessRights="w"',
             b'accessPath="management.date" accessRights="r"',
             "/api/v1/settings/time-zone"),
        )
        for expected, replacement, route in cases:
            with self.subTest(route=route), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                navigation = NAVIGATION_RESPONSE.read_bytes().replace(expected, replacement, 1)
                cookie, _session, _controller, _result = self.login_session(root, navigation=navigation)
                rejected = self.run_cgi(
                    "GET", route, cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
                    },
                )
                headers, payload = self.cgi_json(rejected)
                self.assertIn(b"Status: 403", headers)
                self.assertEqual("forbidden", payload["code"])
                self.assertFalse((root / "must-not-open.sock").exists())

    def test_help_language_get_returns_values_choices_revision_and_strong_etag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _controller, _result = self.login_session(root)
            result, controller = self.setting_get(
                root, cookie, "/api/v1/settings/help-language", self.help_language_page(), "help"
            )
            headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            etag = next(line.split(b": ", 1)[1] for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            self.assertRegex(etag.decode(), r'^"[0-9a-f]{64}"$')
            self.assertEqual(etag.decode(), payload["revision"])
            self.assertEqual("en", payload["applianceLanguage"])
            self.assertEqual("https://help.example.test/a&b", payload["url"])
            self.assertEqual(["en", "de"], payload["allowedLanguages"])
            self.assertEqual(1, len(controller.requests))
            self.assertIn(b"<action>get</action>", controller.requests[0][1])

    def test_fixed_setting_backend_accepts_legal_xml_whitespace_in_allowed_attribute(self) -> None:
        for name, whitespace in (("tab", b"\t"), ("line-feed", b"\n"), ("carriage-return", b"\r")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cookie, _session, _controller, _result = self.login_session(root)
                page = self.help_language_page().replace(
                    b'<option label="English">', b'<option label="before' + whitespace + b'after">', 1
                )
                result, _controller = self.setting_get(
                    root, cookie, "/api/v1/settings/help-language", page, f"help-{name}"
                )
                headers, payload = self.cgi_json(result)
                self.assertIn(b"Status: 200", headers)
                self.assertEqual("en", payload["applianceLanguage"])

    def test_fixed_setting_get_rejects_wrong_hierarchy_duplicates_controls_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _controller, _result = self.login_session(root)
            help_page = self.help_language_page()
            data_page = self.data_buffering_page()
            time_zone_page = self.time_zone_page()
            cases = (
                ("help-no-save", "/api/v1/settings/help-language", help_page.replace(b'<controls><control id="save" structure="button"/></controls>', b"")),
                ("help-extra-control", "/api/v1/settings/help-language", help_page.replace(b'</controls>', b'<control id="other" structure="button"/></controls>')),
                ("help-stray-control-in-form", "/api/v1/settings/help-language", help_page.replace(b'<controls>', b'<control id="unexpected" structure="button"/><controls>')),
                ("help-nested-empty-controls", "/api/v1/settings/help-language", help_page.replace(b'<controls>', b'<controls/><controls>')),
                ("help-control-under-payload", "/api/v1/settings/help-language", help_page.replace(b'<section id="sessionform"', b'<control id="unexpected" structure="button"/><section id="sessionform"')),
                ("help-extra-form", "/api/v1/settings/help-language", help_page.replace(b'</payload>', b'<section id="other" structure="form"></section></payload>')),
                ("help-duplicate", "/api/v1/settings/help-language", help_page.replace(b'</section></payload>', b'<parameter id="url" structure="RWtext"><value>x</value></parameter></section></payload>')),
                ("help-unknown", "/api/v1/settings/help-language", help_page.replace(b'</section></payload>', b'<parameter id="hidden" structure="RWtext"><value>x</value></parameter></section></payload>')),
                ("help-unknown-empty", "/api/v1/settings/help-language", help_page.replace(b'</section></payload>', b'<parameter id="hidden" structure="password"/></section></payload>')),
                ("help-choice-duplicate", "/api/v1/settings/help-language", help_page.replace(b'</parameter><parameter id="url"', b'<option>en</option></parameter><parameter id="url"', 1)),
                ("help-choice-wrong-field", "/api/v1/settings/help-language", help_page.replace(b'</value></parameter></section></payload>', b'</value><option>x</option></parameter></section></payload>', 1)),
                ("help-language-long", "/api/v1/settings/help-language", self.help_language_page(b"a" * 33)),
                ("help-xml-noncharacter", "/api/v1/settings/help-language", self.help_language_page(b"en", b"\xef\xbf\xbe")),
                ("help-literal-cdata-close", "/api/v1/settings/help-language", self.help_language_page(b"en", b"https://help.example.test/a]]>b")),
                ("help-text-under-payload", "/api/v1/settings/help-language", help_page.replace(b"<controls>", b"JUNK<controls>")),
                ("help-empty-processing-instruction", "/api/v1/settings/help-language", b"<??>" + help_page),
                ("help-incomplete-xml-declaration", "/api/v1/settings/help-language", b"<?xml?>" + help_page),
                ("help-invalid-processing-target", "/api/v1/settings/help-language", b"<?1bad?>" + help_page),
                ("help-extra-root-child", "/api/v1/settings/help-language", help_page.replace(b"<avtrans>", b"<avtrans><unexpected/>", 1)),
                ("help-text-under-root", "/api/v1/settings/help-language", help_page.replace(b"</action>", b"</action>JUNK", 1)),
                ("help-root-attribute", "/api/v1/settings/help-language", help_page.replace(b"<avtrans>", b'<avtrans mystery="x">', 1)),
                ("help-action-attribute", "/api/v1/settings/help-language", help_page.replace(b"<action>", b'<action mystery="x">', 1)),
                ("help-paths-attribute", "/api/v1/settings/help-language", help_page.replace(b"<paths>", b'<paths mystery="x">', 1)),
                ("help-path-attribute", "/api/v1/settings/help-language", help_page.replace(b"<path>", b'<path mystery="x">', 1)),
                ("help-payload-attribute", "/api/v1/settings/help-language", help_page.replace(b"<payload>", b'<payload mystery="x">', 1)),
                ("help-controls-attribute", "/api/v1/settings/help-language", help_page.replace(b"<controls>", b'<controls mystery="x">', 1)),
                ("help-control-attribute", "/api/v1/settings/help-language", help_page.replace(b'<control id="save"', b'<control mystery="x" id="save"', 1)),
                ("help-section-attribute", "/api/v1/settings/help-language", help_page.replace(b'<section id="sessionform"', b'<section mystery="x" id="sessionform"', 1)),
                ("help-parameter-attribute", "/api/v1/settings/help-language", help_page.replace(b'<parameter id="url"', b'<parameter mystery="x" id="url"', 1)),
                ("help-value-attribute", "/api/v1/settings/help-language", help_page.replace(b"<value>", b'<value mystery="x">', 1)),
                ("help-option-attribute", "/api/v1/settings/help-language", help_page.replace(b'<option label="English"', b'<option mystery="x" label="English"', 1)),
                ("help-default-namespace", "/api/v1/settings/help-language", help_page.replace(b"<avtrans>", b'<avtrans xmlns="urn:x">', 1)),
                ("help-prefixed-attribute", "/api/v1/settings/help-language", help_page.replace(b"<payload>", b'<payload x:flag="1">', 1)),
                ("help-invalid-attribute-name", "/api/v1/settings/help-language", help_page.replace(b"<payload>", b'<payload 1bad="1">', 1)),
                ("help-missing-attribute-space", "/api/v1/settings/help-language", help_page.replace(b'id="save" structure=', b'id="save"structure=', 1)),
                ("help-prefixed-id-attribute", "/api/v1/settings/help-language", help_page.replace(b'id="save" structure=', b'id="save" x:id="other" structure=', 1)),
                ("help-declaration-missing-space", "/api/v1/settings/help-language", b'<?xml version="1.0"encoding="UTF-8"?>' + help_page),
                ("help-payload-before-paths", "/api/v1/settings/help-language", help_page.replace(b'<paths><path>units.applianceSettings.help</path></paths>', b'', 1).replace(b'</avtrans>', b'<paths><path>units.applianceSettings.help</path></paths></avtrans>', 1)),
                ("help-controls-after-form", "/api/v1/settings/help-language", help_page.replace(b'<controls><control id="save" structure="button"/></controls>', b'', 1).replace(b'</payload>', b'<controls><control id="save" structure="button"/></controls></payload>', 1)),
                ("help-extra-empty-paths", "/api/v1/settings/help-language", help_page.replace(b'</paths>', b'</paths><paths/>', 1)),
                ("help-option-before-value", "/api/v1/settings/help-language", help_page.replace(b'<value>en</value><option label="English">en</option>', b'<option label="English">en</option><value>en</value>', 1)),
                ("data-wrong-parent", "/api/v1/settings/data-buffering", data_page.replace(b'id="local" structure="title"', b'id="wrong" structure="title"')),
                ("data-syslog-wrong-parent", "/api/v1/settings/data-buffering", data_page.replace(b'id="syslog" structure="title"', b'id="wrong" structure="title"')),
                ("data-duplicate", "/api/v1/settings/data-buffering", data_page.replace(b'</parameter></parameter><parameter id="nfs"', b'</parameter><parameter id="local_size" structure="RWtext"><value>1</value></parameter></parameter><parameter id="nfs"', 1)),
                ("data-unknown-empty", "/api/v1/settings/data-buffering", data_page.replace(b'<parameter id="nfs_notice" structure="notice"/>', b'<parameter id="nfs_notice" structure="notice"/><parameter id="hidden" structure="password"/>')),
                ("data-missing-notice", "/api/v1/settings/data-buffering", data_page.replace(b'<parameter id="nfs_notice" structure="notice"/>', b"")),
                ("data-xml-noncharacter", "/api/v1/settings/data-buffering", self.data_buffering_page((b"1024", b"4", b"", b"\xef\xbf\xbe", b"4096", b"8", b"LOG_LOCAL2"))),
                ("data-noncharacter-in-title-text", "/api/v1/settings/data-buffering", data_page.replace(b'<parameter id="local" structure="title">', b'<parameter id="local" structure="title">\xef\xbf\xbe')),
                ("data-noncharacter-between-elements", "/api/v1/settings/data-buffering", data_page.replace(b'<controls>', b'\xef\xbf\xbf<controls>')),
                ("data-noncharacter-in-attribute", "/api/v1/settings/data-buffering", data_page.replace(b'<payload>', b'<payload ignored="\xef\xbf\xbe">')),
                ("data-prohibited-c0", "/api/v1/settings/data-buffering", data_page.replace(b'<controls>', b'\x01<controls>')),
                ("help-parameter-outside-form", "/api/v1/settings/help-language", help_page.replace(b'<section id="sessionform"', b'<parameter id="hidden" structure="password"/><section id="sessionform"')),
                ("help-empty-section-outside-form", "/api/v1/settings/help-language", help_page.replace(b'<section id="sessionform"', b'<section id="wrapper" structure="standard"/><section id="sessionform"')),
                ("help-stray-value", "/api/v1/settings/help-language", help_page.replace(b'<section id="sessionform"', b'<value>hidden</value><section id="sessionform"')),
                ("data-parameter-in-nonform", "/api/v1/settings/data-buffering", data_page.replace(b'<section id="global_settings_form"', b'<section id="wrapper" structure="standard"><parameter id="hidden" structure="password"/></section><section id="global_settings_form"')),
                ("data-out-of-range", "/api/v1/settings/data-buffering", self.data_buffering_page((b"2049", b"4", b"", b"/buffer", b"4096", b"8", b"LOG_LOCAL2"))),
                ("time-zone-radio-value", "/api/v1/settings/time-zone", time_zone_page.replace(b'<parameter value="no" structure="radio">', b'<parameter value="other" structure="radio">', 1)),
                ("time-zone-wrong-radio-parent", "/api/v1/settings/time-zone", time_zone_page.replace(b'<parameter value="no" structure="radio"><parameter id="timezone_list"', b'<parameter value="no" structure="radio"></parameter><parameter id="timezone_list"', 1)),
                ("time-zone-duplicate-choice", "/api/v1/settings/time-zone", time_zone_page.replace(b'</parameter></parameter><parameter value="yes"', b'<option>UTC</option></parameter></parameter><parameter value="yes"', 1)),
                ("time-zone-reordered-fields", "/api/v1/settings/time-zone", time_zone_page.replace(b'<parameter id="tzName" structure="RWtext"><value>Example</value></parameter><parameter id="stdTimeAcronym" structure="RWtext"><value>EX</value></parameter>', b'<parameter id="stdTimeAcronym" structure="RWtext"><value>EX</value></parameter><parameter id="tzName" structure="RWtext"><value>Example</value></parameter>', 1)),
            )
            for name, route, page in cases:
                with self.subTest(name=name):
                    result, _controller = self.setting_get(root, cookie, route, page, name)
                    headers, payload = self.cgi_json(result)
                    self.assertIn(b"Status: 502", headers)
                    self.assertEqual("backend_protocol_error", payload["code"])

    def test_help_language_put_is_get_first_closed_and_serializes_escaped_ordered_complete_form(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            get_result, _controller = self.setting_get(root, cookie, "/api/v1/settings/help-language", self.help_language_page(), "help-rev")
            get_headers, payload = self.cgi_json(get_result)
            revision = next(line.split(b": ", 1)[1].decode() for line in get_headers.split(b"\r\n") if line.startswith(b"ETag: "))
            self.assertEqual(revision, payload["revision"])
            current = self.help_language_page()
            saved = self.help_language_page(b"de", b"https://help.example.test/?x=&lt;&amp;y=&quot;q&quot;")
            socket_path = root / "help-put.sock"
            environment = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": revision}
            body = json.dumps({"applianceLanguage": "de", "url": 'https://help.example.test/?x=<&y="q"'}, ensure_ascii=False).encode()
            with FakeAvtransController(socket_path, [current, saved]) as controller:
                result = self.run_cgi(
                    "PUT", "/api/v1/settings/help-language", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body,
                    content_type="application/json", extra_environment=environment,
                )
            self.assertIn(b"Status: 204", result.stdout)
            self.assertEqual(2, len(controller.requests))
            request = controller.requests[1][1]
            expected = (
                b'<section structure="form"><parameter id="applanguage" structure="combo"><value>de</value></parameter>'
                b'<parameter id="url" structure="RWtext"><value>https://help.example.test/?x=&lt;&amp;y=&quot;q&quot;</value></parameter></section>'
            )
            self.assertIn(expected, request)
            self.assertNotIn(b"sessionform", request)

            maximum_url = "'" * 256
            maximum_saved = self.help_language_page(b"en", b"&apos;" * 256)
            maximum_socket = root / "help-put-maximum-expansion.sock"
            maximum_environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(maximum_socket),
                "HTTP_IF_MATCH": revision,
            }
            with FakeAvtransController(maximum_socket, [current, maximum_saved]) as maximum_controller:
                maximum_result = self.run_cgi(
                    "PUT", "/api/v1/settings/help-language", cookie=cookie,
                    csrf=str(session["csrfToken"]),
                    body=json.dumps({"applianceLanguage": "en", "url": maximum_url}).encode(),
                    content_type="application/json", extra_environment=maximum_environment,
                )
            self.assertIn(b"Status: 204", maximum_result.stdout)
            self.assertEqual(2, len(maximum_controller.requests))
            self.assertIn(b"&apos;" * 256, maximum_controller.requests[1][1])

    def test_help_language_put_rejects_auth_preconditions_json_and_fresh_choices_before_save(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            environment = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock")}
            valid = b'{"applianceLanguage":"en","url":"https://help.example.test"}'
            cases = (
                ("missing-csrf", {}, valid, b"Status: 403"),
                ("bearer", {"csrf": str(session["csrfToken"]), "authorization": "Bearer denied"}, valid, b"Status: 401"),
                ("missing-if-match", {"csrf": str(session["csrfToken"])}, valid, b"Status: 428"),
                ("invalid-if-match", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "g" * 64 + '"'}}, valid, b"Status: 400"),
                ("unknown", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "0" * 64 + '"'}}, b'{"applianceLanguage":"en","url":"x","hidden":"bad"}', b"Status: 400"),
                ("duplicate", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "0" * 64 + '"'}}, b'{"applianceLanguage":"en","applianceLanguage":"de","url":"x"}', b"Status: 400"),
                ("url-empty", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "0" * 64 + '"'}}, b'{"applianceLanguage":"en","url":""}', b"Status: 400"),
                ("url-bytes", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "0" * 64 + '"'}}, json.dumps({"applianceLanguage":"en", "url":"é" * 129}, ensure_ascii=False).encode(), b"Status: 400"),
                ("url-xml-noncharacter", {"csrf": str(session["csrfToken"]), "extra_environment": {**environment, "HTTP_IF_MATCH": '"' + "0" * 64 + '"'}}, b'{"applianceLanguage":"en","url":"\\ufffe"}', b"Status: 400"),
            )
            for name, kwargs, body, expected in cases:
                with self.subTest(name=name):
                    options = {"cookie": cookie, "body": body, "content_type": "application/json", "extra_environment": environment}
                    options.update(kwargs)
                    rejected = self.run_cgi("PUT", "/api/v1/settings/help-language", **options)
                    self.assertIn(expected, rejected.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())

            get_result, _controller = self.setting_get(root, cookie, "/api/v1/settings/help-language", self.help_language_page(), "help-choice-rev")
            headers = get_result.stdout.split(b"\r\n\r\n", 1)[0]
            revision = next(line.split(b": ", 1)[1].decode() for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            socket_path = root / "help-choice.sock"
            with FakeAvtransController(socket_path, [self.help_language_page()]) as controller:
                rejected = self.run_cgi(
                    "PUT", "/api/v1/settings/help-language", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=b'{"applianceLanguage":"fr","url":"https://help.example.test"}',
                    content_type="application/json", extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": revision,
                    },
                )
            self.assertIn(b"Status: 400", rejected.stdout)
            self.assertEqual(1, len(controller.requests))

    def test_data_buffering_get_and_put_enforce_revision_ranges_order_and_unknown_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            current = self.data_buffering_page()
            get_result, _controller = self.setting_get(root, cookie, "/api/v1/settings/data-buffering", current, "data-rev")
            headers, payload = self.cgi_json(get_result)
            revision = next(line.split(b": ", 1)[1].decode() for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            self.assertEqual({
                "localSize": 1024, "localSegments": 4, "nfsServer": "nfs.example.test", "nfsPath": "/buffer",
                "nfsSize": 4096, "nfsSegments": 8, "syslogFacility": "LOG_LOCAL2", "revision": revision,
            }, payload)
            requested = {"localSize": 0, "localSegments": 9, "nfsServer": "", "nfsPath": "<&", "nfsSize": 99999, "nfsSegments": 99, "syslogFacility": "LOG_LOCAL5"}
            saved = self.data_buffering_page((b"0", b"9", b"", b"&lt;&amp;", b"99999", b"99", b"LOG_LOCAL5"))
            socket_path = root / "data-put.sock"
            environment = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": revision}
            with FakeAvtransController(socket_path, [current, saved]) as controller:
                result = self.run_cgi(
                    "PUT", "/api/v1/settings/data-buffering", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=json.dumps(requested).encode(),
                    content_type="application/json", extra_environment=environment,
                )
            self.assertIn(b"Status: 204", result.stdout)
            request = controller.requests[1][1]
            ids = [b'local_size', b'local_segments', b'nfs_server', b'nfs_path', b'nfs_size', b'nfs_segments', b'syslog_facility']
            self.assertEqual(sorted(request.index(b'id="' + item + b'"') for item in ids), [request.index(b'id="' + item + b'"') for item in ids])
            self.assertIn(b"<value>&lt;&amp;</value>", request)
            self.assertNotIn(b"global_settings_form", request)
            self.assertNotIn(b'id="local"', request)
            self.assertNotIn(b'id="nfs"', request)
            self.assertNotIn(b'id="syslog"', request)

            mismatch_socket = root / "data-mismatch.sock"
            environment["PM3000_AVTRANS_SOCKET"] = str(mismatch_socket)
            with FakeAvtransController(mismatch_socket, [current, current]) as mismatch_controller:
                mismatch = self.run_cgi(
                    "PUT", "/api/v1/settings/data-buffering", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=json.dumps(requested).encode(),
                    content_type="application/json", extra_environment=environment,
                )
            _, error = self.cgi_json(mismatch)
            self.assertEqual("action_outcome_unknown", error["code"])
            self.assertEqual(2, len(mismatch_controller.requests))

            invalid_cases = (
                {**requested, "localSize": -1}, {**requested, "localSize": 2049},
                {**requested, "localSegments": 0}, {**requested, "localSegments": 10},
                {**requested, "nfsSize": 100000}, {**requested, "nfsSegments": 100},
                {**requested, "nfsServer": "bad server"}, {**requested, "nfsServer": "é" * 51},
                {**requested, "nfsPath": "é" * 51}, {**requested, "syslogFacility": "LOG_LOCAL6"},
                {**requested, "metadata": "forbidden"},
            )
            no_backend = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(root / "never.sock"), "HTTP_IF_MATCH": revision}
            for candidate in invalid_cases:
                rejected = self.run_cgi(
                    "PUT", "/api/v1/settings/data-buffering", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=json.dumps(candidate, ensure_ascii=False).encode(),
                    content_type="application/json", extra_environment=no_backend,
                )
                self.assertIn(b"Status: 400", rejected.stdout, candidate)
            self.assertFalse((root / "never.sock").exists())

    def test_time_zone_get_and_conditional_put_preserve_inactive_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            route = "/api/v1/settings/time-zone"
            current = self.time_zone_page()
            get_result, _controller = self.setting_get(root, cookie, route, current, "time-zone")
            headers, payload = self.cgi_json(get_result)
            self.assertIn(b"Status: 200", headers)
            revision = next(line.split(b": ", 1)[1].decode() for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            self.assertEqual("predefined", payload["mode"])
            self.assertEqual({"selected": "UTC", "choices": ["Europe/Berlin", "UTC"]}, payload["predefined"])
            self.assertEqual("Example", payload["custom"]["name"])
            self.assertFalse(payload["custom"]["dst"]["enabled"])
            self.assertEqual(revision, payload["revision"])

            cases = (
                ("predefined", {"mode": "predefined", "predefinedZone": "Europe/Berlin"}, self.time_zone_page(selected=b"Europe/Berlin"), b'<parameter id="timezone_list" structure="combo"><value>Europe/Berlin</value></parameter>', b'id="tzName"'),
                ("custom-no-dst", {"mode": "custom", "custom": {"name": "Example", "standardAcronym": "EX", "gmtOffset": "-7:00", "dst": {"enabled": False}}}, self.time_zone_page(mode=b"yes"), b'<parameter id="enableDst" structure="checkbox"><value>false</value></parameter>', b'id="dstAcronym"'),
                (
                    "custom-dst",
                    {
                        "mode": "custom",
                        "custom": {
                            "name": "Example", "standardAcronym": "EX", "gmtOffset": "-7:00",
                            "dst": {
                                "enabled": True, "acronym": "EDT", "saveTime": "1:00",
                                "start": {"month": "3", "week": "2", "weekday": "1", "hour": "2:00"},
                                "end": {"month": "11", "week": "1", "weekday": "1", "hour": "2:00"},
                            },
                        },
                    },
                    self.time_zone_page(mode=b"yes", dst_enabled=True),
                    b'<parameter id="dstAcronym" structure="RWtext"><value>EDT</value></parameter>',
                    b'id="timezone_list"',
                ),
            )
            for name, body, saved, included, omitted in cases:
                socket_path = root / f"time-zone-{name}.sock"
                environment = {"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": revision}
                with self.subTest(name=name), FakeAvtransController(socket_path, [current, saved]) as controller:
                    result = self.run_cgi("PUT", route, cookie=cookie, csrf=str(session["csrfToken"]), body=json.dumps(body).encode(), content_type="application/json", extra_environment=environment)
                self.assertIn(b"Status: 204", result.stdout)
                self.assertEqual(2, len(controller.requests))
                self.assertIn(included, controller.requests[1][1])
                self.assertNotIn(omitted, controller.requests[1][1])

    def test_time_zone_write_lock_rejects_symlink_and_contention_before_backend_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            victim = root / "victim"
            victim.write_text("unchanged")
            (root / "sessions" / "settings-write.lock").symlink_to(victim)
            result = self.run_cgi(
                "PUT", "/api/v1/settings/time-zone", cookie=cookie,
                csrf=str(session["csrfToken"]),
                body=b'{"mode":"predefined","predefinedZone":"UTC"}', content_type="application/json",
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "never.sock"),
                    "HTTP_IF_MATCH": '"' + "a" * 64 + '"',
                },
            )
            headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 503", headers)
            self.assertEqual("backend_unavailable", payload["code"])
            self.assertEqual("unchanged", victim.read_text())
            self.assertFalse((root / "never.sock").exists())

            (root / "sessions" / "settings-write.lock").unlink()
            lock_path = root / "sessions" / "settings-write.lock"
            lock_path.touch(mode=0o600)
            with lock_path.open("r+") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                busy = self.run_cgi(
                    "PUT", "/api/v1/settings/time-zone", cookie=cookie,
                    csrf=str(session["csrfToken"]),
                    body=b'{"mode":"predefined","predefinedZone":"UTC"}',
                    content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(root / "still-never.sock"),
                        "HTTP_IF_MATCH": '"' + "a" * 64 + '"',
                    },
                )
            headers, payload = self.cgi_json(busy)
            self.assertIn(b"Status: 503", headers)
            self.assertEqual("backend_unavailable", payload["code"])
            self.assertFalse((root / "still-never.sock").exists())

    def test_time_zone_synthetic_fixture_matches_native_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _controller, _result = self.login_session(root)
            result, _controller = self.setting_get(
                root, cookie, "/api/v1/settings/time-zone",
                TIME_ZONE_RESPONSE.read_bytes(), "time-zone-synthetic-fixture",
            )
            headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            self.assertEqual("predefined", payload["mode"])
            self.assertIn(payload["predefined"]["selected"], payload["predefined"]["choices"])

    def test_time_zone_accepts_exact_firmware_choice_ceiling_and_rejects_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _controller, _result = self.login_session(root)
            choices = tuple(f"Etc/Z{index:03d}".encode("ascii") for index in range(521))
            accepted, _controller = self.setting_get(
                root, cookie, "/api/v1/settings/time-zone",
                self.time_zone_page(selected=choices[0], choices=choices), "time-zone-521",
            )
            headers, payload = self.cgi_json(accepted)
            self.assertIn(b"Status: 200", headers)
            self.assertEqual(521, len(payload["predefined"]["choices"]))
            rejected, _controller = self.setting_get(
                root, cookie, "/api/v1/settings/time-zone",
                self.time_zone_page(selected=choices[0], choices=choices + (b"Etc/Overflow",)), "time-zone-522",
            )
            headers, payload = self.cgi_json(rejected)
            self.assertIn(b"Status: 502", headers)
            self.assertEqual("backend_protocol_error", payload["code"])
            duplicate, _controller = self.setting_get(
                root, cookie, "/api/v1/settings/time-zone",
                self.time_zone_page(
                    selected=b"Etc/UTC", choices=(b"Etc/UTC", b"Europe/Berlin", b"Europe/Berlin")
                ),
                "time-zone-duplicate-choice",
            )
            headers, payload = self.cgi_json(duplicate)
            self.assertIn(b"Status: 502", headers)
            self.assertEqual("backend_protocol_error", payload["code"])

    def test_time_zone_close_after_save_is_unknown_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            current = self.time_zone_page()
            initial, _controller = self.setting_get(
                root, cookie, "/api/v1/settings/time-zone", current, "time-zone-unknown-initial"
            )
            headers, _payload = self.cgi_json(initial)
            revision = next(line.split(b": ", 1)[1].decode() for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            socket_path = root / "time-zone-unknown.sock"
            body = json.dumps({"mode": "predefined", "predefinedZone": "Europe/Berlin"}).encode()
            with FakeAvtransController(socket_path, [current, None]) as controller:
                result = self.run_cgi(
                    "PUT", "/api/v1/settings/time-zone", cookie=cookie,
                    csrf=str(session["csrfToken"]), body=body, content_type="application/json",
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path),
                        "HTTP_IF_MATCH": revision,
                    },
                )
            response_headers, payload = self.cgi_json(result)
            self.assertIn(b"Status: 503", response_headers)
            self.assertEqual("action_outcome_unknown", payload["code"])
            self.assertEqual(2, len(controller.requests))
            self.assertIn(b"<action>get</action>", controller.requests[0][1])
            self.assertIn(b"<action>save</action>", controller.requests[1][1])

    def test_appliance_logging_get_and_conditional_put_preserve_inactive_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            route = "/api/v1/settings/appliance-logging"
            current_strings = (b"one", b"two", b"three", b"four", b"five", b"six", b"seven", b"eight", b"nine", b"ten")
            current = self.appliance_logging_page(alert_strings=current_strings)
            get_result, _controller = self.setting_get(root, cookie, route, current, "logging-rev")
            headers, payload = self.cgi_json(get_result)
            self.assertIn(b"Status: 200", headers)
            revision = next(line.split(b": ", 1)[1].decode() for line in headers.split(b"\r\n") if line.startswith(b"ETag: "))
            self.assertEqual({
                "sessionLoggingEnabled": True, "destination": "local", "timestampEnabled": True,
                "alertsEnabled": True, "alertStrings": [item.decode() for item in current_strings],
                "allowedDestinations": ["local", "nfs", "syslog", "dsview"], "revision": revision,
            }, payload)

            cases = (
                (
                    "disabled", {"sessionLoggingEnabled": False},
                    self.appliance_logging_page(False, alert_strings=current_strings),
                    b'<section structure="form"><parameter id="sessionlogenable" structure="checkbox"><value>false</value></parameter></section>',
                    (b'id="destination"', b'id="alertenable"', b'id="alertstring1"'),
                ),
                (
                    "alerts-disabled", {"sessionLoggingEnabled": True, "destination": "nfs", "timestampEnabled": False, "alertsEnabled": False},
                    self.appliance_logging_page(True, b"nfs", False, False, current_strings),
                    b'<parameter id="sessionlogenable" structure="checkbox"><value>true</value><parameter id="destination" structure="combo"><value>nfs</value></parameter><parameter id="enabletimestamp" structure="combo"><value>no</value></parameter><parameter id="alertenable" structure="checkbox"><value>false</value></parameter></parameter>',
                    (b'id="alertstring1"',),
                ),
                (
                    "alerts-enabled", {"sessionLoggingEnabled": True, "destination": "syslog", "timestampEnabled": True, "alertsEnabled": True, "alertStrings": ["<&"] + [""] * 9},
                    self.appliance_logging_page(True, b"syslog", True, True, (b"&lt;&amp;",) + (b"",) * 9),
                    b'<parameter id="alertstring1" structure="RWtext"><value>&lt;&amp;</value></parameter>',
                    (),
                ),
            )
            for name, body, saved, expected, omitted in cases:
                with self.subTest(name=name):
                    socket_path = root / f"logging-{name}.sock"
                    environment = {
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": revision,
                    }
                    with FakeAvtransController(socket_path, [current, saved]) as controller:
                        result = self.run_cgi(
                            "PUT", route, cookie=cookie, csrf=str(session["csrfToken"]),
                            body=json.dumps(body).encode(), content_type="application/json",
                            extra_environment=environment,
                        )
                    self.assertIn(b"Status: 204", result.stdout)
                    self.assertEqual(2, len(controller.requests))
                    request = controller.requests[1][1]
                    self.assertIn(expected, request)
                    for marker in omitted:
                        self.assertNotIn(marker, request)

            current = self.appliance_logging_page(True, b"local", True, False, current_strings)
            read, _controller = self.setting_get(root, cookie, route, current, "logging-mismatch-read")
            read_headers, _payload = self.cgi_json(read)
            etag = next(line.split(b": ", 1)[1].decode() for line in read_headers.split(b"\r\n") if line.startswith(b"ETag: "))
            changed = self.appliance_logging_page(True, b"local", False, False, (b"tampered",) + current_strings[1:])
            socket_path = root / "logging-mismatch.sock"
            with FakeAvtransController(socket_path, [current, changed]) as controller:
                rejected = self.run_cgi(
                    "PUT", route, cookie=cookie, csrf=str(session["csrfToken"]),
                    body=json.dumps({"sessionLoggingEnabled": True, "destination": "local", "timestampEnabled": False, "alertsEnabled": False}).encode(),
                    content_type="application/json",
                    extra_environment={"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": etag},
                )
            _headers, payload = self.cgi_json(rejected)
            self.assertEqual("action_outcome_unknown", payload["code"])
            self.assertEqual(2, len(controller.requests))

            socket_path = root / "logging-disconnect-after-write.sock"
            with FakeAvtransController(socket_path, [current, None]) as controller:
                uncertain = self.run_cgi(
                    "PUT", route, cookie=cookie, csrf=str(session["csrfToken"]),
                    body=json.dumps({"sessionLoggingEnabled": False}).encode(),
                    content_type="application/json",
                    extra_environment={"PM3000_SESSION_DIR": str(root / "sessions"), "PM3000_AVTRANS_SOCKET": str(socket_path), "HTTP_IF_MATCH": etag},
                )
            uncertain_headers, uncertain_payload = self.cgi_json(uncertain)
            self.assertIn(b"Status: 503", uncertain_headers)
            self.assertEqual("action_outcome_unknown", uncertain_payload["code"])
            self.assertEqual(2, len(controller.requests))
            self.assertIn(b"<action>get</action>", controller.requests[0][1])
            self.assertIn(b"<action>save</action>", controller.requests[1][1])

    def test_appliance_logging_rejects_malformed_backend_and_closed_invalid_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _controller, _result = self.login_session(root)
            route = "/api/v1/settings/appliance-logging"
            page = self.appliance_logging_page()
            destination = (
                b'<parameter id="destination" structure="combo"><value>local</value>'
                b'<option>local</option><option>nfs</option><option>syslog</option><option>dsview</option></parameter>'
            )
            timestamp = (
                b'<parameter id="enabletimestamp" structure="combo"><value>yes</value>'
                b'<option>yes</option><option>no</option></parameter>'
            )
            strings_start = page.index(b'<parameter id="alertstring1"')
            strings_end = page.index(b'</parameter>', page.index(b'<parameter id="alertstring10"')) + len(b'</parameter>')
            alert_strings = page[strings_start:strings_end]
            closing = b'</parameter></parameter></parameter></section>'
            malformed_pages = (
                page.replace(b'id="sessiontitle" structure="title"', b'id="wrong" structure="title"'),
                page.replace(b'<parameter id="notice" structure="notice"/>', b''),
                page.replace(b'<option>dsview</option>', b'<option>other</option>'),
                page.replace(b'<parameter id="alertstring1"', b'<parameter id="extra" structure="RWtext"><value>x</value></parameter><parameter id="alertstring1"'),
                self.appliance_logging_page(alert_strings=(b"a" * 65,) + (b"",) * 9),
                page.replace(destination + timestamp, timestamp + destination),
                page.replace(destination, b'').replace(closing, b'</parameter></parameter>' + destination + b'</parameter></section>'),
                page.replace(alert_strings, b'').replace(closing, b'</parameter>' + alert_strings + b'</parameter></parameter></section>'),
                page.replace(destination, b'<parameter id="wrapper" structure="title">' + destination + b'</parameter>'),
            )
            for index, malformed in enumerate(malformed_pages):
                with self.subTest(malformed=index):
                    result, _controller = self.setting_get(root, cookie, route, malformed, f"logging-bad-{index}")
                    headers, payload = self.cgi_json(result)
                    self.assertIn(b"Status: 502", headers)
                    self.assertEqual("backend_protocol_error", payload["code"])

            etag = '"' + "0" * 64 + '"'
            valid_base = {"sessionLoggingEnabled": True, "destination": "local", "timestampEnabled": False, "alertsEnabled": False}
            invalid_bodies = (
                {}, {"sessionLoggingEnabled": "false"},
                {"sessionLoggingEnabled": False, "destination": "local"},
                {"sessionLoggingEnabled": True, "destination": "local", "timestampEnabled": False},
                {**valid_base, "destination": "other"},
                {**valid_base, "alertStrings": [""] * 10},
                {**valid_base, "alertsEnabled": True},
                {**valid_base, "alertsEnabled": True, "alertStrings": [""] * 9},
                {**valid_base, "alertsEnabled": True, "alertStrings": [""] * 11},
                {**valid_base, "alertsEnabled": True, "alertStrings": ["é" * 33] + [""] * 9},
                {**valid_base, "unexpected": 1},
            )
            no_backend = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"), "HTTP_IF_MATCH": etag,
            }
            for candidate in invalid_bodies:
                with self.subTest(candidate=candidate):
                    rejected = self.run_cgi(
                        "PUT", route, cookie=cookie, csrf=str(session["csrfToken"]),
                        body=json.dumps(candidate, ensure_ascii=False).encode(), content_type="application/json",
                        extra_environment=no_backend,
                    )
                    self.assertIn(b"Status: 400", rejected.stdout)
            duplicate = self.run_cgi(
                "PUT", route, cookie=cookie, csrf=str(session["csrfToken"]),
                body=b'{"sessionLoggingEnabled":false,"sessionLoggingEnabled":false}',
                content_type="application/json", extra_environment=no_backend,
            )
            self.assertIn(b"Status: 400", duplicate.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())

    def test_session_password_change_rejects_bearer_csrf_and_confirmation_errors_before_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
            }
            body = b'{"oldPassword":"old","newPassword":"new","confirmation":"different"}'
            mismatch = self.run_cgi(
                "POST", "/api/v1/session/password", cookie=cookie,
                csrf=str(session["csrfToken"]), body=body,
                content_type="application/json", extra_environment=environment,
            )
            missing_csrf = self.run_cgi(
                "POST", "/api/v1/session/password", cookie=cookie,
                body=b'{"oldPassword":"old","newPassword":"new","confirmation":"new"}',
                content_type="application/json", extra_environment=environment,
            )
            bearer = self.run_cgi(
                "POST", "/api/v1/session/password", cookie=cookie,
                authorization="Bearer forbidden", csrf=str(session["csrfToken"]),
                body=b'{"oldPassword":"old","newPassword":"new","confirmation":"new"}',
                content_type="application/json", extra_environment=environment,
            )
            self.assertIn(b"Status: 400", mismatch.stdout)
            self.assertIn(b"Status: 403", missing_csrf.stdout)
            self.assertIn(b"Status: 401", bearer.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())

    def test_action_request_is_validated_before_disabled_response_without_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            outlet_id = "A" * 22
            controller = store.create_token(administrator.plaintext, label="Controller", scope="control", outlets=[outlet_id])
            environment = self.token_environment(root, store_path)
            route = f"/api/v1/outlets/{outlet_id}/actions"
            cases = (
                (b"{}", "application/json", None, b"Status: 400"),
                (b'{"action":"on","action":"off","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}', "application/json", None, b"Status: 400"),
                (b'{"action":"on","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA","extra":1}', "application/json", None, b"Status: 400"),
                (b'{"action":"toggle","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}', "application/json", None, b"Status: 400"),
                (b'{"action":"on","inventoryRevision":"short"}', "application/json", None, b"Status: 400"),
                (b'{"action":"on","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}', "text/plain", None, b"Status: 415"),
                (b" " * 1025, "application/json", None, b"Status: 413"),
                (b'{"action":"on","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}', "application/json", "gzip", b"Status: 415"),
            )
            for request_body, content_type, encoding, status in cases:
                extra = dict(environment)
                if encoding is not None:
                    extra["HTTP_CONTENT_ENCODING"] = encoding
                result = self.run_cgi("POST", route, authorization=f"Bearer {controller.plaintext}", body=request_body,
                                      content_type=content_type, extra_environment=extra)
                self.assertIn(status, result.stdout, request_body[:80])
            self.assertFalse((root / "must-not-open.sock").exists())

    def test_invalid_bearer_is_401_but_insufficient_scope_or_allowlist_is_403(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            allowed, denied = "A" * 22, "B" * 22
            reader = store.create_token(administrator.plaintext, label="Reader", scope="read", outlets=[allowed])
            environment = self.token_environment(root, store_path)
            request_body = b'{"action":"on","inventoryRevision":"AAAAAAAAAAAAAAAAAAAAAA"}'
            invalid_action = self.run_cgi("POST", f"/api/v1/outlets/{allowed}/actions", authorization="Bearer pm3_" + "A" * 43,
                                          body=request_body, content_type="application/json", extra_environment=environment)
            insufficient_action = self.run_cgi("POST", f"/api/v1/outlets/{allowed}/actions", authorization=f"Bearer {reader.plaintext}",
                                               body=request_body, content_type="application/json", extra_environment=environment)
            denied_detail = self.run_cgi("GET", f"/api/v1/outlets/{denied}", authorization=f"Bearer {reader.plaintext}", extra_environment=environment)
            self.assertIn(b"Status: 401", invalid_action.stdout)
            self.assertIn(b"Status: 403", insufficient_action.stdout)
            self.assertIn(b"Status: 403", denied_detail.stdout)

    def test_known_routes_methods_accept_and_backend_protocol_errors_match_contract(self) -> None:
        apache_path_info = self.run_cgi(
            "GET", "/health", extra_environment={"SCRIPT_NAME": "/api/v1"}
        )
        self.assertIn(b"Status: 200", apache_path_info.stdout)
        self.assertIn(b'"status":"live"', apache_path_info.stdout)
        self.assertIn(b"Status: 405", self.run_cgi("POST", "/api/v1/health").stdout)
        unacceptable = self.run_cgi("GET", "/api/v1/health", extra_environment={"HTTP_ACCEPT": "text/plain"})
        headers, body = self.cgi_json(unacceptable)
        self.assertIn(b"Status: 406", headers)
        self.assertEqual("not_acceptable", body["code"])
        for accepted in ("application/json", "application/*", "*/*", "application/json;q=0.5"):
            result = self.run_cgi("GET", "/api/v1/health", extra_environment={"HTTP_ACCEPT": accepted})
            self.assertIn(b"Status: 200", result.stdout, accepted)

        for accepted in (
            "Application/JSON", "APPLICATION/*", "*/*;Q=1.000",
            "text/plain;q=0.9, Application/Json; q=0.001",
            "application/json; charset=utf-8; q=0.5",
        ):
            result = self.run_cgi("GET", "/api/v1/health", extra_environment={"HTTP_ACCEPT": accepted})
            self.assertIn(b"Status: 200", result.stdout, accepted)
        for rejected in (
            "application/json;q=0", "application/*;q=0.000", "*/*;Q=0",
            "application/json;q=0, */*;q=1",
            "application/json;q=0, application/*;q=1, */*;q=1",
            "application/*;q=0, */*;q=1",
            "application/json;q=abc", "application/json;q=", "application/json;q=.5",
            "application/json;q=1.001", "application/json;q=0.0000",
            "application/json;q=0.5junk", "application/json;q=0.5;q=1",
        ):
            result = self.run_cgi("GET", "/api/v1/health", extra_environment={"HTTP_ACCEPT": rejected})
            self.assertIn(b"Status: 406", result.stdout, rejected)
        for accepted in (
            "application/json;q=1, application/*;q=0, */*;q=0",
            "application/*;q=0.5, */*;q=0",
        ):
            result = self.run_cgi("GET", "/api/v1/health", extra_environment={"HTTP_ACCEPT": accepted})
            self.assertIn(b"Status: 200", result.stdout, accepted)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            credentials_path, socket_path = root / "service.credentials", root / "avtrans.sock"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            reader = store.create_token(administrator.plaintext, label="Reader", scope="read")
            credentials_path.write_text("service-user\nservice-password\n")
            credentials_path.chmod(0o600)
            environment = {"PM3000_TOKEN_STORE": str(store_path), "PM3000_CREDENTIALS": str(credentials_path), "PM3000_AVTRANS_SOCKET": str(socket_path)}
            with FakeAvtransController(socket_path, [LOGIN_RESPONSE.read_bytes(), b"<broken>", LOGOUT_RESPONSE.read_bytes()]):
                invalid = self.run_cgi("GET", "/api/v1/outlets", authorization=f"Bearer {reader.plaintext}", extra_environment=environment)
            _headers, error = self.cgi_json(invalid)
            self.assertEqual("backend_protocol_error", error["code"])

    def test_production_binary_excludes_authorize_helper_and_uses_installed_credentials(self) -> None:
        source = (NATIVE / "main.c").read_text(encoding="utf-8")
        self.assertNotIn("/mnt/hdUser/pm3000-revive/rest/service.credentials", source)
        self.assertGreaterEqual(source.count("/etc/pm3000-rest/controller.credentials"), 4)
        subprocess.run(["make", "-C", str(NATIVE), "target"], check=True)
        production = (NATIVE / "build" / "pm3000-rest-ppc32").read_bytes()
        self.assertNotIn(b"--authorize", production)

    def test_controller_socket_does_not_require_post_2623_atomic_cloexec(self) -> None:
        source = (NATIVE / "avtrans.c").read_text(encoding="utf-8")
        self.assertNotIn("SOCK_STREAM | SOCK_CLOEXEC", source)
        self.assertIn("socket(AF_UNIX, SOCK_STREAM, 0)", source)
        self.assertIn("fcntl(descriptor, F_SETFD, FD_CLOEXEC)", source)

    def test_token_store_rejects_symlinks_hardlinks_and_wrong_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            for mutation in ("store_mode", "store_hardlink", "store_symlink", "lock_symlink"):
                lock = path.with_name(path.name + ".lock")
                if mutation == "store_mode":
                    path.chmod(0o644)
                elif mutation == "store_hardlink":
                    os.link(path, root / "store-link")
                elif mutation == "store_symlink":
                    path.rename(root / "real-store")
                    path.symlink_to(root / "real-store")
                else:
                    lock.unlink()
                    lock.symlink_to(path)
                result = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
                self.assertEqual(3, result.returncode, mutation)
                if mutation == "store_mode":
                    path.chmod(0o600)
                elif mutation == "store_hardlink":
                    (root / "store-link").unlink()
                elif mutation == "store_symlink":
                    path.unlink()
                    (root / "real-store").rename(path)
                else:
                    lock.unlink()
                    lock.touch(mode=0o600)

    def test_token_reader_and_writer_reject_lock_directory_and_store_filesystem_attacks(self) -> None:
        for mutation in ("lock_mode", "lock_hardlink", "directory_mode", "directory_symlink", "store_fifo"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path = root / "rest" / "tokens.json"
                store = token_store.TokenStore(path)
                administrator = store.bootstrap("Administrator")
                lock = path.with_name(path.name + ".lock")
                if mutation == "lock_mode":
                    lock.chmod(0o644)
                elif mutation == "lock_hardlink":
                    os.link(lock, root / "lock-link")
                elif mutation == "directory_mode":
                    path.parent.chmod(0o755)
                elif mutation == "directory_symlink":
                    path.parent.rename(root / "real-rest")
                    path.parent.symlink_to(root / "real-rest", target_is_directory=True)
                else:
                    path.unlink()
                    os.mkfifo(path, 0o600)

                reader = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
                writer = self.run_cgi(
                    "POST", "/api/v1/tokens", authorization=f"Bearer {administrator.plaintext}",
                    body=b'{"label":"Rejected writer","scope":"read"}', content_type="application/json",
                    extra_environment=self.token_environment(root, path),
                )
                self.assertEqual(3, reader.returncode, mutation)
                self.assertIn(b"Status: 503", writer.stdout, mutation)
                self.assertNotIn(b"pm3_", writer.stdout, mutation)

    def test_native_store_and_allowlist_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            document = json.loads(path.read_text())
            admin_record = document["tokens"][0]
            outlets = [f"{index:022d}" for index in range(256)]
            records = [admin_record]
            for index in range(1, 21):
                records.append({
                    "createdAt": "2026-01-01T00:00:00Z",
                    "digest": f"{index:064x}",
                    "enabled": True,
                    "id": "tok_" + f"{index:022d}",
                    "label": "😀" * 28 + "abc" if index == 20 else "R",
                    "outlets": outlets[:203] if index == 20 else outlets,
                    "scope": "read",
                })
            document["tokens"] = records
            exact = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
            self.assertEqual(128 * 1024, len(exact))
            path.write_bytes(exact)
            path.chmod(0o600)
            accepted = self.run_adapter("--authorize", str(path), administrator.plaintext, "read")
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            path.write_bytes(exact + b" ")
            path.chmod(0o600)
            self.assertEqual(128 * 1024 + 1, path.stat().st_size)
            self.assertEqual(3, self.run_adapter("--authorize", str(path), administrator.plaintext, "read").returncode)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(path)
            administrator = store.bootstrap("Administrator")
            outlets = [f"{index:022d}" for index in range(256)]
            reader = store.create_token(administrator.plaintext, label="Full allowlist", scope="read", outlets=outlets)
            environment = self.token_environment(root, path)
            changed = self.run_cgi(
                "POST", f"/api/v1/tokens/{reader.record.id}/disable",
                authorization=f"Bearer {administrator.plaintext}", extra_environment=environment,
            )
            self.assertIn(b"Status: 204", changed.stdout)
            persisted = json.loads(path.read_text())
            record = next(item for item in persisted["tokens"] if item["id"] == reader.record.id)
            self.assertEqual(outlets, record["outlets"])
            self.assertFalse(record["enabled"])

    def test_outlet_collection_uses_fixed_read_only_fake_controller_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            credentials_path = root / "service.credentials"
            socket_path = root / "avtrans.sock"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            observed_projection = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)
            allowed_id = observed_projection["outlets"][0]["id"]
            reader = store.create_token(
                administrator.plaintext,
                label="Read inventory",
                scope="read",
                outlets=[allowed_id],
            )
            credentials_path.write_text("service-user\nservice-password\n")
            credentials_path.chmod(0o600)
            responses = [
                LOGIN_RESPONSE.read_bytes(),
                OBSERVED.read_bytes(),
                LOGOUT_RESPONSE.read_bytes(),
            ] * 2
            environment = {
                "PM3000_TOKEN_STORE": str(store_path),
                "PM3000_CREDENTIALS": str(credentials_path),
                "PM3000_AVTRANS_SOCKET": str(socket_path),
                "REMOTE_ADDR": "198.51.100.27",
            }

            with FakeAvtransController(socket_path, responses) as controller:
                result = self.run_cgi(
                    "GET",
                    "/api/v1/outlets",
                    authorization=f"Bearer {reader.plaintext}",
                    extra_environment=environment,
                )
                detail = self.run_cgi(
                    "GET",
                    f"/api/v1/outlets/{allowed_id}",
                    authorization=f"Bearer {reader.plaintext}",
                    extra_environment=environment,
                )

            self.assertEqual(0, result.returncode, result.stderr)
            headers, body = result.stdout.split(b"\r\n\r\n", 1)
            self.assertIn(b"Status: 200", headers)
            projected = json.loads(body)
            self.assertEqual(1, len(projected["outlets"]))
            self.assertEqual(allowed_id, projected["outlets"][0]["id"])
            self.assertEqual(0, detail.returncode, detail.stderr)
            _detail_headers, detail_body = detail.stdout.split(b"\r\n\r\n", 1)
            self.assertEqual(projected["outlets"][0], json.loads(detail_body))
            self.assertEqual(6, len(controller.requests))
            for header, _request in controller.requests:
                self.assertEqual(59, len(header))
                self.assertEqual(b"\0\0\1", header[:3])
                self.assertTrue(header[3:43].startswith(b"198.51.100.27\0"))
                self.assertTrue(header[43:59].startswith(b"en\0"))
            requests = [request.decode("utf-8") for _, request in controller.requests]
            self.assertIn("<action>login</action>", requests[0])
            self.assertIn("<action>get</action>", requests[1])
            self.assertIn("<path>units.topology</path>", requests[1])
            self.assertIn("<action>logout</action>", requests[2])
            self.assertNotIn("targPower", "".join(requests))
            self.assertNotIn(reader.plaintext, "".join(requests))
            self.assertNotIn("service-password", result.stdout.decode("utf-8"))

    def test_health_is_local_https_only_cgi_response(self) -> None:
        result = self.run_cgi("GET", "/api/v1/health")

        self.assertEqual(0, result.returncode, result.stderr)
        headers, body = result.stdout.split(b"\r\n\r\n", 1)
        self.assertIn(b"Status: 200", headers)
        self.assertIn(b"Content-Type: application/json", headers)
        self.assertIn(b"Cache-Control: no-store", headers)
        self.assertIn(b"X-Content-Type-Options: nosniff", headers)
        self.assertEqual({"apiVersion": "v1", "status": "live"}, json.loads(body))
        self.assertEqual(b"", result.stderr)

        cleartext = self.run_cgi("GET", "/api/v1/health", https="off")
        self.assertIn(b"Status: 403", cleartext.stdout)
        self.assertNotIn(b'"status":"live"', cleartext.stdout)

    def project_xml(self, content: bytes) -> subprocess.CompletedProcess[bytes]:
        with tempfile.NamedTemporaryFile() as fixture:
            fixture.write(content)
            fixture.flush()
            return self.run_adapter("--project", fixture.name)

    def test_detail_projection_returns_one_opaque_outlet_or_not_found(self) -> None:
        collection = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)
        outlet = collection["outlets"][0]

        found = self.run_adapter("--detail", str(OBSERVED), outlet["id"])
        missing = self.run_adapter("--detail", str(OBSERVED), "AAAAAAAAAAAAAAAAAAAAAA")

        self.assertEqual(0, found.returncode, found.stderr)
        self.assertEqual(outlet, json.loads(found.stdout))
        self.assertEqual(4, missing.returncode)
        self.assertEqual(b"", missing.stdout)

    def test_outlets_must_be_inside_the_single_topology_table(self) -> None:
        observed = OBSERVED.read_bytes()
        displaced = observed.replace(b'id="topologyTable"', b'id="otherTable"', 1)
        displaced = displaced.replace(
            b"</payload>",
            b'<section id="topologyTable" structure="table" /></payload>',
            1,
        )

        result = self.project_xml(displaced)

        self.assertEqual(3, result.returncode)
        self.assertEqual(b"", result.stdout)

    def test_rejects_ambiguous_or_noncanonical_outlet_positions(self) -> None:
        observed = OBSERVED.read_bytes()
        duplicate_position = observed.replace(
            b'<value label="2">2</value>',
            b'<value label="1">1</value>',
            1,
        )
        leading_zero = observed.replace(
            b'<value label="1">1</value>',
            b'<value label="01">01</value>',
            1,
        )

        duplicate = self.project_xml(duplicate_position)
        noncanonical = self.project_xml(leading_zero)

        self.assertEqual(3, duplicate.returncode)
        self.assertEqual(b"", duplicate.stdout)
        self.assertEqual(3, noncanonical.returncode)
        self.assertEqual(b"", noncanonical.stdout)

    def test_observed_topology_projects_closed_read_only_inventory(self) -> None:
        result = self.run_adapter("--project", str(OBSERVED))

        self.assertEqual(0, result.returncode, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual({"apiVersion", "inventoryRevision", "outlets"}, set(document))
        self.assertEqual("v1", document["apiVersion"])
        self.assertEqual(22, len(document["inventoryRevision"]))
        self.assertEqual(10, len(document["outlets"]))
        self.assertEqual(list(range(1, 11)), [item["position"] for item in document["outlets"]])
        self.assertEqual("on", document["outlets"][0]["state"])
        self.assertTrue(all(item["state"] == "off" for item in document["outlets"][1:]))
        for item in document["outlets"]:
            self.assertEqual(
                {"id", "pduId", "position", "name", "state", "availableActions"},
                set(item),
            )
            self.assertEqual(22, len(item["id"]))
            self.assertEqual(22, len(item["pduId"]))
            self.assertEqual([], item["availableActions"])
        self.assertNotIn(b"pdu.[REDACTED]", result.stdout)
        self.assertNotIn(b"targPower", result.stdout)

    def test_native_xml_one_mib_and_depth_32_boundaries(self) -> None:
        observed = OBSERVED.read_bytes()
        marker = b"</avtrans>"
        exact = observed.replace(marker, b" " * (1024 * 1024 - len(observed)) + marker, 1)
        self.assertEqual(1024 * 1024, len(exact))
        self.assertEqual(0, self.project_xml(exact).returncode)
        self.assertEqual(3, self.project_xml(exact + b" ").returncode)

        script = b'<script id="confirmation" label="Are you sure you want to turn on the outlet(s)?" />'
        accepted_script = script[:-2] + b">" + b"<section>" * 26 + b"</section>" * 26 + b"</script>"
        rejected_script = script[:-2] + b">" + b"<section>" * 27 + b"</section>" * 27 + b"</script>"
        accepted = observed.replace(script, accepted_script, 1)
        rejected = observed.replace(script, rejected_script, 1)
        self.assertEqual(0, self.project_xml(accepted).returncode)
        self.assertEqual(3, self.project_xml(rejected).returncode)

    def test_published_identifier_vectors(self) -> None:
        outlet = self.run_adapter("--derive", "outlet", "SYNTHETIC_OUTLET_1")
        pdu = self.run_adapter("--derive", "pdu", "SYNTHETIC_PDU_1")
        revision = self.run_adapter(
            "--revision", "SYNTHETIC_OUTLET_2", "SYNTHETIC_OUTLET_1"
        )

        self.assertEqual(0, outlet.returncode, outlet.stderr)
        self.assertEqual(b"XDmSGmQaZ6o7iRBWKUnpVg\n", outlet.stdout)
        self.assertEqual(0, pdu.returncode, pdu.stderr)
        self.assertEqual(b"niRcjzKfdPHmzgYMv2BzfB\n", pdu.stdout)
        self.assertEqual(0, revision.returncode, revision.stderr)
        self.assertEqual(b"3Nsqnx4t6hGoJs5d-ahRdd\n", revision.stdout)


    def test_system_information_returns_typed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, session, _login_controller, _result = self.login_session(root)
            socket_path = root / "sysinfo.sock"
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(socket_path),
            }

            with FakeAvtransController(socket_path, [SYSINFO_RESPONSE.read_bytes()]) as controller:
                result = self.run_cgi(
                    "GET", "/api/v1/system/information", cookie=cookie,
                    extra_environment=environment,
                )
            headers, body = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            self.assertEqual(
                {"modelNumber", "bootCodeVersion", "firmwareVersion",
                 "bootedFrom", "cpu", "revision", "bogomips"},
                set(body),
            )
            self.assertEqual("PM3000", body["modelNumber"])
            self.assertEqual("2.0.1.23 (2015-05-11)", body["firmwareVersion"])
            self.assertNotIn("serialNumber", body)
            self.assertNotIn("ports", body)
            self.assertEqual(1, len(controller.requests))
            self.assertIn(b"<action>get</action>", controller.requests[0][1])
            self.assertIn(b"<path>units.applianceSettings.information</path>",
                          controller.requests[0][1])

            unicode_socket = root / "sysinfo-unicode.sock"
            unicode_page = SYSINFO_RESPONSE.read_bytes().replace(
                b"PPC83xx", "PPCé".encode("utf-8"), 1
            )
            with FakeAvtransController(unicode_socket, [unicode_page]):
                unicode_result = self.run_cgi(
                    "GET", "/api/v1/system/information", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(unicode_socket),
                    },
                )
            unicode_headers, unicode_body = self.cgi_json(unicode_result)
            self.assertIn(b"Status: 200", unicode_headers)
            self.assertEqual("PPCé", unicode_body["cpu"])

            bearer_result = self.run_cgi(
                "GET", "/api/v1/system/information", cookie=cookie,
                authorization="Bearer token",
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-open-bearer.sock"),
                },
            )
            self.assertIn(b"Status: 401", bearer_result.stdout)
            self.assertFalse((root / "must-not-open-bearer.sock").exists())

            missing_sock = self.run_cgi(
                "GET", "/api/v1/system/information", cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "missing.sock"),
                },
            )
            self.assertIn(b"Status: 503", missing_sock.stdout)
            _, err503 = self.cgi_json(missing_sock)
            self.assertEqual("backend_unavailable", err503["code"])

            malformed_socket = root / "sysinfo-malformed.sock"
            bad_page = SYSINFO_RESPONSE.read_bytes().replace(
                b'id="identityform"', b'id="wrongform"'
            )
            with FakeAvtransController(malformed_socket, [bad_page]):
                malformed = self.run_cgi(
                    "GET", "/api/v1/system/information", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(malformed_socket),
                    },
                )
            self.assertIn(b"Status: 502", malformed.stdout)
            _, err502 = self.cgi_json(malformed)
            self.assertEqual("backend_protocol_error", err502["code"])

            wrong_path_socket = root / "sysinfo-wrongpath.sock"
            wrong_path_page = SYSINFO_RESPONSE.read_bytes().replace(
                b"<path>units.applianceSettings.information</path>",
                b"<path>units.applianceSettings.usage</path>",
            )
            with FakeAvtransController(wrong_path_socket, [wrong_path_page]):
                wrong_path = self.run_cgi(
                    "GET", "/api/v1/system/information", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(wrong_path_socket),
                    },
                )
            self.assertIn(b"Status: 502", wrong_path.stdout)

            wrong_parent_socket = root / "sysinfo-wrong-parent.sock"
            wrong_parent_page = SYSINFO_RESPONSE.read_bytes().replace(
                b'id="identity" structure="title"',
                b'id="wrongIdentity" structure="title"',
                1,
            )
            with FakeAvtransController(wrong_parent_socket, [wrong_parent_page]):
                wrong_parent = self.run_cgi(
                    "GET", "/api/v1/system/information", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(wrong_parent_socket),
                    },
                )
            self.assertIn(b"Status: 502", wrong_parent.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            no_cap_nav = NAVIGATION_RESPONSE.read_bytes().replace(
                b'path="units.applianceSettings.information"',
                b'path="units.applianceSettings.x-information"',
            )
            cookie, _, _, _ = self.login_session(root, navigation=no_cap_nav)
            cap_denied = self.run_cgi(
                "GET", "/api/v1/system/information", cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
                },
            )
            self.assertIn(b"Status: 403", cap_denied.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())


    def test_memory_usage_returns_typed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _login_controller, _result = self.login_session(root)
            socket_path = root / "memory.sock"
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(socket_path),
            }

            with FakeAvtransController(socket_path, [MEMORY_RESPONSE.read_bytes()]) as controller:
                result = self.run_cgi(
                    "GET", "/api/v1/system/usage/memory", cookie=cookie,
                    extra_environment=environment,
                )
            headers, body = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            self.assertIn("rows", body)
            rows = body["rows"]
            self.assertIsInstance(rows, list)
            self.assertEqual(2, len(rows))
            self.assertEqual({"name", "value"}, set(rows[0]))
            self.assertEqual("MemTotal", rows[0]["name"])
            self.assertEqual("128236 kB", rows[0]["value"])
            self.assertEqual("MemFree", rows[1]["name"])
            self.assertIn(b"<path>units.applianceSettings.usage.memory</path>",
                          controller.requests[0][1])

            bearer_result = self.run_cgi(
                "GET", "/api/v1/system/usage/memory", cookie=cookie,
                authorization="Bearer token",
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
                },
            )
            self.assertIn(b"Status: 401", bearer_result.stdout)
            self.assertFalse((root / "must-not-open.sock").exists())

            missing_sock = self.run_cgi(
                "GET", "/api/v1/system/usage/memory", cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "missing.sock"),
                },
            )
            self.assertIn(b"Status: 503", missing_sock.stdout)

            malformed_socket = root / "memory-malformed.sock"
            bad_page = MEMORY_RESPONSE.read_bytes().replace(
                b'id="memoryTable"', b'id="wrongTable"'
            )
            with FakeAvtransController(malformed_socket, [bad_page]):
                malformed = self.run_cgi(
                    "GET", "/api/v1/system/usage/memory", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(malformed_socket),
                    },
                )
            self.assertIn(b"Status: 502", malformed.stdout)

            duplicate_socket = root / "memory-duplicate.sock"
            table = MEMORY_RESPONSE.read_bytes().split(b"<payload>", 1)[1].split(
                b"</payload>", 1
            )[0]
            duplicate_page = MEMORY_RESPONSE.read_bytes().replace(
                b"</payload>", table + b"</payload>", 1
            )
            with FakeAvtransController(duplicate_socket, [duplicate_page]):
                duplicate = self.run_cgi(
                    "GET", "/api/v1/system/usage/memory", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(duplicate_socket),
                    },
                )
            self.assertIn(b"Status: 502", duplicate.stdout)

            nested_socket = root / "memory-nested.sock"
            field = (
                b'<parameter id="memoryFieldName" structure="ROtext">'
                b'<value>MemTotal</value></parameter>'
            )
            nested_page = MEMORY_RESPONSE.read_bytes().replace(
                field,
                b'<parameter id="unexpected" structure="title">' + field + b'</parameter>',
                1,
            )
            with FakeAvtransController(nested_socket, [nested_page]):
                nested = self.run_cgi(
                    "GET", "/api/v1/system/usage/memory", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(nested_socket),
                    },
                )
            self.assertIn(b"Status: 502", nested.stdout)

            sibling_socket = root / "memory-sibling-row.sock"
            source = MEMORY_RESPONSE.read_bytes()
            row_marker = b'<section id="memoryTableRows" structure="row">'
            row = source.split(row_marker, 1)[1]
            row = row.split(b"</section>", 1)[0]
            sibling_page = source.replace(
                row_marker + row + b"</section>",
                b"",
                1,
            ).replace(
                b"</payload>",
                b'<section id="unrelated" structure="standard">'
                b'<section id="forged" structure="row">' + row +
                b"</section></section></payload>",
                1,
            )
            with FakeAvtransController(sibling_socket, [sibling_page]):
                sibling = self.run_cgi(
                    "GET", "/api/v1/system/usage/memory", cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(sibling_socket),
                    },
                )
            self.assertIn(b"Status: 502", sibling.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            no_cap_nav = NAVIGATION_RESPONSE.read_bytes().replace(
                b'path="units.applianceSettings.usage.memory"',
                b'path="units.applianceSettings.usage.x-memory"',
            )
            cookie, _, _, _ = self.login_session(root, navigation=no_cap_nav)
            cap_denied = self.run_cgi(
                "GET", "/api/v1/system/usage/memory", cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
                },
            )
            self.assertIn(b"Status: 403", cap_denied.stdout)


    def _route_session_table_test(
        self,
        route: str,
        fixture: "Path",
        nav_path: str,
        bad_table_attr: bytes,
        good_table_attr: bytes,
        check_body: "Callable[[dict], None]",
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cookie, _session, _lc, _r = self.login_session(root)
            socket_path = root / "table.sock"
            environment = {
                "PM3000_SESSION_DIR": str(root / "sessions"),
                "PM3000_AVTRANS_SOCKET": str(socket_path),
            }

            with FakeAvtransController(socket_path, [fixture.read_bytes()]) as ctrl:
                result = self.run_cgi("GET", route, cookie=cookie, extra_environment=environment)
            headers, body = self.cgi_json(result)
            self.assertIn(b"Status: 200", headers)
            check_body(body)
            self.assertEqual(1, len(ctrl.requests))

            bearer = self.run_cgi(
                "GET", route, cookie=cookie, authorization="Bearer t",
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "no-bearer.sock"),
                },
            )
            self.assertIn(b"Status: 401", bearer.stdout)
            self.assertFalse((root / "no-bearer.sock").exists())

            missing = self.run_cgi(
                "GET", route, cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "missing.sock"),
                },
            )
            self.assertIn(b"Status: 503", missing.stdout)
            _, err503 = self.cgi_json(missing)
            self.assertEqual("backend_unavailable", err503["code"])

            malformed_sock = root / "bad.sock"
            bad_page = fixture.read_bytes().replace(good_table_attr, bad_table_attr)
            with FakeAvtransController(malformed_sock, [bad_page]):
                malformed = self.run_cgi(
                    "GET", route, cookie=cookie,
                    extra_environment={
                        "PM3000_SESSION_DIR": str(root / "sessions"),
                        "PM3000_AVTRANS_SOCKET": str(malformed_sock),
                    },
                )
            self.assertIn(b"Status: 502", malformed.stdout)
            _, err502 = self.cgi_json(malformed)
            self.assertEqual("backend_protocol_error", err502["code"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            no_cap_nav = NAVIGATION_RESPONSE.read_bytes().replace(
                nav_path.encode(), nav_path.encode() + b"-removed"
            )
            cookie, _, _, _ = self.login_session(root, navigation=no_cap_nav)
            cap_denied = self.run_cgi(
                "GET", route, cookie=cookie,
                extra_environment={
                    "PM3000_SESSION_DIR": str(root / "sessions"),
                    "PM3000_AVTRANS_SOCKET": str(root / "no-cap.sock"),
                },
            )
            self.assertIn(b"Status: 403", cap_denied.stdout)
            self.assertFalse((root / "no-cap.sock").exists())

    def test_flash_usage_returns_typed_rows(self) -> None:
        def check(body: dict) -> None:
            self.assertIn("rows", body)
            rows = body["rows"]
            self.assertEqual(2, len(rows))
            self.assertEqual(
                {"filesystem", "blocks1k", "used", "available",
                 "usePercentage", "mountedOn"},
                set(rows[0]),
            )
            self.assertEqual("rootfs", rows[0]["filesystem"])
            self.assertEqual("60%", rows[0]["usePercentage"])
            self.assertEqual("/mnt/hdUser", rows[1]["mountedOn"])

        self._route_session_table_test(
            "/api/v1/system/usage/flash",
            FLASH_RESPONSE,
            "units.applianceSettings.usage.flashUsage",
            b'id="wrongTable"',
            b'id="flashUsageTable"',
            check,
        )

    def test_network_devices_returns_typed_rows(self) -> None:
        def check(body: dict) -> None:
            self.assertIn("devices", body)
            devices = body["devices"]
            self.assertEqual(2, len(devices))
            self.assertEqual(
                {"name", "status", "ipv4Address", "ipv4Mask", "ipv6Address"},
                set(devices[0]),
            )
            self.assertEqual("eth0", devices[0]["name"])
            self.assertEqual("192.0.2.100", devices[0]["ipv4Address"])
            self.assertEqual("lo", devices[1]["name"])

        self._route_session_table_test(
            "/api/v1/monitoring/network/devices",
            NETDEV_RESPONSE,
            "units.monitoring.networkmon.monitoringDevice",
            b'id="wrongTable"',
            b'id="devicesTable"',
            check,
        )

    def test_ipv4_routes_returns_typed_rows(self) -> None:
        def check(body: dict) -> None:
            self.assertIn("routes", body)
            routes = body["routes"]
            self.assertEqual(2, len(routes))
            self.assertEqual(
                {"destination", "gateway", "genmask", "flags",
                 "metric", "ref", "use", "iface"},
                set(routes[0]),
            )
            self.assertEqual("0.0.0.0", routes[0]["destination"])
            self.assertEqual("192.0.2.1", routes[0]["gateway"])
            self.assertEqual("UG", routes[0]["flags"])
            self.assertEqual("eth0", routes[1]["iface"])

        self._route_session_table_test(
            "/api/v1/monitoring/network/routes/ipv4",
            IPV4_ROUTES_RESPONSE,
            "units.monitoring.networkmon.monitoringIpv4RouteTable",
            b'id="wrongTable"',
            b'id="ipv4RouteTable"',
            check,
        )

    def test_ipv6_routes_returns_typed_rows(self) -> None:
        def check(body: dict) -> None:
            self.assertIn("routes", body)
            routes = body["routes"]
            self.assertEqual(2, len(routes))
            self.assertEqual(
                {"destination", "nextHop", "flags", "metric",
                 "ref", "use", "iface"},
                set(routes[0]),
            )
            self.assertEqual("::1/128", routes[0]["destination"])
            self.assertEqual("::", routes[0]["nextHop"])
            self.assertEqual("eth0", routes[1]["iface"])

        self._route_session_table_test(
            "/api/v1/monitoring/network/routes/ipv6",
            IPV6_ROUTES_RESPONSE,
            "units.monitoring.networkmon.monitoringIpv6RouteTable",
            b'id="wrongTable"',
            b'id="ipv6RouteTable"',
            check,
        )

    def test_serial_ports_returns_typed_rows(self) -> None:
        def check(body: dict) -> None:
            self.assertIn("ports", body)
            ports = body["ports"]
            self.assertEqual(2, len(ports))
            self.assertEqual(
                {"deviceName", "portProfile", "speed", "signals",
                 "txBytes", "rxBytes", "frameError", "parityError",
                 "brk", "overrun"},
                set(ports[0]),
            )
            self.assertEqual("/dev/ttyS0", ports[0]["deviceName"])
            self.assertEqual("Console", ports[0]["portProfile"])
            self.assertEqual("1024", ports[0]["txBytes"])
            self.assertEqual("0", ports[0]["brk"])
            self.assertEqual("/dev/ttyS1", ports[1]["deviceName"])

        self._route_session_table_test(
            "/api/v1/monitoring/serial-ports",
            SERIAL_RESPONSE,
            "units.monitoring.serialstatistics",
            b'id="wrongTable"',
            b'id="serialstatistictable"',
            check,
        )


if __name__ == "__main__":
    unittest.main()
