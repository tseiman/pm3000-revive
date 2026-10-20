#!/usr/bin/env python3
"""Host-side tests for the Stage 4 native read-only adapter."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
BINARY = NATIVE / "build" / "pm3000-rest-host"
OBSERVED = ROOT / "fixtures" / "observed" / "topology-get-response.xml"
LOGIN_RESPONSE = ROOT / "fixtures" / "observed" / "login-submit-response.xml"
LOGOUT_RESPONSE = ROOT / "fixtures" / "observed" / "logout-response.xml"
sys.path.insert(0, str(ROOT / "tools"))
import token_store  # noqa: E402


class FakeAvtransController:
    def __init__(self, path: Path, responses: list[bytes]) -> None:
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
        body: bytes | None = None,
        content_type: str | None = None,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment.update({"REQUEST_METHOD": method, "PATH_INFO": path, "HTTPS": https})
        if authorization is not None:
            environment["HTTP_AUTHORIZATION"] = authorization
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

    def test_outlet_actions_remain_disabled_without_backend_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store_path = root / "rest" / "tokens.json"
            store = token_store.TokenStore(store_path)
            administrator = store.bootstrap("Administrator")
            outlet_id = json.loads(self.run_adapter("--project", str(OBSERVED)).stdout)["outlets"][0]["id"]
            controller = store.create_token(
                administrator.plaintext,
                label="Controller",
                scope="control",
                outlets=[outlet_id],
            )
            result = self.run_cgi(
                "POST",
                f"/api/v1/outlets/{outlet_id}/actions",
                authorization=f"Bearer {controller.plaintext}",
                body=json.dumps({"action": "on", "inventoryRevision": "A" * 22}).encode(),
                content_type="application/json",
                extra_environment={
                    "PM3000_TOKEN_STORE": str(store_path),
                    "PM3000_CREDENTIALS": str(root / "must-not-open.credentials"),
                    "PM3000_AVTRANS_SOCKET": str(root / "must-not-open.sock"),
                },
            )

            self.assertEqual(0, result.returncode, result.stderr)
            _headers, body = result.stdout.split(b"\r\n\r\n", 1)
            self.assertEqual("action_disabled", json.loads(body)["code"])
            self.assertIn(b"Status: 503", result.stdout)

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

    def test_production_binary_excludes_authorize_helper(self) -> None:
        subprocess.run(["make", "-C", str(NATIVE), "target"], check=True)
        production = (NATIVE / "build" / "pm3000-rest-ppc32").read_bytes()
        self.assertNotIn(b"--authorize", production)

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
                self.assertTrue(header[3:43].startswith(b"127.0.0.1\0"))
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


if __name__ == "__main__":
    unittest.main()
