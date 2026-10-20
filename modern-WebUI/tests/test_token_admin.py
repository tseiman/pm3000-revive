#!/usr/bin/env python3
"""Subprocess tests for the Stage 3 host-side token administration command."""

from __future__ import annotations

import json
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "tools" / "token_admin.py"
sys.path.insert(0, str(ROOT / "tools"))

import token_admin  # noqa: E402
import token_store  # noqa: E402


class TokenAdminCommandTests(unittest.TestCase):
    def test_bootstrap_prints_plaintext_once_and_refuses_rebootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            command = [
                sys.executable,
                str(COMMAND),
                "bootstrap",
                "--store",
                str(store_path),
                "--label",
                "Initial administrator",
            ]

            first = subprocess.run(command, text=True, capture_output=True, check=False)

            self.assertEqual(0, first.returncode, first.stderr)
            response = json.loads(first.stdout)
            self.assertEqual("admin", response["scope"])
            self.assertTrue(response["token"].startswith("pm3_"))
            self.assertNotIn(response["token"], first.stderr)
            self.assertNotIn(response["token"], store_path.read_text())

            second = subprocess.run(command, text=True, capture_output=True, check=False)

            self.assertNotEqual(0, second.returncode)
            self.assertEqual("", second.stdout)
            self.assertNotIn(response["token"], second.stderr)

    def test_create_and_list_read_admin_token_from_stdin_without_exposing_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            bootstrap = subprocess.run(
                [
                    sys.executable,
                    str(COMMAND),
                    "bootstrap",
                    "--store",
                    str(store_path),
                    "--label",
                    "Initial administrator",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            administrator = json.loads(bootstrap.stdout)["token"]
            outlet_id = "A" * 22

            created = subprocess.run(
                [
                    sys.executable,
                    str(COMMAND),
                    "create",
                    "--store",
                    str(store_path),
                    "--label",
                    "Automation client",
                    "--scope",
                    "control",
                    "--outlet",
                    outlet_id,
                ],
                input=administrator + "\n",
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(0, created.returncode, created.stderr)
            issued = json.loads(created.stdout)
            self.assertTrue(issued["token"].startswith("pm3_"))
            self.assertNotIn(administrator, created.stderr)

            listed = subprocess.run(
                [
                    sys.executable,
                    str(COMMAND),
                    "list",
                    "--store",
                    str(store_path),
                ],
                input=administrator + "\n",
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(0, listed.returncode, listed.stderr)
            records = json.loads(listed.stdout)["tokens"]
            self.assertEqual(2, len(records))
            self.assertNotIn("digest", listed.stdout)
            self.assertNotIn(administrator, listed.stdout + listed.stderr)
            self.assertNotIn(issued["token"], listed.stdout + listed.stderr)

    def test_disable_enable_and_revoke_commands_update_by_opaque_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"

            def run(arguments: list[str], administrator: str | None = None):
                return subprocess.run(
                    [sys.executable, str(COMMAND), *arguments],
                    input=None if administrator is None else administrator + "\n",
                    text=True,
                    capture_output=True,
                    check=False,
                )

            bootstrapped = run(
                [
                    "bootstrap",
                    "--store",
                    str(store_path),
                    "--label",
                    "Initial administrator",
                ]
            )
            administrator = json.loads(bootstrapped.stdout)["token"]
            created = run(
                [
                    "create",
                    "--store",
                    str(store_path),
                    "--label",
                    "Disposable reader",
                    "--scope",
                    "read",
                ],
                administrator,
            )
            token_id = json.loads(created.stdout)["id"]

            disabled = run(
                ["disable", "--store", str(store_path), "--id", token_id],
                administrator,
            )
            self.assertEqual(0, disabled.returncode, disabled.stderr)
            enabled = run(
                ["enable", "--store", str(store_path), "--id", token_id],
                administrator,
            )
            self.assertEqual(0, enabled.returncode, enabled.stderr)
            revoked = run(
                ["revoke", "--store", str(store_path), "--id", token_id],
                administrator,
            )
            self.assertEqual(0, revoked.returncode, revoked.stderr)

            listed = run(["list", "--store", str(store_path)], administrator)
            records = json.loads(listed.stdout)["tokens"]
            self.assertEqual(1, len(records))
            self.assertNotIn(token_id, listed.stdout)
            self.assertNotIn(administrator, disabled.stderr + enabled.stderr + revoked.stderr)

    def test_output_failure_does_not_publish_bootstrap_or_created_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            with open("/dev/full", "w", encoding="utf-8") as full:
                failed_bootstrap = subprocess.run(
                    [
                        sys.executable,
                        str(COMMAND),
                        "bootstrap",
                        "--store",
                        str(store_path),
                        "--label",
                        "Initial administrator",
                    ],
                    text=True,
                    stdout=full,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            self.assertNotEqual(0, failed_bootstrap.returncode)
            self.assertFalse(store_path.exists())

            bootstrapped = subprocess.run(
                [
                    sys.executable,
                    str(COMMAND),
                    "bootstrap",
                    "--store",
                    str(store_path),
                    "--label",
                    "Initial administrator",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, bootstrapped.returncode, bootstrapped.stderr)
            administrator = json.loads(bootstrapped.stdout)["token"]
            original = store_path.read_bytes()
            with open("/dev/full", "w", encoding="utf-8") as full:
                failed_create = subprocess.run(
                    [
                        sys.executable,
                        str(COMMAND),
                        "create",
                        "--store",
                        str(store_path),
                        "--label",
                        "Undelivered reader",
                        "--scope",
                        "read",
                    ],
                    input=administrator + "\n",
                    text=True,
                    stdout=full,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            self.assertNotEqual(0, failed_create.returncode)
            self.assertEqual(original, store_path.read_bytes())
            self.assertNotIn(administrator, failed_create.stderr)

    def test_committed_durability_warning_still_emits_issued_token_once(self) -> None:
        plaintext = "pm3_" + "A" * 43
        issued = token_store.IssuedToken(
            plaintext=plaintext,
            record=token_store.TokenRecord(
                id="tok_" + "B" * 22,
                label="Initial administrator",
                createdAt="2026-10-20T12:00:00Z",
                digest="0" * 64,
                enabled=True,
                scope="admin",
                outlets=None,
            ),
        )

        class FailingStore:
            def bootstrap(self, label: str, *, deliver=None):
                self.assert_delivery(deliver)
                raise token_store.IssuedTokenDurabilityError(
                    issued,
                    delivered=True,
                )

            @staticmethod
            def assert_delivery(deliver):
                if deliver is None:
                    raise AssertionError("delivery callback missing")
                deliver(issued)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(token_admin, "TokenStore", return_value=FailingStore()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = token_admin.main(
                    [
                        "bootstrap",
                        "--store",
                        "/absolute/staging/tokens.json",
                        "--label",
                        "Initial administrator",
                    ]
                )

        self.assertEqual(3, result)
        response = json.loads(stdout.getvalue())
        self.assertNotIn("durability", response)
        self.assertEqual(plaintext, response["token"])
        self.assertEqual(1, stdout.getvalue().count(plaintext))
        self.assertNotIn(plaintext, stderr.getvalue())
        self.assertIn("inspect the store before retrying", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
