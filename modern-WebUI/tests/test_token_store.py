#!/usr/bin/env python3
"""Tests for the host-side Stage 3 bearer-token store."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import token_store  # noqa: E402


class DeterministicRandom:
    def __init__(self, values: list[bytes]) -> None:
        self.values = iter(values)

    def __call__(self, length: int) -> bytes:
        value = next(self.values)
        if len(value) != length:
            raise AssertionError(f"expected {length} random bytes, fixture has {len(value)}")
        return value


class TokenStoreTests(unittest.TestCase):
    def test_bootstrap_stores_only_digest_in_mode_0600_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            store_path = directory / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"T" * 32, b"I" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )

            issued = store.bootstrap("Initial administrator")

            document = json.loads(store_path.read_text())
            self.assertTrue(issued.plaintext.startswith("pm3_"))
            self.assertEqual(47, len(issued.plaintext))
            self.assertEqual("admin", issued.record.scope)
            self.assertEqual(1, document["schemaVersion"])
            self.assertEqual(1, document["generation"])
            self.assertEqual(1, len(document["tokens"]))
            self.assertNotIn(issued.plaintext, store_path.read_text())
            self.assertEqual(
                hashlib.sha256(issued.plaintext.encode("ascii")).hexdigest(),
                document["tokens"][0]["digest"],
            )
            self.assertEqual(0o600, stat.S_IMODE(store_path.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode))

    def test_authenticate_returns_record_for_matching_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom([b"T" * 32, b"I" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            issued = store.bootstrap("Initial administrator")

            authenticated = store.authenticate(issued.plaintext)

            self.assertIsNotNone(authenticated)
            self.assertEqual(issued.record.id, authenticated.id)
            self.assertEqual("admin", authenticated.scope)

    def test_admin_creates_scoped_token_with_outlet_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            outlet_id = "A" * 22

            issued = store.create_token(
                administrator.plaintext,
                label="Automation client",
                scope="control",
                outlets=[outlet_id],
            )

            document = json.loads(store_path.read_text())
            self.assertEqual("control", issued.record.scope)
            self.assertEqual([outlet_id], issued.record.outlets)
            self.assertEqual(2, document["generation"])
            self.assertEqual(2, len(document["tokens"]))
            self.assertNotIn(issued.plaintext, store_path.read_text())

    def test_authorize_enforces_scope_and_outlet_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            allowed_outlet = "A" * 22
            denied_outlet = "B" * 22
            control = store.create_token(
                administrator.plaintext,
                label="Restricted controller",
                scope="control",
                outlets=[allowed_outlet],
            )

            self.assertIsNotNone(store.authorize_outlet(control.plaintext, "read", allowed_outlet))
            self.assertIsNotNone(store.authorize_outlet(control.plaintext, "control", allowed_outlet))
            self.assertIsNone(store.authorize_outlet(control.plaintext, "admin", allowed_outlet))
            self.assertIsNone(store.authorize_outlet(control.plaintext, "read", denied_outlet))

    def test_admin_disables_token_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            reader = store.create_token(
                administrator.plaintext,
                label="Read client",
                scope="read",
            )

            store.set_enabled(administrator.plaintext, reader.record.id, False)

            self.assertIsNone(store.authorize_global(reader.plaintext, "read"))
            document = json.loads(store_path.read_text())
            disabled = next(value for value in document["tokens"] if value["id"] == reader.record.id)
            self.assertFalse(disabled["enabled"])
            self.assertEqual(3, document["generation"])

    def test_admin_revokes_token_by_removing_digest_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            reader = store.create_token(
                administrator.plaintext,
                label="Disposable reader",
                scope="read",
            )

            store.revoke(administrator.plaintext, reader.record.id)

            self.assertIsNone(store.authenticate(reader.plaintext))
            document = json.loads(store_path.read_text())
            self.assertEqual([administrator.record.id], [value["id"] for value in document["tokens"]])
            self.assertEqual(3, document["generation"])

    def test_cannot_revoke_last_enabled_administrator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            original = store_path.read_bytes()

            with self.assertRaises(token_store.LastAdministratorError):
                store.revoke(administrator.plaintext, administrator.record.id)

            self.assertEqual(original, store_path.read_bytes())
            self.assertIsNotNone(store.authorize_global(administrator.plaintext, "admin"))

    def test_cannot_disable_last_enabled_administrator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            original = store_path.read_bytes()

            with self.assertRaises(token_store.LastAdministratorError):
                store.set_enabled(administrator.plaintext, administrator.record.id, False)

            self.assertEqual(original, store_path.read_bytes())

    def test_disabled_administrator_cannot_create_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom(
                    [
                        b"A" * 32,
                        b"B" * 16,
                        b"C" * 32,
                        b"D" * 16,
                        b"E" * 32,
                        b"F" * 16,
                    ]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            primary = store.bootstrap("Primary administrator")
            secondary = store.create_token(
                primary.plaintext,
                label="Secondary administrator",
                scope="admin",
            )
            store.set_enabled(primary.plaintext, secondary.record.id, False)

            with self.assertRaises(token_store.AuthorizationError):
                store.create_token(
                    secondary.plaintext,
                    label="Must not be created",
                    scope="read",
                )

    def test_duplicate_json_key_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            original = b'{"schemaVersion":1,"generation":1,"generation":2,"tokens":[]}\n'
            store_path.write_bytes(original)
            store_path.chmod(0o600)
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
            )

            with self.assertRaises(token_store.TokenStoreError):
                store.bootstrap("Must not replace existing data")

            self.assertEqual(original, store_path.read_bytes())

    def test_unknown_top_level_member_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            original = (
                b'{"schemaVersion":1,"generation":1,"tokens":[],"unexpected":true}\n'
            )
            store_path.write_bytes(original)
            store_path.chmod(0o600)
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
            )

            with self.assertRaises(token_store.TokenStoreError):
                store.bootstrap("Must not replace existing data")

            self.assertEqual(original, store_path.read_bytes())

    def test_unknown_token_member_is_rejected_as_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            document = {
                "schemaVersion": 1,
                "generation": 1,
                "tokens": [
                    {
                        "id": "tok_" + "A" * 22,
                        "label": "Administrator",
                        "createdAt": "2026-10-20T12:00:00Z",
                        "digest": "0" * 64,
                        "enabled": True,
                        "scope": "admin",
                        "outlets": None,
                        "unexpected": True,
                    }
                ],
            }
            store_path.write_text(json.dumps(document) + "\n")
            store_path.chmod(0o600)
            original = store_path.read_bytes()
            store = token_store.TokenStore(store_path)

            with self.assertRaises(token_store.TokenStoreError):
                store.authenticate("not-the-token")

            self.assertEqual(original, store_path.read_bytes())

    def test_noncanonical_token_documents_are_rejected(self) -> None:
        base = {
            "schemaVersion": 1,
            "generation": 1,
            "tokens": [
                {
                    "id": "tok_" + "A" * 22,
                    "label": "Administrator",
                    "createdAt": "2026-10-20T12:00:00Z",
                    "digest": "0" * 64,
                    "enabled": True,
                    "scope": "admin",
                    "outlets": None,
                }
            ],
        }
        cases = {
            "generation-type": ("generation", True),
            "generation-zero": ("generation", 0),
            "id": ("id", "tok_short"),
            "label": ("label", " bad"),
            "created-at": ("createdAt", "2026-10-20 12:00:00"),
            "digest": ("digest", "ABC"),
            "enabled": ("enabled", 1),
            "scope": ("scope", "root"),
            "outlets-type": ("outlets", "A" * 22),
            "outlets-order": ("outlets", ["B" * 22, "A" * 22]),
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            store = token_store.TokenStore(store_path)
            for name, (field, value) in cases.items():
                with self.subTest(case=name):
                    document = json.loads(json.dumps(base))
                    if field == "generation":
                        document[field] = value
                    else:
                        document["tokens"][0][field] = value
                    store_path.write_text(json.dumps(document) + "\n")
                    store_path.chmod(0o600)
                    with self.assertRaises(token_store.TokenStoreError):
                        store.authenticate("not-the-token")

    def test_document_wide_identity_invariants_are_enforced(self) -> None:
        administrator = {
            "id": "tok_" + "A" * 22,
            "label": "Administrator",
            "createdAt": "2026-10-20T12:00:00Z",
            "digest": "0" * 64,
            "enabled": True,
            "scope": "admin",
            "outlets": None,
        }
        duplicate_id = dict(administrator, digest="1" * 64, label="Duplicate ID")
        duplicate_digest = dict(
            administrator,
            id="tok_" + "B" * 22,
            label="Duplicate digest",
        )
        cases = {
            "duplicate-id": [administrator, duplicate_id],
            "duplicate-digest": [administrator, duplicate_digest],
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            store = token_store.TokenStore(store_path)
            for name, records in cases.items():
                with self.subTest(case=name):
                    store_path.write_text(
                        json.dumps(
                            {
                                "schemaVersion": 1,
                                "generation": 1,
                                "tokens": records,
                            }
                        )
                        + "\n"
                    )
                    store_path.chmod(0o600)
                    with self.assertRaises(token_store.TokenStoreError):
                        store.authenticate("not-the-token")

    def test_store_accepts_no_enabled_administrator_and_no_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            store = token_store.TokenStore(store_path)
            disabled_administrator = {
                "id": "tok_" + "A" * 22,
                "label": "Disabled administrator",
                "createdAt": "2026-10-20T12:00:00Z",
                "digest": "0" * 64,
                "enabled": False,
                "scope": "admin",
                "outlets": None,
            }
            for records in ([disabled_administrator], []):
                store_path.write_text(json.dumps({
                    "schemaVersion": 1, "generation": 1, "tokens": records,
                }) + "\n")
                store_path.chmod(0o600)
                self.assertIsNone(store.authenticate("not-the-token"))

    def test_bootstrap_rejects_broken_store_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            store_path.symlink_to(directory / "missing-target")
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
            )

            with self.assertRaises(token_store.TokenStoreError):
                store.bootstrap("Must not replace a symlink")

            self.assertTrue(store_path.is_symlink())
            self.assertFalse((directory / "missing-target").exists())

    def test_failure_before_replace_preserves_previous_store_and_cleans_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            store_path = directory / "tokens.json"
            armed = False

            def fault(point: str) -> None:
                if armed and point == "before_replace":
                    raise OSError("injected publication failure")

            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
                fault_hook=fault,
            )
            administrator = store.bootstrap("Initial administrator")
            original = store_path.read_bytes()
            armed = True

            with self.assertRaises(OSError):
                store.create_token(
                    administrator.plaintext,
                    label="Must not commit",
                    scope="read",
                )

            self.assertEqual(original, store_path.read_bytes())
            self.assertEqual([], list(directory.glob(".tokens.*")))

    def test_failure_after_replace_reports_committed_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            armed = False

            def fault(point: str) -> None:
                if armed and point == "after_replace":
                    raise OSError("injected directory durability failure")

            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
                fault_hook=fault,
            )
            administrator = store.bootstrap("Initial administrator")
            armed = True

            with self.assertRaises(token_store.IssuedTokenDurabilityError) as raised:
                store.create_token(
                    administrator.plaintext,
                    label="Committed reader",
                    scope="read",
                )

            self.assertEqual("Committed reader", raised.exception.issued.record.label)
            self.assertTrue(raised.exception.issued.plaintext.startswith("pm3_"))
            self.assertNotIn(raised.exception.issued.plaintext, store_path.read_text())
            document = json.loads(store_path.read_text())
            self.assertEqual(2, document["generation"])
            self.assertEqual(2, len(document["tokens"]))

    def test_bootstrap_post_replace_failure_still_returns_only_administrator_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"

            def fault(point: str) -> None:
                if point == "after_replace":
                    raise OSError("injected directory durability failure")

            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
                fault_hook=fault,
            )

            with self.assertRaises(token_store.IssuedTokenDurabilityError) as raised:
                store.bootstrap("Initial administrator")

            issued = raised.exception.issued
            self.assertTrue(issued.plaintext.startswith("pm3_"))
            self.assertIsNotNone(store.authorize_global(issued.plaintext, "admin"))
            self.assertNotIn(issued.plaintext, store_path.read_text())

    def test_admin_listing_omits_token_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            store.create_token(
                administrator.plaintext,
                label="Read client",
                scope="read",
            )

            records = store.list_tokens(administrator.plaintext)

            self.assertEqual(2, len(records))
            self.assertEqual("Initial administrator", records[0].label)
            self.assertFalse(hasattr(records[0], "digest"))
            self.assertFalse(hasattr(records[0], "plaintext"))

    def test_random_identifier_collision_never_replaces_valid_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"B" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            original = store_path.read_bytes()

            with self.assertRaises(token_store.TokenStoreError):
                store.create_token(
                    administrator.plaintext,
                    label="Colliding identifier",
                    scope="read",
                )

            self.assertEqual(original, store_path.read_bytes())
            self.assertIsNotNone(store.authorize_global(administrator.plaintext, "admin"))

    def test_authorize_rejects_malformed_outlet_even_when_unrestricted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")

            self.assertIsNone(
                store.authorize_outlet(administrator.plaintext, "read", "not-an-opaque-id")
            )

    def test_lock_symlink_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            target = Path(temporary) / "unrelated"
            target.write_text("unchanged")
            (directory / "tokens.json.lock").symlink_to(target)
            store = token_store.TokenStore(
                directory / "tokens.json",
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
            )

            with self.assertRaises((token_store.TokenStoreError, OSError)):
                store.bootstrap("Initial administrator")

            self.assertEqual("unchanged", target.read_text())
            self.assertFalse((directory / "tokens.json").exists())

    def test_deep_json_and_unpaired_surrogate_are_closed_store_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "rest"
            directory.mkdir(mode=0o700)
            store_path = directory / "tokens.json"
            store = token_store.TokenStore(store_path)

            store_path.write_bytes(b"[" * 2000 + b"]" * 2000)
            store_path.chmod(0o600)
            with self.assertRaises(token_store.TokenStoreError):
                store.authenticate("pm3_" + "A" * 43)

            payload = (
                b'{"schemaVersion":1,"generation":1,"tokens":[{'
                b'"id":"tok_AAAAAAAAAAAAAAAAAAAAAA",'
                b'"label":"\\ud800",'
                b'"createdAt":"2026-10-20T12:00:00Z",'
                b'"digest":"' + b"0" * 64 + b'",'
                b'"enabled":true,"scope":"admin","outlets":null}]}'
            )
            store_path.write_bytes(payload)
            store_path.chmod(0o600)
            with self.assertRaises(token_store.TokenStoreError):
                store.authenticate("pm3_" + "A" * 43)

    def test_delivery_failure_never_publishes_unknown_credential(self) -> None:
        def fail_delivery(issued: token_store.IssuedToken) -> None:
            raise OSError("simulated output failure")

        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [
                        b"A" * 32,
                        b"B" * 16,
                        b"C" * 32,
                        b"D" * 16,
                        b"E" * 32,
                        b"F" * 16,
                    ]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            with self.assertRaises(OSError):
                store.bootstrap("Undelivered administrator", deliver=fail_delivery)
            self.assertFalse(store_path.exists())

            administrator = store.bootstrap("Initial administrator")
            original = store_path.read_bytes()
            with self.assertRaises(OSError):
                store.create_token(
                    administrator.plaintext,
                    label="Undelivered reader",
                    scope="read",
                    deliver=fail_delivery,
                )
            self.assertEqual(original, store_path.read_bytes())

    def test_unlock_failure_closes_descriptors_and_next_transaction_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = token_store.TokenStore(
                Path(temporary) / "rest" / "tokens.json",
                random_bytes=DeterministicRandom([b"A" * 32, b"B" * 16]),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            administrator = store.bootstrap("Initial administrator")
            baseline = len(os.listdir("/proc/self/fd"))
            original_flock = token_store.fcntl.flock
            failed = False

            def interrupted_unlock(descriptor: int, operation: int) -> None:
                nonlocal failed
                if operation == fcntl.LOCK_UN and not failed:
                    failed = True
                    raise InterruptedError("simulated unlock interruption")
                original_flock(descriptor, operation)

            with mock.patch.object(
                token_store.fcntl,
                "flock",
                side_effect=interrupted_unlock,
            ):
                with self.assertRaises(InterruptedError):
                    store.authenticate(administrator.plaintext)

            self.assertEqual(baseline, len(os.listdir("/proc/self/fd")))
            self.assertIsNotNone(store.authenticate(administrator.plaintext))

    def test_surrogate_label_and_generation_overflow_fail_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "rest" / "tokens.json"
            store = token_store.TokenStore(
                store_path,
                random_bytes=DeterministicRandom(
                    [b"A" * 32, b"B" * 16, b"C" * 32, b"D" * 16]
                ),
                clock=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            )
            with self.assertRaises(token_store.TokenStoreError):
                store.bootstrap("\ud800")
            self.assertFalse(store_path.exists())

            administrator = store.bootstrap("Initial administrator")
            document = json.loads(store_path.read_text())
            document["generation"] = token_store.MAX_GENERATION
            store_path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
            store_path.chmod(0o600)
            original = store_path.read_bytes()

            with self.assertRaises(token_store.TokenStoreError):
                store.create_token(
                    administrator.plaintext,
                    label="Overflow must not commit",
                    scope="read",
                )

            self.assertEqual(original, store_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
