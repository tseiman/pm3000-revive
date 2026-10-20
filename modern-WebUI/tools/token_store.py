#!/usr/bin/env python3
"""Host-side Stage 3 bearer-token store and provisioning primitives."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


SCHEMA_VERSION = 1
TOKEN_PREFIX = "pm3_"
MAX_STORE_BYTES = 128 * 1024
MAX_GENERATION = (1 << 63) - 1


class TokenStoreError(RuntimeError):
    """Base error for a rejected token-store operation."""


class BootstrapExistsError(TokenStoreError):
    """Raised when bootstrap is attempted against a non-empty store."""


class AuthorizationError(TokenStoreError):
    """Raised when token administration lacks an administrator credential."""


class TokenNotFoundError(TokenStoreError):
    """Raised when an opaque token ID is absent."""


class LastAdministratorError(TokenStoreError):
    """Raised when a mutation would remove the final enabled administrator."""


class CommittedDurabilityError(TokenStoreError):
    """The replacement is visible, but directory durability could not be confirmed."""


@dataclass(frozen=True)
class TokenRecord:
    id: str
    label: str
    createdAt: str
    digest: str
    enabled: bool
    scope: str
    outlets: Optional[list[str]]


@dataclass(frozen=True)
class IssuedToken:
    plaintext: str
    record: TokenRecord


class IssuedTokenDurabilityError(CommittedDurabilityError):
    """A new credential committed, but directory durability is uncertain."""

    def __init__(self, issued: IssuedToken, *, delivered: bool = False):
        super().__init__(
            "token was committed but directory durability is uncertain"
        )
        self.issued = issued
        self.delivered = delivered


@dataclass(frozen=True)
class TokenMetadata:
    id: str
    label: str
    createdAt: str
    enabled: bool
    scope: str
    outlets: Optional[list[str]]


class TokenStore:
    """Manage a strict JSON token database through locked atomic transactions."""

    def __init__(
        self,
        path: Path | str,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        fault_hook: Callable[[str], None] = lambda _point: None,
    ) -> None:
        self.path = Path(path)
        self.random_bytes = random_bytes
        self.clock = clock
        self.fault_hook = fault_hook

    def bootstrap(
        self,
        label: str,
        *,
        deliver: Optional[Callable[[IssuedToken], None]] = None,
    ) -> IssuedToken:
        """Create the first administrator token and return its plaintext once."""
        label = self._validate_label(label)
        with self._locked() as directory_descriptor:
            try:
                metadata = os.stat(
                    self.path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                metadata = None
            if metadata is not None:
                if not stat.S_ISREG(metadata.st_mode):
                    raise TokenStoreError("token store path must be a regular file, not a symlink")
                self._load_document(directory_descriptor)
                raise BootstrapExistsError("an administrative token store already exists")

            issued = self._new_token(label=label, scope="admin", outlets=None)
            document = {
                "schemaVersion": SCHEMA_VERSION,
                "generation": 1,
                "tokens": [asdict(issued.record)],
            }
            self._validate_candidate(document)
            delivered = False
            if deliver is not None:
                deliver(issued)
                delivered = True
            try:
                self._atomic_write(document, directory_descriptor)
            except CommittedDurabilityError as error:
                raise IssuedTokenDurabilityError(
                    issued,
                    delivered=delivered,
                ) from error
            return issued

    def authenticate(self, plaintext: str) -> Optional[TokenRecord]:
        """Return metadata for a token whose SHA-256 digest matches."""
        if not isinstance(plaintext, str):
            return None
        with self._locked() as directory_descriptor:
            document = self._load_document(directory_descriptor)
            return self._matching_record(document, plaintext)

    def authorize_global(
        self,
        plaintext: str,
        required_scope: str,
    ) -> Optional[TokenRecord]:
        """Authorize a non-outlet or collection operation."""
        return self._authorize_scope(plaintext, required_scope)

    def authorize_outlet(
        self,
        plaintext: str,
        required_scope: str,
        outlet_id: str,
    ) -> Optional[TokenRecord]:
        """Authorize one required opaque outlet ID."""
        if not isinstance(outlet_id, str) or re.fullmatch(
            r"[A-Za-z0-9_-]{22}", outlet_id
        ) is None:
            return None
        record = self._authorize_scope(plaintext, required_scope)
        if record is None:
            return None
        if record.outlets is not None and outlet_id not in record.outlets:
            return None
        return record

    def _authorize_scope(
        self,
        plaintext: str,
        required_scope: str,
    ) -> Optional[TokenRecord]:
        levels = {"read": 1, "control": 2, "admin": 3}
        if required_scope not in levels:
            raise TokenStoreError("required scope must be read, control, or admin")
        record = self.authenticate(plaintext)
        if record is None or not record.enabled:
            return None
        if levels[record.scope] < levels[required_scope]:
            return None
        return record

    def create_token(
        self,
        administrator_token: str,
        *,
        label: str,
        scope: str,
        outlets: Optional[list[str]] = None,
        deliver: Optional[Callable[[IssuedToken], None]] = None,
    ) -> IssuedToken:
        """Create a token in one locked transaction authorized by an admin token."""
        label = self._validate_label(label)
        if scope not in {"read", "control", "admin"}:
            raise TokenStoreError("scope must be read, control, or admin")
        if outlets is not None:
            if not isinstance(outlets, list) or len(outlets) > 256:
                raise TokenStoreError("outlet allowlist must contain at most 256 IDs")
            if any(not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{22}", value) is None for value in outlets):
                raise TokenStoreError("outlet allowlist contains an invalid opaque ID")
            if len(set(outlets)) != len(outlets):
                raise TokenStoreError("outlet allowlist contains duplicates")
            outlets = sorted(outlets)

        with self._locked() as directory_descriptor:
            document = self._load_document(directory_descriptor)
            administrator = self._matching_record(document, administrator_token)
            if administrator is None or administrator.scope != "admin" or not administrator.enabled:
                raise AuthorizationError("an enabled administrator token is required")
            if len(document["tokens"]) >= 128:
                raise TokenStoreError("token-store record limit reached")
            issued = self._new_token(label=label, scope=scope, outlets=outlets)
            document["tokens"].append(asdict(issued.record))
            document["generation"] += 1
            self._validate_candidate(document)
            delivered = False
            if deliver is not None:
                deliver(issued)
                delivered = True
            try:
                self._atomic_write(document, directory_descriptor)
            except CommittedDurabilityError as error:
                raise IssuedTokenDurabilityError(
                    issued,
                    delivered=delivered,
                ) from error
            return issued

    def set_enabled(self, administrator_token: str, token_id: str, enabled: bool) -> None:
        """Atomically enable or disable one token by opaque ID."""
        if not isinstance(enabled, bool):
            raise TokenStoreError("enabled must be boolean")
        if re.fullmatch(r"tok_[A-Za-z0-9_-]{22}", token_id) is None:
            raise TokenStoreError("invalid token ID")
        with self._locked() as directory_descriptor:
            document = self._load_document(directory_descriptor)
            administrator = self._matching_record(document, administrator_token)
            if administrator is None or administrator.scope != "admin" or not administrator.enabled:
                raise AuthorizationError("an enabled administrator token is required")
            for value in document["tokens"]:
                if value["id"] == token_id:
                    if not enabled and value["scope"] == "admin" and value["enabled"]:
                        enabled_administrators = sum(
                            candidate["scope"] == "admin" and candidate["enabled"]
                            for candidate in document["tokens"]
                        )
                        if enabled_administrators == 1:
                            raise LastAdministratorError(
                                "cannot disable the last enabled administrator"
                            )
                    value["enabled"] = enabled
                    document["generation"] += 1
                    self._atomic_write(document, directory_descriptor)
                    return
            raise TokenNotFoundError("token ID does not exist")

    def revoke(self, administrator_token: str, token_id: str) -> None:
        """Atomically remove one token digest and its metadata."""
        if re.fullmatch(r"tok_[A-Za-z0-9_-]{22}", token_id) is None:
            raise TokenStoreError("invalid token ID")
        with self._locked() as directory_descriptor:
            document = self._load_document(directory_descriptor)
            administrator = self._matching_record(document, administrator_token)
            if administrator is None or administrator.scope != "admin" or not administrator.enabled:
                raise AuthorizationError("an enabled administrator token is required")
            target = next((value for value in document["tokens"] if value["id"] == token_id), None)
            if target is None:
                raise TokenNotFoundError("token ID does not exist")
            if target["scope"] == "admin" and target["enabled"]:
                enabled_administrators = sum(
                    value["scope"] == "admin" and value["enabled"]
                    for value in document["tokens"]
                )
                if enabled_administrators == 1:
                    raise LastAdministratorError("cannot revoke the last enabled administrator")
            document["tokens"] = [value for value in document["tokens"] if value["id"] != token_id]
            document["generation"] += 1
            self._atomic_write(document, directory_descriptor)

    def _matching_record(self, document: dict, plaintext: str) -> Optional[TokenRecord]:
        if not isinstance(plaintext, str):
            return None
        presented_digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
        match = None
        for value in document["tokens"]:
            record = TokenRecord(**value)
            if hmac.compare_digest(record.digest, presented_digest):
                match = record
        return match

    def list_tokens(self, administrator_token: str) -> list[TokenMetadata]:
        """List non-secret token metadata for an enabled administrator."""
        with self._locked() as directory_descriptor:
            document = self._load_document(directory_descriptor)
            administrator = self._matching_record(document, administrator_token)
            if administrator is None or administrator.scope != "admin" or not administrator.enabled:
                raise AuthorizationError("an enabled administrator token is required")
            return [
                TokenMetadata(
                    id=value["id"],
                    label=value["label"],
                    createdAt=value["createdAt"],
                    enabled=value["enabled"],
                    scope=value["scope"],
                    outlets=value["outlets"],
                )
                for value in document["tokens"]
            ]

    def _new_token(self, *, label: str, scope: str, outlets: Optional[list[str]]) -> IssuedToken:
        token_material = self.random_bytes(32)
        identifier_material = self.random_bytes(16)
        plaintext = TOKEN_PREFIX + self._base64url(token_material)
        identifier = "tok_" + self._base64url(identifier_material)
        created = self.clock().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        record = TokenRecord(
            id=identifier,
            label=label,
            createdAt=created,
            digest=hashlib.sha256(plaintext.encode("ascii")).hexdigest(),
            enabled=True,
            scope=scope,
            outlets=outlets,
        )
        return IssuedToken(plaintext=plaintext, record=record)

    @staticmethod
    def _base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _validate_label(label: str) -> str:
        if not isinstance(label, str) or not 1 <= len(label) <= 64:
            raise TokenStoreError("label must contain 1 to 64 characters")
        if label != label.strip() or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label):
            raise TokenStoreError("label contains disallowed whitespace or control characters")
        try:
            encoded = label.encode("utf-8")
        except UnicodeEncodeError as error:
            raise TokenStoreError("label is not valid Unicode") from error
        if len(encoded) > 128:
            raise TokenStoreError("UTF-8 label exceeds 128 bytes")
        return label

    def _open_private_directory(self) -> int:
        directory = self.path.parent
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass

        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(directory, flags)
        except OSError as error:
            raise TokenStoreError("token-store directory is not a real directory") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise TokenStoreError(
                    "token-store directory must be owned by the caller and mode 0700"
                )
            parent_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                parent_flags |= os.O_DIRECTORY
            if hasattr(os, "O_CLOEXEC"):
                parent_flags |= os.O_CLOEXEC
            parent_descriptor = os.open(directory.parent, parent_flags)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _locked(self):
        directory_descriptor = self._open_private_directory()
        lock_name = self.path.name + ".lock"
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(
                lock_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise TokenStoreError(
                    "token-store lock must be caller-owned regular mode-0600 file"
                )
        except BaseException:
            if "descriptor" in locals():
                os.close(descriptor)
            os.close(directory_descriptor)
            raise

        class Lock:
            def __enter__(inner_self):
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    locked_metadata = os.stat(
                        lock_name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        locked_metadata.st_dev != metadata.st_dev
                        or locked_metadata.st_ino != metadata.st_ino
                    ):
                        raise TokenStoreError(
                            "token-store lock path changed while acquiring lock"
                        )
                    return directory_descriptor
                except BaseException:
                    os.close(descriptor)
                    os.close(directory_descriptor)
                    raise

            def __exit__(inner_self, exception_type, exception, traceback):
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    try:
                        os.close(descriptor)
                    finally:
                        os.close(directory_descriptor)

        return Lock()

    @staticmethod
    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
        document = {}
        for key, value in pairs:
            if key in document:
                raise TokenStoreError(f"duplicate JSON member: {key}")
            document[key] = value
        return document

    def _load_document(self, directory_descriptor: int) -> dict:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(
            self.path.name,
            flags,
            dir_fd=directory_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise TokenStoreError(
                    "token store must be caller-owned regular mode-0600 file"
                )
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_STORE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(65536, MAX_STORE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
        if len(payload) > MAX_STORE_BYTES:
            raise TokenStoreError("token store exceeds the size limit")
        try:
            document = json.loads(
                payload.decode("utf-8"), object_pairs_hook=self._reject_duplicate_keys
            )
            self._validate_candidate(document)
        except (
            RecursionError,
            UnicodeError,
            json.JSONDecodeError,
            TokenStoreError,
        ) as error:
            raise TokenStoreError("token store is not strict UTF-8 JSON") from error
        return document

    def _validate_candidate(self, document: object) -> None:
        if not isinstance(document, dict) or set(document) != {
            "schemaVersion",
            "generation",
            "tokens",
        }:
            raise TokenStoreError("token-store document has unknown or missing members")
        if type(document["schemaVersion"]) is not int or document["schemaVersion"] != SCHEMA_VERSION:
            raise TokenStoreError("unsupported token-store document")
        if (
            type(document["generation"]) is not int
            or not 1 <= document["generation"] <= MAX_GENERATION
        ):
            raise TokenStoreError(
                "token-store generation must be an integer from 1 through 2^63-1"
            )
        if not isinstance(document["tokens"], list) or not 1 <= len(document["tokens"]) <= 128:
            raise TokenStoreError("token-store tokens must contain 1 to 128 records")
        expected_record_members = {
            "id",
            "label",
            "createdAt",
            "digest",
            "enabled",
            "scope",
            "outlets",
        }
        identifiers: set[str] = set()
        digests: set[str] = set()
        enabled_administrators = 0
        for value in document["tokens"]:
            if not isinstance(value, dict) or set(value) != expected_record_members:
                raise TokenStoreError("token record has unknown or missing members")
            if not isinstance(value["id"], str) or re.fullmatch(
                r"tok_[A-Za-z0-9_-]{22}", value["id"]
            ) is None:
                raise TokenStoreError("token record has an invalid ID")
            self._validate_label(value["label"])
            if not isinstance(value["createdAt"], str) or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                value["createdAt"],
            ) is None:
                raise TokenStoreError("token record has an invalid creation time")
            try:
                datetime.strptime(value["createdAt"], "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as error:
                raise TokenStoreError("token record has an invalid creation time") from error
            if not isinstance(value["digest"], str) or re.fullmatch(r"[0-9a-f]{64}", value["digest"]) is None:
                raise TokenStoreError("token record has an invalid SHA-256 digest")
            if type(value["enabled"]) is not bool:
                raise TokenStoreError("token record enabled state must be boolean")
            if not isinstance(value["scope"], str) or value["scope"] not in {
                "read",
                "control",
                "admin",
            }:
                raise TokenStoreError("token record has an invalid scope")
            outlets = value["outlets"]
            if outlets is not None:
                if not isinstance(outlets, list) or len(outlets) > 256:
                    raise TokenStoreError("token record has an invalid outlet allowlist")
                if any(
                    not isinstance(outlet, str)
                    or re.fullmatch(r"[A-Za-z0-9_-]{22}", outlet) is None
                    for outlet in outlets
                ):
                    raise TokenStoreError("token record has an invalid outlet allowlist")
                if outlets != sorted(set(outlets)):
                    raise TokenStoreError("token outlet allowlist is not canonical")
            if value["id"] in identifiers or value["digest"] in digests:
                raise TokenStoreError("token IDs and digests must be unique")
            identifiers.add(value["id"])
            digests.add(value["digest"])
            if value["scope"] == "admin" and value["enabled"]:
                enabled_administrators += 1
        if enabled_administrators == 0:
            raise TokenStoreError("token store has no enabled administrator")

    def _atomic_write(self, document: dict, directory_descriptor: int) -> None:
        self._validate_candidate(document)
        serialized = (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(serialized) > MAX_STORE_BYTES:
            raise TokenStoreError("serialized token store exceeds the size limit")

        descriptor = -1
        temporary_name = ""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        for _attempt in range(16):
            candidate_name = ".tokens." + secrets.token_hex(16)
            try:
                descriptor = os.open(
                    candidate_name,
                    flags,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                temporary_name = candidate_name
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise TokenStoreError("could not allocate a private temporary store file")

        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise TokenStoreError("temporary token store is not a private regular file")
            view = memoryview(serialized)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write while publishing token store")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            self.fault_hook("before_replace")
            committed = False
            try:
                os.replace(
                    temporary_name,
                    self.path.name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
                committed = True
                self.fault_hook("after_replace")
                os.fsync(directory_descriptor)
            except OSError as error:
                if committed:
                    raise CommittedDurabilityError(
                        "token store was replaced, but directory durability is uncertain"
                    ) from error
                raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
