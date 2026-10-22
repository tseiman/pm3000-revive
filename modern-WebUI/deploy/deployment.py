#!/usr/bin/env python3
"""Backup-first Stage 6 release and deployment helper (Python standard library only)."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import Iterable, Optional
import uuid


class DeploymentError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _safe_release_id(value: str) -> str:
    if not value or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in value):
        raise DeploymentError("release id must contain only ASCII letters, digits, dot, underscore, or dash")
    if value in (".", ".."):
        raise DeploymentError("invalid release id")
    return value


def _tar_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def build_release(source_root: Path | str, output: Path | str, release_id: str,
                  git_revision: str = "unknown") -> Path:
    """Snapshot the exact allowlist bytes and write a deterministic uncompressed tar."""
    source = Path(source_root)
    destination = Path(output)
    release_id = _safe_release_id(release_id)
    if git_revision != "unknown" and (
            len(git_revision) < 7 or len(git_revision) > 40
            or any(c not in "0123456789abcdef" for c in git_revision)):
        raise DeploymentError("unsafe Git revision")
    lines = (source / "web" / "release-files.txt").read_text(encoding="utf-8").splitlines()
    parsed = [line.split("\t", 1) for line in lines]
    if not parsed or any(len(fields) != 2 or not fields[0] or not fields[1] for fields in parsed):
        raise DeploymentError("web release allowlist must contain path and MIME type")
    names = [fields[0] for fields in parsed]
    if any(n != Path(n).name or n.startswith(".") for n in names):
        raise DeploymentError("web release allowlist contains an unsafe entry")
    if len(names) != len(set(names)):
        raise DeploymentError("web release allowlist contains a duplicate")

    sources = {f"web/{name}": source / "web" / name for name in names}
    sources["bin/pm3000-rest"] = source / "native" / "build" / "pm3000-rest-ppc32"
    sources["bin/pm3000-atomic-publish"] = source / "deploy" / "build" / "pm3000-atomic-publish-ppc32"
    sources["apache/pm3000-revive.conf"] = source / "deploy" / "pm3000-revive.conf"
    snapshots: dict[str, tuple[bytes, int]] = {}
    for target, path in sources.items():
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise DeploymentError(f"release source is not a regular file: {path}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened_before = os.fstat(descriptor)
            if (not stat.S_ISREG(opened_before.st_mode) or opened_before.st_nlink != 1
                    or (opened_before.st_dev, opened_before.st_ino) != (before.st_dev, before.st_ino)):
                raise DeploymentError(f"unsafe release source: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read()
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity_before = (opened_before.st_dev, opened_before.st_ino, opened_before.st_size,
                           opened_before.st_mtime_ns, opened_before.st_ctime_ns)
        identity_after = (opened_after.st_dev, opened_after.st_ino, opened_after.st_size,
                          opened_after.st_mtime_ns, opened_after.st_ctime_ns)
        if identity_before != identity_after or len(data) != opened_before.st_size:
            raise DeploymentError(f"release source changed while being read: {path}")
        mode = 0o755 if target.startswith("bin/") else 0o644
        if target == "web/index.html":
            release_placeholder = b"__PM3000_RELEASE_ID__"
            revision_placeholder = b"__PM3000_GIT_REVISION__"
            if data.count(release_placeholder) != 1 or data.count(revision_placeholder) != 1:
                raise DeploymentError("web build identity placeholders are missing or duplicated")
            data = data.replace(release_placeholder, release_id.encode("ascii"))
            data = data.replace(revision_placeholder, git_revision.encode("ascii"))
        snapshots[target] = (data, mode)

    entries = [
        {"path": name, "sha256": _sha256(data), "size": len(data), "mode": mode}
        for name, (data, mode) in sorted(snapshots.items())
    ]
    manifest = json.dumps(
        {"format": 1, "release_id": release_id, "files": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    checksum_lines = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries).encode("ascii")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    with tarfile.open(temporary, "w", format=tarfile.PAX_FORMAT) as archive:
        _tar_bytes(archive, "RELEASE_MANIFEST.json", manifest, 0o600)
        _tar_bytes(archive, "RELEASE_SHA256SUMS", checksum_lines, 0o600)
        for name in sorted(snapshots):
            data, mode = snapshots[name]
            _tar_bytes(archive, name, data, mode)
    os.replace(temporary, destination)
    digest_file = destination.with_name(destination.name + ".sha256")
    digest_temp = digest_file.with_name(digest_file.name + ".tmp")
    digest_temp.write_text(_sha256(destination.read_bytes()) + "  " + destination.name + "\n", encoding="ascii")
    os.replace(digest_temp, digest_file)
    return destination


CURRENT = "/mnt/hdUser/pm3000-revive/webui/current"
RELEASES = "/mnt/hdUser/pm3000-revive/webui/releases"
APACHE_CONFIG = "/etc/apache2/conf.d/pm3000-revive.conf"
ACTIVE_TRANSACTION = "/mnt/hdUser/pm3000-revive/deploy/ACTIVE_TRANSACTION.json"
BACKUP_ROOTS = (
    "/mnt/hdUser/pm3000-revive/webui",
    "/mnt/hdUser/pm3000-revive/rest",
    "/mnt/hdUser/pm3000-revive/deploy",
    APACHE_CONFIG,
    "/etc/pm3000-rest",
)
INVENTORY_PARENTS = (
    "/mnt", "/mnt/hdUser", "/mnt/hdUser/pm3000-revive",
    "/etc", "/etc/apache2", "/etc/apache2/conf.d",
)


def _device_path(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/") or ".." in PurePosixPath(absolute).parts:
        raise DeploymentError(f"unsafe device path: {absolute}")
    return root / absolute.lstrip("/")


def _target_identity(root: Path) -> dict:
    metadata = root.stat()
    firmware = _entry(root, "/etc/version")
    return {
        "transport": "simulation",
        "root": str(root.resolve()),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "firmware_evidence": firmware,
    }


def _capture_entry(root: Path, name: str) -> tuple[dict, Optional[bytes]]:
    path = _device_path(root, name)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"path": name, "type": "absent"}, None
    common = {
        "path": name, "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid, "gid": metadata.st_gid,
    }
    if stat.S_ISREG(metadata.st_mode):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            if (not stat.S_ISREG(opened_before.st_mode) or opened_before.st_nlink != 1
                    or (opened_before.st_dev, opened_before.st_ino) != (metadata.st_dev, metadata.st_ino)):
                raise DeploymentError(f"unsafe backup source: {name}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read()
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity_before = (opened_before.st_dev, opened_before.st_ino, opened_before.st_size,
                           opened_before.st_mtime_ns, opened_before.st_ctime_ns)
        identity_after = (opened_after.st_dev, opened_after.st_ino, opened_after.st_size,
                          opened_after.st_mtime_ns, opened_after.st_ctime_ns)
        if identity_before != identity_after or len(data) != opened_before.st_size:
            raise DeploymentError(f"backup source changed during capture: {name}")
        return ({**common, "type": "file", "size": len(data), "sha256": _sha256(data)}, data)
    if stat.S_ISDIR(metadata.st_mode):
        return {**common, "type": "directory"}, None
    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(path)
        after = path.lstat()
        if (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_mtime_ns):
            raise DeploymentError(f"symlink changed during capture: {name}")
        return {**common, "type": "symlink", "target": target}, None
    return {**common, "type": "other"}, None


def _entry(root: Path, name: str) -> dict:
    return _capture_entry(root, name)[0]


def _scope_entries(root: Path) -> tuple[list[dict], dict[str, bytes]]:
    """Inventory every managed object without following symlinks.

    Each scope root is represented explicitly even when absent. Parent entries are
    metadata-only; descendants are recursively captured only below BACKUP_ROOTS.
    """
    entries = [_entry(root, name) for name in INVENTORY_PARENTS]
    payloads: dict[str, bytes] = {}

    def visit(absolute: str) -> None:
        entry, data = _capture_entry(root, absolute)
        entries.append(entry)
        if data is not None:
            payloads[absolute] = data
        if entry["type"] != "directory":
            return
        directory = _device_path(root, absolute)
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened_before = os.fstat(descriptor)
            if (not stat.S_ISDIR(opened_before.st_mode)
                    or stat.S_IMODE(opened_before.st_mode) != entry["mode"]
                    or opened_before.st_uid != entry["uid"] or opened_before.st_gid != entry["gid"]):
                raise DeploymentError(f"backup directory changed before enumeration: {absolute}")
            children = sorted((child.name for child in os.scandir(descriptor)))
            opened_after = os.fstat(descriptor)
        except OSError as exc:
            raise DeploymentError(f"cannot inventory backup scope: {absolute}") from exc
        finally:
            os.close(descriptor)
        identity_before = (opened_before.st_dev, opened_before.st_ino, opened_before.st_mtime_ns,
                           opened_before.st_ctime_ns)
        identity_after = (opened_after.st_dev, opened_after.st_ino, opened_after.st_mtime_ns,
                          opened_after.st_ctime_ns)
        if identity_before != identity_after:
            raise DeploymentError(f"backup directory changed during enumeration: {absolute}")
        for child_name in children:
            visit(absolute.rstrip("/") + "/" + child_name)

    for scope_root in BACKUP_ROOTS:
        visit(scope_root)
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)):
        raise DeploymentError("backup inventory contains duplicate paths")
    return entries, payloads


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_bytes(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".stage6-tmp")
    if temporary.exists() or temporary.is_symlink():
        raise DeploymentError(f"refusing existing transaction temporary path: {temporary}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    _fsync_dir(path.parent)


def _validate_chain(root: Path, absolute: str, final_types: tuple[str, ...]) -> None:
    relative = PurePosixPath(absolute).parts[1:]
    cursor = root
    for index, component in enumerate(relative):
        cursor = cursor / component
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            if index == len(relative) - 1 and "symlink" in final_types:
                return
            raise DeploymentError(f"unsafe symlink in path: {cursor}")
        if index < len(relative) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise DeploymentError(f"unsafe non-directory parent: {cursor}")
        if index < len(relative) - 1 and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise DeploymentError(f"unsafe writable parent mode: {cursor}")
        if index == len(relative) - 1:
            kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "other"
            if kind not in final_types:
                raise DeploymentError(f"unsafe {kind} at {cursor}")
            if kind in ("directory", "file") and stat.S_IMODE(metadata.st_mode) & 0o022:
                raise DeploymentError(f"unsafe writable mode at {cursor}")


def _safe_archive_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    names: set[str] = set()
    for member in members:
        pure = PurePosixPath(member.name)
        if pure.is_absolute() or ".." in pure.parts or member.name in names:
            raise DeploymentError(f"unsafe archive member: {member.name}")
        if not member.isfile():
            raise DeploymentError(f"unsafe archive member type: {member.name}")
        names.add(member.name)
    return members


def _read_regular_snapshot(path: Path, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DeploymentError(f"cannot open {label} safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise DeploymentError(f"unsafe {label} inode")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size,
                           before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise DeploymentError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_release_snapshot(package: Path) -> tuple[dict, dict[str, bytes], bytes]:
    sidecar = package.with_name(package.name + ".sha256")
    try:
        sidecar_text = _read_regular_snapshot(sidecar, "package SHA256 sidecar").decode("ascii")
        sidecar_lines = sidecar_text.splitlines()
        if len(sidecar_lines) != 1 or sidecar_lines[0] != sidecar_lines[0].strip():
            raise DeploymentError("invalid package SHA256 sidecar")
        digest_and_name = sidecar_lines[0].split("  ")
        if len(digest_and_name) != 2 or digest_and_name[1] != package.name:
            raise DeploymentError("package SHA256 sidecar filename mismatch")
        expected_package = digest_and_name[0]
        if len(expected_package) != 64 or any(c not in "0123456789abcdef" for c in expected_package):
            raise DeploymentError("invalid package SHA256")
    except (UnicodeDecodeError, FileNotFoundError) as exc:
        raise DeploymentError("missing or invalid package SHA256 sidecar") from exc
    package_bytes = _read_regular_snapshot(package, "release package")
    if _sha256(package_bytes) != expected_package:
        raise DeploymentError("release package digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(package_bytes), mode="r:") as archive:
        members = _safe_archive_members(archive)
        names = {member.name for member in members}
        if "RELEASE_MANIFEST.json" not in names:
            raise DeploymentError("release manifest missing")
        stream = archive.extractfile("RELEASE_MANIFEST.json")
        if stream is None:
            raise DeploymentError("release manifest unreadable")
        manifest = json.load(stream)
        if (not isinstance(manifest, dict) or set(manifest) != {"format", "release_id", "files"}
                or manifest["format"] != 1 or not isinstance(manifest["files"], list)):
            raise DeploymentError("invalid release manifest schema")
        required_payloads = {
            "apache/pm3000-revive.conf", "bin/pm3000-atomic-publish", "bin/pm3000-rest",
            "web/app.js", "web/index.html", "web/styles.css",
        }
        entries = manifest["files"]
        if any(not isinstance(entry, dict)
               or set(entry) != {"path", "sha256", "size", "mode"} for entry in entries):
            raise DeploymentError("invalid release manifest entry")
        entry_names = [entry["path"] for entry in entries]
        if len(entry_names) != len(set(entry_names)) or set(entry_names) != required_payloads:
            raise DeploymentError("release manifest allowlist mismatch")
        for entry in entries:
            expected_mode = 0o755 if entry["path"].startswith("bin/") else 0o644
            if (entry["mode"] != expected_mode or not isinstance(entry["size"], int)
                    or isinstance(entry["size"], bool) or entry["size"] < 0
                    or not isinstance(entry["sha256"], str) or len(entry["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in entry["sha256"])):
                raise DeploymentError(f"invalid release metadata: {entry['path']}")
        expected_names = {"RELEASE_MANIFEST.json", "RELEASE_SHA256SUMS"} | set(entry_names)
        if names != expected_names:
            raise DeploymentError("unexpected or missing release archive member")
        sums_stream = archive.extractfile("RELEASE_SHA256SUMS")
        expected_sums = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in manifest["files"]).encode("ascii")
        if sums_stream is None or sums_stream.read() != expected_sums:
            raise DeploymentError("release checksum list mismatch")
        payloads: dict[str, bytes] = {}
        member_by_name = {member.name: member for member in members}
        for entry in entries:
            name = entry["path"]
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts:
                raise DeploymentError("unsafe path in release manifest")
            source = archive.extractfile(name)
            if source is None:
                raise DeploymentError(f"release member unreadable: {name}")
            data = source.read()
            if (member_by_name[name].mode != entry["mode"] or len(data) != entry["size"]
                    or _sha256(data) != entry["sha256"]):
                raise DeploymentError(f"release member digest mismatch: {name}")
            payloads[name] = data
    _safe_release_id(manifest["release_id"])
    return manifest, payloads, package_bytes


def _read_release(package: Path) -> tuple[dict, dict[str, bytes]]:
    manifest, payloads, _ = _read_release_snapshot(package)
    return manifest, payloads


def _verify_release_directory(release: Path, manifest: dict, *, allow_missing: bool = False) -> None:
    try:
        metadata = release.lstat()
    except FileNotFoundError as exc:
        if allow_missing:
            return
        raise DeploymentError("managed release is missing") from exc
    trusted_uid = os.geteuid()
    if (not stat.S_ISDIR(metadata.st_mode) or release.is_symlink()
            or stat.S_IMODE(metadata.st_mode) != 0o755 or metadata.st_uid != trusted_uid):
        raise DeploymentError("managed release has unsafe type, mode, or ownership")
    expected_files = {entry["path"] for entry in manifest["files"]} | {
        "RELEASE_MANIFEST.json", "RELEASE_SHA256SUMS",
    }
    expected_directories = {str(PurePosixPath(name).parent) for name in expected_files if "/" in name}
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for directory, directory_names, file_names in os.walk(release, followlinks=False):
        base = Path(directory)
        relative_base = base.relative_to(release)
        if relative_base != Path("."):
            actual_directories.add(relative_base.as_posix())
            base_metadata = base.lstat()
            if (base.is_symlink() or stat.S_IMODE(base_metadata.st_mode) != 0o755
                    or base_metadata.st_uid != trusted_uid):
                raise DeploymentError("managed release directory drifted")
        for name in list(directory_names):
            if (base / name).is_symlink():
                raise DeploymentError("managed release contains a symlink")
        for name in file_names:
            child = base / name
            child_metadata = child.lstat()
            if (child.is_symlink() or not stat.S_ISREG(child_metadata.st_mode)
                    or child_metadata.st_uid != trusted_uid):
                raise DeploymentError("managed release contains an unsafe object")
            actual_files.add(child.relative_to(release).as_posix())
    if (actual_files - expected_files or actual_directories - expected_directories
            or (not allow_missing
                and (actual_files != expected_files or actual_directories != expected_directories))):
        raise DeploymentError("managed release members drifted")
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    manifest_path = release / "RELEASE_MANIFEST.json"
    if "RELEASE_MANIFEST.json" in actual_files:
        manifest_metadata = manifest_path.lstat()
        if (manifest_metadata.st_uid != trusted_uid
                or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
                or _read_regular_snapshot(manifest_path, "managed release manifest") != canonical_manifest):
            raise DeploymentError("managed release manifest drifted")
    sums_path = release / "RELEASE_SHA256SUMS"
    if "RELEASE_SHA256SUMS" in actual_files:
        expected_sums = "".join(
            f"{entry['sha256']}  {entry['path']}\n" for entry in manifest["files"]
        ).encode("ascii")
        sums_metadata = sums_path.lstat()
        if (sums_metadata.st_uid != trusted_uid
                or stat.S_IMODE(sums_metadata.st_mode) != 0o600
                or _read_regular_snapshot(sums_path, "managed release checksum list") != expected_sums):
            raise DeploymentError("managed release checksum list drifted")
    for entry in manifest["files"]:
        if entry["path"] not in actual_files:
            continue
        path = release / entry["path"]
        data = _read_regular_snapshot(path, f"managed release payload {entry['path']}")
        path_metadata = path.lstat()
        if (path_metadata.st_uid != trusted_uid
                or stat.S_IMODE(path_metadata.st_mode) != entry["mode"] or len(data) != entry["size"]
                or _sha256(data) != entry["sha256"]):
            raise DeploymentError(f"managed release payload drifted: {entry['path']}")


def _create_backup(root: Path, backup_root: Path, release_id: str, package_sha256: str,
                   release_manifest: dict, transaction_id: str, target_identity: dict,
                   fault: str | None) -> tuple[Path, dict, dict, bytes]:
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_root, 0o700)
    backup_dir = Path(tempfile.mkdtemp(prefix=release_id + "-", dir=backup_root))
    os.chmod(backup_dir, 0o700)
    new_release = RELEASES + "/" + release_id
    transaction_paths = (
        new_release,
        RELEASES + "/." + release_id + ".stage6-tmp",
        "/mnt/hdUser/pm3000-revive/webui/.current.stage6-tmp",
        "/etc/apache2/conf.d/.pm3000-revive.conf.stage6-tmp",
    )
    entries, captured_payloads = _scope_entries(root)
    represented = {entry["path"] for entry in entries}
    for required_path in (RELEASES, CURRENT, ACTIVE_TRANSACTION) + transaction_paths:
        if required_path not in represented:
            entries.append(_entry(root, required_path))
            represented.add(required_path)
    if any(entry["type"] == "other" for entry in entries):
        raise DeploymentError("backup inventory contains unsupported file type")
    created_paths = [name for name in (new_release, transaction_paths[1], CURRENT,
                                      APACHE_CONFIG, ACTIVE_TRANSACTION)
                     if _entry(root, name)["type"] == "absent"]
    apache_entry = next(entry for entry in release_manifest["files"]
                        if entry["path"] == "apache/pm3000-revive.conf")
    state = {
        "format": 1,
        "transaction_id": transaction_id,
        "target_identity": target_identity,
        "release_id": release_id,
        "backup_dir": str(backup_dir),
        "created_release": new_release in created_paths,
        "post_current_target": "releases/" + release_id,
        "post_config_sha256": apache_entry["sha256"],
        "release_manifest": release_manifest,
    }
    state_bytes = _canonical_json(state)
    manifest = {"format": 2, "transaction_id": transaction_id,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "target_identity": target_identity,
                "release_id": release_id, "package_sha256": package_sha256,
                "release_manifest_sha256": _sha256(_canonical_json(release_manifest)),
                "deployment_state_sha256": _sha256(state_bytes),
                "entries": entries,
                "created_paths": created_paths}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    remote_dir = root / "tmp" / ("stage6-backup-" + backup_dir.name)
    remote_dir.mkdir(parents=True, mode=0o700)
    os.chmod(remote_dir, 0o700)
    remote_archive = remote_dir / "backup.tar"
    with tarfile.open(remote_archive, "w", format=tarfile.PAX_FORMAT) as archive:
        _tar_bytes(archive, "BACKUP_MANIFEST.json", manifest_bytes, 0o600)
        regular_entries = [entry for entry in entries if entry["type"] == "file"]
        for index, entry in enumerate(regular_entries):
            if fault == "backup_incomplete" and index == len(regular_entries) - 1:
                continue
            data = captured_payloads[entry["path"]]
            _tar_bytes(archive, "files" + entry["path"], data, entry["mode"])
    os.chmod(remote_archive, 0o600)
    remote_digest = _sha256(remote_archive.read_bytes())
    if fault == "backup_copy":
        raise DeploymentError("injected backup copy failure")
    local_archive = backup_dir / "backup.tar"
    shutil.copyfile(remote_archive, local_archive)
    os.chmod(local_archive, 0o600)
    local_digest = _sha256(local_archive.read_bytes())
    if fault == "backup_digest":
        remote_digest = "0" * 64
    if remote_digest != local_digest:
        raise DeploymentError("remote/local backup SHA256 mismatch")
    with tarfile.open(local_archive, "r:") as archive:
        names = {member.name for member in _safe_archive_members(archive)}
        stream = archive.extractfile("BACKUP_MANIFEST.json")
        if stream is None or stream.read() != manifest_bytes:
            raise DeploymentError("backup manifest mismatch")
        required = {"BACKUP_MANIFEST.json"} | {
            "files" + entry["path"] for entry in entries if entry["type"] == "file"
        }
        if names != required:
            raise DeploymentError("backup archive incomplete")
    _atomic_bytes(backup_dir / "BACKUP_MANIFEST.json", manifest_bytes, 0o600)
    digest_text = remote_digest + "  backup.tar\n"
    _atomic_bytes(backup_dir / "SHA256SUMS", digest_text.encode("ascii"), 0o600)
    marker = (remote_digest + "\n" + _sha256(manifest_bytes) + "\n").encode("ascii")
    _atomic_bytes(backup_dir / "BACKUP_COMPLETE", marker, 0o600)
    _fsync_dir(backup_dir)
    _atomic_bytes(backup_dir / "EVENTS", b"BACKUP_COMPLETE\n", 0o600)
    remote_archive.unlink()
    remote_dir.rmdir()
    return backup_dir, manifest, state, state_bytes


def _verify_backup(backup_dir: Path) -> tuple[dict, dict[str, bytes]]:
    marker_path = backup_dir / "BACKUP_COMPLETE"
    manifest_path = backup_dir / "BACKUP_MANIFEST.json"
    archive_path = backup_dir / "backup.tar"
    try:
        marker = marker_path.read_text(encoding="ascii").splitlines()
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise DeploymentError("backup is incomplete") from exc
    if len(marker) != 2 or marker[0] != _sha256(archive_path.read_bytes()) or marker[1] != _sha256(manifest_bytes):
        raise DeploymentError("backup completion digest mismatch")
    manifest = json.loads(manifest_bytes)
    payloads: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:") as archive:
        _safe_archive_members(archive)
        internal = archive.extractfile("BACKUP_MANIFEST.json")
        if internal is None or internal.read() != manifest_bytes:
            raise DeploymentError("backup manifest is not the archived manifest")
        for entry in manifest["entries"]:
            if entry["type"] == "file":
                member = "files" + entry["path"]
                source = archive.extractfile(member)
                if source is None:
                    raise DeploymentError(f"backup payload missing: {entry['path']}")
                data = source.read()
                if len(data) != entry["size"] or _sha256(data) != entry["sha256"]:
                    raise DeploymentError(f"backup payload mismatch: {entry['path']}")
                payloads[entry["path"]] = data
    return manifest, payloads


def _switch_symlink(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".stage6-tmp")
    if temporary.exists() or temporary.is_symlink():
        raise DeploymentError(f"refusing existing transaction temporary path: {temporary}")
    temporary.symlink_to(target)
    os.replace(temporary, path)
    _fsync_dir(path.parent)


def _restore_transaction(root: Path, manifest: dict, payloads: dict[str, bytes], remove_release: bool = True) -> None:
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    config = _device_path(root, APACHE_CONFIG)
    old_config = entries[APACHE_CONFIG]
    if old_config["type"] == "absent":
        if config.exists() or config.is_symlink():
            config.unlink()
            _fsync_dir(config.parent)
    elif old_config["type"] == "file":
        _atomic_bytes(config, payloads[APACHE_CONFIG], old_config["mode"])
        try:
            os.chown(config, old_config["uid"], old_config["gid"])
        except PermissionError:
            pass
        _fsync_file(config)
        _fsync_dir(config.parent)
    active = _device_path(root, ACTIVE_TRANSACTION)
    old_active = entries[ACTIVE_TRANSACTION]
    if old_active["type"] == "absent":
        if active.exists() or active.is_symlink():
            active.unlink()
            _fsync_dir(active.parent)
    elif old_active["type"] == "file":
        _atomic_bytes(active, payloads[ACTIVE_TRANSACTION], old_active["mode"])
    current = _device_path(root, CURRENT)
    old_current = entries[CURRENT]
    if old_current["type"] == "absent":
        if current.exists() or current.is_symlink():
            current.unlink()
            _fsync_dir(current.parent)
    elif old_current["type"] == "symlink":
        _switch_symlink(current, old_current["target"])
        try:
            os.lchown(current, old_current["uid"], old_current["gid"])
        except PermissionError:
            pass
        _fsync_dir(current.parent)
    if remove_release:
        release_names = (
            RELEASES + "/" + manifest["release_id"],
            RELEASES + "/." + manifest["release_id"] + ".stage6-tmp",
        )
        for release_name in release_names:
            if release_name in manifest.get("created_paths", []):
                release = _device_path(root, release_name)
                if release.exists() and not release.is_symlink():
                    shutil.rmtree(release)
                    _fsync_dir(release.parent)
    absent_directories = sorted(
        (entry["path"] for entry in entries.values() if entry["type"] == "absent"),
        key=lambda name: len(PurePosixPath(name).parts), reverse=True,
    )
    for name in absent_directories:
        path = _device_path(root, name)
        if path.is_dir() and not path.is_symlink():
            try:
                path.rmdir()
                _fsync_dir(path.parent)
            except OSError:
                pass


def _verify_deployed_state(root: Path, state: dict) -> None:
    current = _device_path(root, CURRENT)
    if not current.is_symlink() or os.readlink(current) != state["post_current_target"]:
        raise DeploymentError("live current pointer drifted; refusing automatic rollback")
    config = _device_path(root, APACHE_CONFIG)
    if (not config.is_file() or config.is_symlink()
            or _sha256(config.read_bytes()) != state["post_config_sha256"]):
        raise DeploymentError("live Apache configuration drifted; refusing automatic rollback")
    _verify_release_directory(
        _device_path(root, RELEASES + "/" + state["release_id"]),
        state["release_manifest"],
    )


def _verify_restored_state(root: Path, manifest: dict, state: dict) -> None:
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    for name in (CURRENT, APACHE_CONFIG, ACTIVE_TRANSACTION):
        expected = entries[name]
        actual = _entry(root, name)
        keys = {"path", "type", "mode", "uid", "gid"}
        if expected["type"] == "file":
            keys |= {"size", "sha256"}
        elif expected["type"] == "symlink":
            keys.add("target")
        if any(actual.get(key) != expected.get(key) for key in keys):
            raise DeploymentError("rollback state drifted; refusing resume")
    release = _device_path(root, RELEASES + "/" + state["release_id"])
    if state["created_release"]:
        temporary_release = _device_path(
            root, RELEASES + "/." + state["release_id"] + ".stage6-tmp"
        )
        if release.exists() or release.is_symlink() or temporary_release.exists() or temporary_release.is_symlink():
            raise DeploymentError("rollback-created release still exists")
    else:
        _verify_release_directory(release, state["release_manifest"])


def _entries_match(actual: dict, expected: dict) -> bool:
    keys = {"path", "type", "mode", "uid", "gid"}
    if expected["type"] == "file":
        keys |= {"size", "sha256"}
    elif expected["type"] == "symlink":
        keys.add("target")
    return all(actual.get(key) == expected.get(key) for key in keys)


def _verify_resumable_rollback_state(root: Path, manifest: dict, state: dict,
                                     deployment_complete: dict) -> None:
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    for name in (CURRENT, APACHE_CONFIG, ACTIVE_TRANSACTION):
        actual = _entry(root, name)
        if _entries_match(actual, entries[name]):
            continue
        if name == CURRENT:
            matches_post = (actual["type"] == "symlink"
                            and actual.get("target") == state["post_current_target"])
        elif name == APACHE_CONFIG:
            matches_post = (actual["type"] == "file" and actual.get("mode") == 0o644
                            and actual.get("sha256") == state["post_config_sha256"])
        else:
            matches_post = (actual["type"] == "file" and actual.get("mode") == 0o600
                            and actual.get("sha256") == deployment_complete.get("active_sha256"))
        if not matches_post:
            raise DeploymentError("rollback contains non-transaction drift; refusing resume")
    release = _device_path(root, RELEASES + "/" + state["release_id"])
    if state["created_release"]:
        temporary_release = _device_path(
            root, RELEASES + "/." + state["release_id"] + ".stage6-tmp"
        )
        if ((release.exists() or release.is_symlink())
                and (temporary_release.exists() or temporary_release.is_symlink())):
            raise DeploymentError("rollback contains both staged and published release trees")
        _verify_release_directory(release, state["release_manifest"], allow_missing=True)
        _verify_release_directory(temporary_release, state["release_manifest"], allow_missing=True)
    else:
        _verify_release_directory(release, state["release_manifest"])


def _recover_failed_deploy(root: Path, manifest: dict, payloads: dict[str, bytes],
                           created_release: bool, syntax_check, reload_apache) -> None:
    _restore_transaction(root, manifest, payloads, remove_release=created_release)
    if not syntax_check():
        raise DeploymentError("automatic deployment rollback restored files but syntax validation failed")
    if not reload_apache():
        raise DeploymentError("automatic deployment rollback restored files but Apache reload failed")


def deploy_simulated(root: Path | str, package: Path | str, backup_root: Path | str, *, fault: str | None = None,
                     syntax_check=lambda: True, reload_apache=lambda: True, modern_health=lambda: True) -> dict:
    root, package, backup_root = Path(root), Path(package), Path(backup_root)
    manifest_release, payloads, package_bytes = _read_release_snapshot(package)
    release_id = manifest_release["release_id"]
    transaction_id = uuid.uuid4().hex
    target_identity = _target_identity(root)
    # Discovery is read-only; reject attacks before creating the remote backup temporary area.
    _validate_chain(root, "/tmp", ("directory",))
    _validate_chain(root, RELEASES, ("directory",))
    _validate_chain(root, RELEASES + "/" + release_id, ("directory",))
    _validate_chain(root, CURRENT, ("symlink",))
    current_path = _device_path(root, CURRENT)
    if current_path.is_symlink():
        current_target = os.readlink(current_path)
        target_parts = PurePosixPath(current_target).parts
        if len(target_parts) != 2 or target_parts[0] != "releases" or target_parts[1] in (".", ".."):
            raise DeploymentError("unsafe current symlink target")
        _safe_release_id(target_parts[1])
    _validate_chain(root, APACHE_CONFIG, ("file",))
    _validate_chain(root, ACTIVE_TRANSACTION, ("file",))
    for temporary_name in (
        RELEASES + "/." + release_id + ".stage6-tmp",
        "/mnt/hdUser/pm3000-revive/webui/.current.stage6-tmp",
        "/etc/apache2/conf.d/.pm3000-revive.conf.stage6-tmp",
    ):
        if _entry(root, temporary_name)["type"] != "absent":
            raise DeploymentError(f"transaction temporary path already exists: {temporary_name}")
    package_sha256 = _sha256(package_bytes)
    backup_dir, backup_manifest, state, state_bytes = _create_backup(
        root, backup_root, release_id, package_sha256,
        manifest_release, transaction_id, target_identity, fault
    )
    verified_manifest, backup_payloads = _verify_backup(backup_dir)
    if verified_manifest != backup_manifest:
        raise DeploymentError("verified backup differs from inventory")
    events = backup_dir / "EVENTS"
    with events.open("a", encoding="ascii") as event_file:
        event_file.write("STAGE_PACKAGE\n")
        event_file.flush()
        os.fsync(event_file.fileno())
    stage = root / "tmp" / ("stage6-stage-" + backup_dir.name)
    stage.mkdir(mode=0o700)
    staged_package = stage / "release.tar"
    if fault == "mutate_package_after_backup":
        with package.open("ab") as mutable_package:
            mutable_package.write(b"changed-after-host-verification")
    if fault == "stage_copy":
        raise DeploymentError("injected staged package copy failure")
    _atomic_bytes(staged_package, package_bytes, 0o600)
    _atomic_bytes(
        staged_package.with_name("release.tar.sha256"),
        f"{package_sha256}  release.tar\n".encode("ascii"),
        0o600,
    )
    if fault == "stage_check":
        staged_package.with_name("release.tar.sha256").write_text("0" * 64 + "  release.tar\n", encoding="ascii")
    staged_manifest, staged_payloads = _read_release(staged_package)
    if staged_manifest != manifest_release or staged_payloads != payloads:
        raise DeploymentError("staged package differs from verified host package")
    releases = _device_path(root, RELEASES)
    release = releases / release_id
    created_release = state["created_release"]
    if created_release != (not release.exists()):
        raise DeploymentError("release path changed after backup")
    committed = False
    try:
        if staged_manifest != state["release_manifest"]:
            raise DeploymentError("staged manifest differs from backup-bound state")
        if fault == "state_publish":
            raise DeploymentError("injected deployment state publication failure")
        _atomic_bytes(backup_dir / "DEPLOYMENT_STATE.json", state_bytes, 0o600)
        if fault == "crash_after_state":
            os._exit(86)
        active_bytes = _canonical_json({
            "format": 1,
            "transaction_id": transaction_id,
            "deployment_state_sha256": _sha256(state_bytes),
            "backup_complete_sha256": _sha256((backup_dir / "BACKUP_COMPLETE").read_bytes()),
        })
        committed = True
        if fault == "active_publish":
            raise DeploymentError("injected active transaction publication failure")
        _atomic_bytes(_device_path(root, ACTIVE_TRANSACTION), active_bytes, 0o600)
        if fault == "crash_after_active":
            os._exit(87)
        releases.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(releases, 0o755)
        if created_release:
            temporary_release = releases / ("." + release_id + ".stage6-tmp")
            if temporary_release.exists() or temporary_release.is_symlink():
                raise DeploymentError(f"refusing existing transaction temporary path: {temporary_release}")
            temporary_release.mkdir(mode=0o755)
            if fault == "crash_after_temp_dir":
                os._exit(90)
            for index, entry in enumerate(staged_manifest["files"]):
                target = temporary_release / entry["path"]
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                os.chmod(target.parent, 0o755)
                _atomic_bytes(target, staged_payloads[entry["path"]], entry["mode"])
                if index == 0 and fault == "crash_after_first_payload":
                    os._exit(91)
            _atomic_bytes(temporary_release / "RELEASE_MANIFEST.json",
                          json.dumps(staged_manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n", 0o600)
            _atomic_bytes(
                temporary_release / "RELEASE_SHA256SUMS",
                "".join(
                    f"{entry['sha256']}  {entry['path']}\n" for entry in staged_manifest["files"]
                ).encode("ascii"),
                0o600,
            )
            os.replace(temporary_release, release)
            _fsync_dir(releases)
            if fault == "crash_after_release":
                os._exit(92)
        else:
            _verify_release_directory(release, staged_manifest)
        if fault == "after_release":
            raise DeploymentError("injected failure after release commit")
        _switch_symlink(_device_path(root, CURRENT), "releases/" + release_id)
        if fault == "crash_after_current":
            os._exit(88)
        if fault == "after_current":
            raise DeploymentError("injected failure after current commit")
        _atomic_bytes(_device_path(root, APACHE_CONFIG), staged_payloads["apache/pm3000-revive.conf"], 0o644)
        if fault == "crash_after_config":
            os._exit(89)
        if fault == "after_config":
            raise DeploymentError("injected failure after config commit")
        if not syntax_check():
            raise DeploymentError("Apache syntax check failed")
        if not reload_apache():
            raise DeploymentError("Apache reload failed")
        if not modern_health():
            raise DeploymentError("modern health check failed")
    except BaseException as deployment_failure:
        if committed:
            try:
                _recover_failed_deploy(root, backup_manifest, backup_payloads, created_release,
                                       syntax_check, reload_apache)
            except BaseException as rollback_failure:
                raise DeploymentError(
                    f"deployment failed and automatic rollback is incomplete: {rollback_failure}"
                ) from deployment_failure
        raise
    try:
        if fault == "complete_publish":
            raise DeploymentError("injected deployment completion publication failure")
        complete_bytes = json.dumps({
            "format": 1,
            "state_sha256": _sha256(state_bytes),
            "active_sha256": _sha256(active_bytes),
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        _atomic_bytes(backup_dir / "DEPLOYMENT_COMPLETE", complete_bytes, 0o600)
    except BaseException as publication_failure:
        try:
            _recover_failed_deploy(root, backup_manifest, backup_payloads, created_release,
                                   syntax_check, reload_apache)
        except BaseException as rollback_failure:
            raise DeploymentError(
                f"deployment publication failed and automatic rollback is incomplete: {rollback_failure}"
            ) from publication_failure
        raise
    return state


def rollback_simulated(root: Path | str, backup_dir: Path | str, *, syntax_check=lambda: True,
                       reload_apache=lambda: True, legacy_health=lambda: True) -> None:
    root, backup_dir = Path(root), Path(backup_dir)
    manifest, payloads = _verify_backup(backup_dir)
    state_path = backup_dir / "DEPLOYMENT_STATE.json"
    rolled_back = backup_dir / "ROLLBACK_COMPLETE"
    pending = backup_dir / "ROLLBACK_PENDING"
    try:
        state_bytes = state_path.read_bytes()
        state = json.loads(state_bytes)
    except (OSError, ValueError) as exc:
        raise DeploymentError("deployment state is missing or invalid") from exc
    expected_state_keys = {
        "format", "transaction_id", "target_identity", "release_id", "backup_dir",
        "created_release", "post_current_target", "post_config_sha256", "release_manifest",
    }
    if (not isinstance(state, dict) or set(state) != expected_state_keys or state.get("format") != 1
            or _sha256(state_bytes) != manifest.get("deployment_state_sha256")
            or _sha256(_canonical_json(state.get("release_manifest")))
            != manifest.get("release_manifest_sha256")):
        raise DeploymentError("deployment state integrity check failed")
    backup_complete_sha256 = _sha256((backup_dir / "BACKUP_COMPLETE").read_bytes())
    expected_active_bytes = _canonical_json({
        "format": 1,
        "transaction_id": state["transaction_id"],
        "deployment_state_sha256": _sha256(state_bytes),
        "backup_complete_sha256": backup_complete_sha256,
    })
    complete_path = backup_dir / "DEPLOYMENT_COMPLETE"
    deployment_complete_present = complete_path.exists()
    if deployment_complete_present:
        try:
            deployment_complete = json.loads(complete_path.read_bytes())
        except (OSError, ValueError) as exc:
            raise DeploymentError("deployment completion state is invalid") from exc
        if (set(deployment_complete) != {"format", "state_sha256", "active_sha256"}
                or deployment_complete.get("format") != 1
                or deployment_complete.get("state_sha256") != _sha256(state_bytes)
                or deployment_complete.get("active_sha256") != _sha256(expected_active_bytes)):
            raise DeploymentError("deployment state integrity check failed")
    else:
        deployment_complete = {"active_sha256": _sha256(expected_active_bytes)}
    if pending.exists():
        try:
            pending_state = json.loads(pending.read_bytes())
        except (OSError, ValueError) as exc:
            raise DeploymentError("rollback pending state is invalid") from exc
        if (pending_state.get("deployment_state_sha256") != _sha256(state_bytes)
                or pending_state.get("backup_complete_sha256") != backup_complete_sha256):
            raise DeploymentError("rollback pending state integrity check failed")
    elif not rolled_back.exists() and deployment_complete_present:
        try:
            active_bytes = _device_path(root, ACTIVE_TRANSACTION).read_bytes()
        except OSError as exc:
            raise DeploymentError("active transaction is missing or invalid") from exc
        if active_bytes != expected_active_bytes:
            raise DeploymentError("deployment state integrity check failed")
    if (state.get("release_id") != manifest.get("release_id")
            or state.get("transaction_id") != manifest.get("transaction_id")
            or state.get("target_identity") != manifest.get("target_identity")
            or _target_identity(root) != state.get("target_identity")):
        raise DeploymentError("deployment state does not match selected backup")
    if rolled_back.exists():
        try:
            rollback_complete = json.loads(rolled_back.read_bytes())
        except (OSError, ValueError) as exc:
            raise DeploymentError("rollback completion state is invalid") from exc
        if (set(rollback_complete) != {"format", "deployment_state_sha256", "backup_complete_sha256"}
                or rollback_complete["format"] != 1
                or rollback_complete["deployment_state_sha256"] != _sha256(state_bytes)
                or rollback_complete["backup_complete_sha256"] != backup_complete_sha256):
            raise DeploymentError("rollback completion state integrity check failed")
        _verify_restored_state(root, manifest, state)
        if pending.exists():
            pending.unlink()
            _fsync_dir(backup_dir)
        return
    if pending.exists():
        _verify_resumable_rollback_state(root, manifest, state, deployment_complete)
        _restore_transaction(root, manifest, payloads)
        _verify_restored_state(root, manifest, state)
    else:
        if deployment_complete_present:
            _verify_deployed_state(root, state)
        else:
            _verify_resumable_rollback_state(root, manifest, state, deployment_complete)
        for name, expected_types in (
            (RELEASES, ("directory",)),
            (CURRENT, ("symlink",)),
            (APACHE_CONFIG, ("file",)),
        ):
            if _entry(root, name)["type"] != "absent":
                _validate_chain(root, name, expected_types)
        pending_bytes = json.dumps({
            "format": 1,
            "deployment_state_sha256": _sha256(state_bytes),
            "backup_complete_sha256": _sha256((backup_dir / "BACKUP_COMPLETE").read_bytes()),
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        _atomic_bytes(pending, pending_bytes, 0o600)
        _restore_transaction(root, manifest, payloads)
        _verify_restored_state(root, manifest, state)
    if not syntax_check():
        raise DeploymentError("restored Apache syntax check failed; not reloading")
    if not reload_apache():
        raise DeploymentError("Apache reload after rollback failed")
    if not legacy_health():
        raise DeploymentError("legacy UI health check failed")
    rollback_complete_bytes = json.dumps({
        "format": 1,
        "deployment_state_sha256": _sha256(state_bytes),
        "backup_complete_sha256": backup_complete_sha256,
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _atomic_bytes(rolled_back, rollback_complete_bytes, 0o600)
    pending.unlink()
    _fsync_dir(backup_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package", help="build a checksummed allowlist release")
    package.add_argument("--source", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--release-id", required=True)
    package.add_argument("--git-revision", default="unknown")
    deploy = commands.add_parser("deploy-sim", help="deploy into an isolated synthetic root")
    deploy.add_argument("--root", type=Path, required=True)
    deploy.add_argument("--package", type=Path, required=True)
    deploy.add_argument("--backup-dir", type=Path, required=True)
    deploy.add_argument("--fault", choices=("backup_copy", "backup_digest", "backup_incomplete",
                                             "mutate_package_after_backup", "stage_copy", "stage_check",
                                             "after_release", "after_current", "after_config",
                                             "state_publish", "active_publish", "complete_publish",
                                             "crash_after_state", "crash_after_active",
                                             "crash_after_temp_dir", "crash_after_first_payload",
                                             "crash_after_release",
                                             "crash_after_current", "crash_after_config",
                                             "config_check", "reload", "health"))
    rollback = commands.add_parser("rollback-sim", help="rollback an isolated synthetic root")
    rollback.add_argument("--root", type=Path, required=True)
    rollback.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "package":
            build_release(args.source, args.output, args.release_id, args.git_revision)
        elif args.command == "deploy-sim":
            deploy_simulated(args.root, args.package, args.backup_dir, fault=args.fault,
                             syntax_check=lambda: args.fault != "config_check",
                             reload_apache=lambda: args.fault != "reload",
                             modern_health=lambda: args.fault != "health")
        elif args.command == "rollback-sim":
            rollback_simulated(args.root, args.backup)
        return 0
    except (DeploymentError, OSError, tarfile.TarError, ValueError) as exc:
        print(f"stage6: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
