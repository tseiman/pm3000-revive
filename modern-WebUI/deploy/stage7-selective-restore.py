#!/usr/bin/env python3
"""Validate a Stage 7 full backup and prepare narrowly scoped restore artifacts."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import sys
import tarfile


PROFILES = {
    "legacy-webui": ("usr/share/apache2/htdocs",),
    "modern-webui": (
        "mnt/hdUser/pm3000-revive/webui",
        "etc/apache2/conf.d/pm3000-revive.conf",
        "etc/apache2/conf.d/listen.conf",
    ),
    "apache": ("etc/apache2",),
}


class RestoreError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_member(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or ".." in pure.parts:
        raise RestoreError(f"unsafe archive member: {name}")
    return name


def load_backup(directory: Path) -> tuple[Path, dict, list[str]]:
    archive_path = directory / "BACKUP_ARCHIVE.tar"
    manifest_path = directory / "BACKUP_MANIFEST.json"
    marker_path = directory / "BACKUP_COMPLETE"
    if not all(path.is_file() and not path.is_symlink() for path in (archive_path, manifest_path, marker_path)):
        raise RestoreError("backup files are missing or unsafe")
    marker = marker_path.read_text(encoding="ascii").splitlines()
    if len(marker) != 2 or any(len(value) != 64 or set(value) - set("0123456789abcdef") for value in marker):
        raise RestoreError("invalid BACKUP_COMPLETE")
    archive_hash, manifest_hash = marker
    if sha256(archive_path) != archive_hash or sha256(manifest_path) != manifest_hash:
        raise RestoreError("backup digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != 3 or manifest.get("archive_sha256") != archive_hash:
        raise RestoreError("unsupported or inconsistent backup manifest")
    manifest_names = [entry.get("path") for entry in manifest.get("entries", [])]
    if not manifest_names or any(not isinstance(name, str) for name in manifest_names):
        raise RestoreError("invalid backup manifest entries")
    with tarfile.open(archive_path, "r:") as archive:
        archive_names = [normalize_member(member.name) for member in archive]
    if len(archive_names) != len(set(archive_names)) or archive_names != manifest_names:
        raise RestoreError("archive and manifest member lists differ")
    return archive_path, manifest, archive_names


def selected_names(names: list[str], profile: str) -> list[str]:
    prefixes = PROFILES[profile]
    return [
        name for name in names
        if any(name == prefix or name.startswith(prefix + "/") for prefix in prefixes)
    ]


def prepare_artifact(source_path: Path, selected: list[str], output_path: Path) -> str:
    if output_path.exists() or output_path.is_symlink():
        raise RestoreError("restore artifact already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.{secrets.token_hex(8)}.tmp")
    selected_set = set(selected)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w+b") as raw_output:
            with tarfile.open(source_path, "r:") as source, tarfile.open(
                    fileobj=raw_output, mode="w", format=tarfile.PAX_FORMAT) as destination:
                for member in source:
                    normalized = normalize_member(member.name)
                    if normalized not in selected_set:
                        continue
                    output_member = copy.copy(member)
                    output_member.name = normalized
                    payload = source.extractfile(member) if member.isfile() else None
                    destination.addfile(output_member, payload)
            raw_output.flush()
            os.fsync(raw_output.fileno())
        os.replace(temporary, output_path)
        parent_descriptor = os.open(output_path.parent, os.O_RDONLY)
        try:
            try:
                os.fsync(parent_descriptor)
            except OSError:
                pass
        finally:
            os.close(parent_descriptor)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return sha256(output_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--prepare", type=Path)
    arguments = parser.parse_args(argv)
    try:
        _archive, _manifest, names = load_backup(arguments.backup)
        selected = selected_names(names, arguments.profile)
        if not selected:
            raise RestoreError(f"profile {arguments.profile} has no payload in this backup")
        print(f"profile={arguments.profile}")
        print(f"members={len(selected)}")
        for name in selected:
            print(name)
        if arguments.prepare is not None:
            artifact_hash = prepare_artifact(_archive, selected, arguments.prepare)
            print(f"restore_artifact={arguments.prepare}")
            print(f"restore_sha256={artifact_hash}")
        print("apply=no")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError, RestoreError) as error:
        print(f"stage7-selective-restore: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
