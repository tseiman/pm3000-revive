#!/usr/bin/env python3
"""Build a deterministic, relative-path PM3000 installer ZIP."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile

RELEASE_NAMES = [
    "RELEASE_MANIFEST.json",
    "RELEASE_SHA256SUMS",
    "apache/listen.conf",
    "apache/pm3000-revive.conf",
    "bin/pm3000-acme",
    "bin/pm3000-acme-admin",
    "bin/pm3000-atomic-publish",
    "bin/pm3000-gsp-session-helper",
    "bin/pm3000-rest",
    "web/app.js",
    "web/index.html",
    "web/styles.css",
]
RELEASE_MODES = [0o600, 0o600, 0o644, 0o644, 0o755, 0o4750, 0o755, 0o4750, 0o755, 0o644, 0o644, 0o644]
SCRIPT_NAMES = [
    "device-install.sh",
    "device-rollback.sh",
    "post-install-read-only-acceptance.sh",
    "stage7-first-backup.sh",
    "stage7-install.sh",
]
PREFIX = "pm3000-installer"
MANAGED_LISTEN_SHA256 = "45c0c16bafde886b8079a1a43047dc85352a164b923b369f9dc1e04cd6e5557f"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_sidecar(path, release):
    fields = path.read_text(encoding="ascii").split()
    if len(fields) != 2 or fields[1] != release.name or len(fields[0]) != 64:
        raise ValueError("invalid release sidecar")
    if set(fields[0]) - set("0123456789abcdef"):
        raise ValueError("invalid release sidecar digest")
    return fields[0]


def verify_release(release, accepted_acme_sha256):
    payload = release.read_bytes()
    sidecar = Path(str(release) + ".sha256")
    if not sidecar.is_file() or sidecar.is_symlink():
        raise ValueError("release sidecar missing or unsafe")
    expected = parse_sidecar(sidecar, release)
    if sha256(payload) != expected:
        raise ValueError("release sidecar digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != RELEASE_NAMES:
            raise ValueError("release member order mismatch")
        for member, mode in zip(members, RELEASE_MODES):
            if not member.isfile() or member.linkname or member.uid != 0 or member.gid != 0:
                raise ValueError(f"unsafe release member metadata: {member.name}")
            if member.mode != mode:
                raise ValueError(f"release member mode mismatch: {member.name}")
        blobs = {}
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"unreadable release member: {member.name}")
            blobs[member.name] = stream.read()
    sums = blobs["RELEASE_SHA256SUMS"].decode("ascii").splitlines()
    expected_sum_names = RELEASE_NAMES[2:]
    if len(sums) != len(expected_sum_names):
        raise ValueError("release checksum count mismatch")
    for line, name in zip(sums, expected_sum_names):
        if line != f"{sha256(blobs[name])}  {name}":
            raise ValueError(f"release checksum mismatch: {name}")
    if sha256(blobs["bin/pm3000-acme"]) != accepted_acme_sha256:
        raise ValueError("accepted ACME hash mismatch")
    if sha256(blobs["apache/listen.conf"]) != MANAGED_LISTEN_SHA256:
        raise ValueError("managed listen.conf hash mismatch")
    manifest = json.loads(blobs["RELEASE_MANIFEST.json"].decode("utf-8"))
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise ValueError("invalid embedded release id")
    matches = re.findall(rb"Build " + re.escape(release_id.encode("ascii")) + rb" \(([0-9a-f]{12})\)", blobs["web/index.html"])
    if len(matches) != 1:
        raise ValueError("invalid embedded Git revision")
    revision = matches[0].decode("ascii")
    provenance = f"Build {release_id} ({revision})".encode("ascii")
    if provenance not in blobs["web/index.html"] or b"__PM3000_" in blobs["web/index.html"]:
        raise ValueError("embedded web provenance mismatch")
    return payload, sidecar.read_bytes(), expected, release_id, revision


def verifier_source(release_name, accepted_sha256):
    return f'''#!/usr/bin/env python3
import hashlib, io, json, os, re
from pathlib import Path
import stat, sys, tarfile
ROOT = Path(__file__).resolve().parent
RELEASE = "release/{release_name}"
ACME_SHA256 = "{accepted_sha256}"
LISTEN_SHA256 = "{MANAGED_LISTEN_SHA256}"
EXPECTED = [
    "README.md", "release/{release_name}", "release/{release_name}.sha256",
    "scripts/device-install.sh", "scripts/device-rollback.sh",
    "scripts/post-install-read-only-acceptance.sh", "scripts/stage7-first-backup.sh",
    "scripts/stage7-install.sh",
]
TAR_NAMES = {RELEASE_NAMES!r}
TAR_MODES = {RELEASE_MODES!r}
def fail(message):
    print(message, file=sys.stderr); raise SystemExit(1)
def digest(data): return hashlib.sha256(data).hexdigest()
try:
    lines = (ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines()
except (OSError, UnicodeDecodeError) as exc: fail(f"cannot read checksum manifest: {{exc}}")
if len(lines) != len(EXPECTED): fail("bundle checksum count mismatch")
for line, name in zip(lines, EXPECTED):
    path = ROOT / name
    if not path.is_file() or path.is_symlink(): fail(f"unsafe bundle member: {{name}}")
    expected = line[:64]
    if line != f"{{expected}}  {{name}}" or len(expected) != 64 or set(expected) - set("0123456789abcdef"):
        fail("invalid bundle checksum manifest")
    if digest(path.read_bytes()) != expected: fail(f"bundle checksum mismatch: {{name}}")
release_path = ROOT / RELEASE
sidecar = Path(str(release_path) + ".sha256")
fields = sidecar.read_text(encoding="ascii").split()
payload = release_path.read_bytes()
if len(fields) != 2 or fields[1] != release_path.name or fields[0] != digest(payload): fail("release sidecar mismatch")
try:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
        if [m.name for m in members] != TAR_NAMES: fail("release member order mismatch")
        blobs = {{}}
        for member, mode in zip(members, TAR_MODES):
            if not member.isfile() or member.linkname or member.uid != 0 or member.gid != 0 or member.mode != mode:
                fail(f"release metadata mismatch: {{member.name}}")
            blobs[member.name] = archive.extractfile(member).read()
except (OSError, tarfile.TarError) as exc: fail(f"invalid release archive: {{exc}}")
sums = blobs["RELEASE_SHA256SUMS"].decode("ascii").splitlines()
if len(sums) != 10: fail("release checksum count mismatch")
for line, name in zip(sums, TAR_NAMES[2:]):
    if line != f"{{digest(blobs[name])}}  {{name}}": fail(f"release checksum mismatch: {{name}}")
if digest(blobs["bin/pm3000-acme"]) != ACME_SHA256: fail("accepted ACME hash mismatch")
if digest(blobs["apache/listen.conf"]) != LISTEN_SHA256: fail("managed listen.conf hash mismatch")
manifest = json.loads(blobs["RELEASE_MANIFEST.json"].decode("utf-8"))
rid = manifest.get("release_id")
if not isinstance(rid, str) or not rid:
    fail("invalid embedded provenance")
matches = re.findall(rb"Build " + re.escape(rid.encode("ascii")) + rb" \(([0-9a-f]{{12}})\)", blobs["web/index.html"])
if len(matches) != 1: fail("invalid embedded provenance")
rev = matches[0].decode("ascii")
if f"Build {{rid}} ({{rev}})".encode("ascii") not in blobs["web/index.html"] or b"__PM3000_" in blobs["web/index.html"]:
    fail("embedded web provenance mismatch")
print(f"release_id={{rid}}")
print(f"git_revision={{rev}}")
print(f"release_sha256={{digest(payload)}}")
print(f"accepted_acme_sha256={{ACME_SHA256}}")
print("bundle.verify.complete=yes")
'''.encode("ascii")


def readme(release_name, release_id, release_sha, accepted_sha):
    return f"""# PM3000 Modern WebUI + ACME local installer

This bundle is relative-path and works with Python 3, Bash, OpenSSH, and tar on
macOS or Linux. It does not install anything merely by being unpacked or verified.
The packaged ACME CLI is the physically accepted production binary, SHA-256
`{accepted_sha}`. No scheduler is included.

## 1. Verify after extracting the ZIP

```sh
cd pm3000-installer
python3 ./verify.py
```

Require `bundle.verify.complete=yes`, release `{release_id}`, and release SHA-256
`{release_sha}` before continuing.

## 2. Make the full backup (device read; private host writes)

```sh
./scripts/stage7-first-backup.sh --target root@CERTIFICATE_VALID_HOST --backup-dir ./backup
```

Record the exact completed directory printed by the command. Require
`backup_complete=yes` before installation.

## 3. Install during an approved maintenance window (device writes)

```sh
./scripts/stage7-install.sh root@CERTIFICATE_VALID_HOST \
  ./release/{release_name} \
  ./backup/stage7-full-backup-YYYYMMDDTHHMMSSZ-PID
```

This is the activation boundary: it stages the release, updates the active
pointer and Apache fragment, reloads Apache, and rolls back automatically on a
failed activation/health gate. Require `install.complete=yes`. Do not run the
standalone `device-install.sh` directly.

## 4. Prove the installed ACME page reports a closed state (read-only)

Export the authenticated browser session to a private Netscape-format cookie
jar without sharing it, then run:

```sh
chmod 600 /private/path/pm3000-cookies.txt
./scripts/post-install-read-only-acceptance.sh \
  root@CERTIFICATE_VALID_HOST {release_id} \
  https://CERTIFICATE_VALID_HOST /private/path/pm3000-cookies.txt
```

Require `acme_http_projection=configured|unconfigured` (one literal value,
showing that the response matched the exact configured or unconfigured projection) and
`post_install_read_only_acceptance.complete=yes`. The script validates TLS,
does not print the cookie or response body, and explicitly removes its local
temporary response. Delete the cookie jar or sign out after acceptance.

## Rollback

The installer automatically restores the prior pointer/configuration on any
failed activation gate. `scripts/device-rollback.sh` is included for a bounded,
operator-reviewed recovery using pre-staged transaction state; it is not a
standalone host command and must not be run ad hoc. Preserve the completed full
backup and failed installer diagnostics path for recovery.

No command here performs ACME renewal or creates a schedule. Real CA/config
writes and renewal require a separate explicit operator action.
""".encode("utf-8")


def add_zip(archive, name, data, mode):
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((stat.S_IFREG | mode) << 16)
    archive.writestr(info, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--accepted-acme-sha256", required=True)
    args = parser.parse_args()
    if len(args.accepted_acme_sha256) != 64 or set(args.accepted_acme_sha256) - set("0123456789abcdef"):
        parser.error("invalid accepted ACME SHA-256")
    if args.output.exists():
        parser.error("output already exists")
    deploy = Path(__file__).resolve().parent
    payload, sidecar, release_sha, release_id, revision = verify_release(args.release, args.accepted_acme_sha256)
    files = {
        "README.md": readme(args.release.name, release_id, release_sha, args.accepted_acme_sha256),
        f"release/{args.release.name}": payload,
        f"release/{args.release.name}.sha256": sidecar,
    }
    for name in SCRIPT_NAMES:
        path = deploy / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"installer source missing or unsafe: {name}")
        files[f"scripts/{name}"] = path.read_bytes()
    checksum_order = ["README.md", f"release/{args.release.name}", f"release/{args.release.name}.sha256"] + [f"scripts/{name}" for name in SCRIPT_NAMES]
    checksums = "".join(f"{sha256(files[name])}  {name}\n" for name in checksum_order).encode("ascii")
    verifier = verifier_source(args.release.name, args.accepted_acme_sha256)
    ordered = [
        ("README.md", files["README.md"], 0o644),
        ("SHA256SUMS", checksums, 0o644),
        ("verify.py", verifier, 0o755),
        (f"release/{args.release.name}", payload, 0o644),
        (f"release/{args.release.name}.sha256", sidecar, 0o644),
    ] + [(f"scripts/{name}", files[f"scripts/{name}"], 0o755) for name in SCRIPT_NAMES]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for name, data, mode in ordered:
                add_zip(archive, f"{PREFIX}/{name}", data, mode)
        os.replace(temporary, args.output)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(f"zip={args.output}")
    print(f"zip_sha256={sha256(args.output.read_bytes())}")
    print(f"release_sha256={release_sha}")
    print(f"release_id={release_id}")
    print(f"git_revision={revision}")
    print("bundle.build.complete=yes")


if __name__ == "__main__":
    main()
