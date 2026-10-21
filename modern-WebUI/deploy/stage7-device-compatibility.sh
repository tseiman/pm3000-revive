#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 SSH_TARGET RELEASE_TAR FULL_BACKUP_DIRECTORY" >&2
    exit 2
}

[[ $# -eq 3 ]] || usage
target=$1
package=$2
backup=$3
case "$target" in ''|-*) echo "unsafe SSH target" >&2; exit 2;; esac
[[ -f "$package" && ! -L "$package" ]] || { echo "release package missing or unsafe" >&2; exit 1; }
[[ -d "$backup" ]] || { echo "full backup directory missing" >&2; exit 1; }
for command in python3 ssh scp mktemp; do
    command -v "$command" >/dev/null 2>&1 || { echo "$command missing" >&2; exit 1; }
done

transport_options=()
if [[ -n "${PM3000_SSH_CONTROL_PATH:-}" ]]; then
    [[ "$PM3000_SSH_CONTROL_PATH" = /* && "$PM3000_SSH_CONTROL_PATH" != *"'"* ]] || {
        echo "unsafe SSH control path" >&2; exit 2;
    }
    transport_options=(-o ControlMaster=no -o ControlPath="$PM3000_SSH_CONTROL_PATH")
fi

local_work=$(mktemp -d "${TMPDIR:-/tmp}/pm3000-stage7-compat-host.XXXXXX")
chmod 700 "$local_work"
package_snapshot=$local_work/release.tar
remote=
remote_created=no
cleanup() {
    if [[ "$remote_created" == yes ]]; then
        ssh "${transport_options[@]}" "$target" "rm -rf '$remote'" >/dev/null 2>&1 || true
    fi
    rm -rf "$local_work"
}
trap cleanup EXIT HUP INT TERM

package_digest=$(python3 - "$package" "$backup" "$target" "$package_snapshot" <<'PY'
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

package = Path(sys.argv[1])
backup = Path(sys.argv[2])
target = sys.argv[3]
snapshot = Path(sys.argv[4])

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

archive_path = backup / "BACKUP_ARCHIVE.tar"
manifest_path = backup / "BACKUP_MANIFEST.json"
marker_path = backup / "BACKUP_COMPLETE"
if not all(path.is_file() and not path.is_symlink()
           for path in (archive_path, manifest_path, marker_path)):
    raise SystemExit("full backup files are missing or unsafe")
try:
    marker = marker_path.read_text(encoding="ascii").splitlines()
except OSError as exc:
    raise SystemExit(f"invalid BACKUP_COMPLETE: {exc}")
if len(marker) != 2 or any(len(value) != 64 or set(value) - set("0123456789abcdef")
                           for value in marker):
    raise SystemExit("invalid BACKUP_COMPLETE")
archive_hash, manifest_hash = marker
if digest(archive_path) != archive_hash or digest(manifest_path) != manifest_hash:
    raise SystemExit("full backup digest mismatch")
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit(f"invalid full backup manifest: {exc}")
if manifest.get("format") != 3 or manifest.get("archive_sha256") != archive_hash:
    raise SystemExit("unsupported or inconsistent full backup manifest")
if manifest.get("target") != target:
    raise SystemExit("full backup target does not match requested SSH target")

sidecar = Path(str(package) + ".sha256")
try:
    fields = sidecar.read_text().split()
except OSError as exc:
    raise SystemExit(f"release sidecar unavailable: {exc}")
if len(fields) != 2 or fields[1] != package.name or len(fields[0]) != 64 \
        or set(fields[0]) - set("0123456789abcdef"):
    raise SystemExit("invalid release sidecar")
descriptor = os.open(package, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("release package is not a trusted single-link regular file")
    with os.fdopen(descriptor, "rb", closefd=False) as source:
        package_bytes = source.read()
        after = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (
    value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
    value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
)
if identity(before) != identity(after) or len(package_bytes) != before.st_size:
    raise SystemExit("release package changed while reading")
actual = hashlib.sha256(package_bytes).hexdigest()
if actual != fields[0]:
    raise SystemExit("release package digest mismatch")
expected_members = {
    "RELEASE_MANIFEST.json": 0o600,
    "RELEASE_SHA256SUMS": 0o600,
    "apache/pm3000-revive.conf": 0o644,
    "bin/pm3000-atomic-publish": 0o755,
    "bin/pm3000-rest": 0o755,
    "web/app.js": 0o644,
    "web/index.html": 0o644,
    "web/styles.css": 0o644,
}
try:
    with tarfile.open(fileobj=io.BytesIO(package_bytes), mode="r:") as archive:
        members = archive.getmembers()
except (OSError, tarfile.TarError) as exc:
    raise SystemExit(f"invalid release archive: {exc}")
if [member.name for member in members] != list(expected_members):
    raise SystemExit("release archive allowlist mismatch")
for member in members:
    if not member.isfile() or member.linkname or member.mode != expected_members[member.name] \
            or member.uid != 0 or member.gid != 0:
        raise SystemExit(f"unsafe release member metadata: {member.name}")
snapshot_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(snapshot_fd, "wb", closefd=False) as output:
        output.write(package_bytes)
        output.flush()
        os.fsync(snapshot_fd)
finally:
    os.close(snapshot_fd)
print(actual)
PY
)

remote=/tmp/pm3000-stage7-compat-$(date -u +%Y%m%dT%H%M%SZ)-$$
ssh "${transport_options[@]}" "$target" "umask 077; mkdir '$remote'"
remote_created=yes
scp -O "${transport_options[@]}" "$package_snapshot" "$target:$remote/release.tar"

ssh "${transport_options[@]}" "$target" sh -s "$remote" "$package_digest" <<'REMOTE'
set -eu
umask 077
work=$1
expected=$2
cleanup() { rm -rf "$work"; }
trap cleanup 0 1 2 15
case "$work" in /tmp/pm3000-stage7-compat-*) :;; *) echo "unsafe compatibility directory" >&2; exit 2;; esac
[ -d "$work" ] && [ ! -L "$work" ] || { echo "compatibility directory missing" >&2; exit 1; }
[ -f "$work/release.tar" ] && [ ! -L "$work/release.tar" ] || { echo "release upload missing" >&2; exit 1; }
actual=$(openssl dgst -sha256 "$work/release.tar" | sed 's/^.*= //')
[ "$actual" = "$expected" ] || { echo "uploaded release digest mismatch" >&2; exit 1; }

cat >"$work/expected-members" <<'EOF_MEMBERS'
RELEASE_MANIFEST.json
RELEASE_SHA256SUMS
apache/pm3000-revive.conf
bin/pm3000-atomic-publish
bin/pm3000-rest
web/app.js
web/index.html
web/styles.css
EOF_MEMBERS
tar tf "$work/release.tar" >"$work/archive-members"
cmp "$work/archive-members" "$work/expected-members" >/dev/null 2>&1 || {
    echo "release archive allowlist mismatch" >&2; exit 1;
}
mkdir "$work/release"
(cd "$work/release" && tar xf "$work/release.tar")
chmod 755 "$work/release" "$work/release/apache" "$work/release/bin" "$work/release/web"
chmod 600 "$work/release/RELEASE_MANIFEST.json" "$work/release/RELEASE_SHA256SUMS"
chmod 644 "$work/release/apache/pm3000-revive.conf" \
    "$work/release/web/app.js" "$work/release/web/index.html" "$work/release/web/styles.css"
chmod 755 "$work/release/bin/pm3000-atomic-publish" "$work/release/bin/pm3000-rest"
helper=$work/release/bin/pm3000-atomic-publish
rest=$work/release/bin/pm3000-rest
"$helper" --verify-regular "$helper"
"$helper" --verify-regular "$rest"
"$helper" --verify-release "$work/release"
"$helper" --verify-private-directory /mnt/hdUser/pm3000-revive/rest
"$helper" --verify-private-directory /etc/pm3000-rest
"$helper" --verify-private-regular /mnt/hdUser/pm3000-revive/rest/tokens.json
"$helper" --verify-private-regular /mnt/hdUser/pm3000-revive/rest/tokens.json.lock
"$helper" --verify-private-regular /etc/pm3000-rest/controller.credentials
health=$(REQUEST_METHOD=GET PATH_INFO=/health SCRIPT_NAME=/api/v1 HTTPS=on "$rest")
case "$health" in *"Status: 200 OK"*'"apiVersion":"v1","status":"live"'*) :;;
    *) echo "REST health compatibility check failed" >&2; exit 1;;
esac
printf '%s\n' "device_machine=$(uname -m)"
printf '%s\n' "release_sha256=$actual"
printf '%s\n' "atomic_helper.compatible=yes"
printf '%s\n' "rest_health.compatible=yes"
printf '%s\n' "compatibility.complete=yes"
REMOTE

remote_created=no
rm -rf "$local_work"
trap - EXIT HUP INT TERM
printf '%s\n' "package_sha256=$package_digest"
printf '%s\n' "apply=no"
