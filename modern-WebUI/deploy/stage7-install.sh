#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 SSH_TARGET RELEASE_TAR FULL_BACKUP_DIRECTORY" >&2
    exit 2
}

log() {
    printf '[stage7] %s\n' "$*"
}

[[ $# -eq 3 ]] || usage
target=$1
package=$2
backup=$3
case "$target" in ''|-*) echo "unsafe SSH target" >&2; exit 2;; esac
[[ -f "$package" && ! -L "$package" ]] || { echo "release package missing or unsafe" >&2; exit 1; }
[[ -f "$package.sha256" && ! -L "$package.sha256" ]] || { echo "release sidecar missing or unsafe" >&2; exit 1; }
[[ -d "$backup" ]] || { echo "full backup directory missing" >&2; exit 1; }
for command in python3 ssh mktemp tar; do
    command -v "$command" >/dev/null 2>&1 || { echo "$command missing" >&2; exit 1; }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
device_installer=$script_dir/device-install.sh
[[ -f "$device_installer" && ! -L "$device_installer" ]] || {
    echo "deployment helper missing or unsafe" >&2; exit 1;
}

local_work=$(mktemp -d "${TMPDIR:-/tmp}/pm3-install.XXXXXX")
chmod 700 "$local_work"
remote_work=/tmp/pm3000-install-$(date -u +%Y%m%dT%H%M%SZ)-$$
installed=no
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [[ "$installed" != yes && "$status" -ne 0 ]]; then
        printf 'remote_diagnostics=%s\n' "$remote_work" >&2
    fi
    rm -rf "$local_work"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

log "Validating the release package and full backup locally"
metadata=$(python3 - "$package" "$package.sha256" "$backup" "$target" \
    "$local_work/release.tar" "$local_work/BACKUP_COMPLETE" <<'PY'
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

source = Path(sys.argv[1])
sidecar = Path(sys.argv[2])
backup = Path(sys.argv[3])
target = sys.argv[4]
snapshot = Path(sys.argv[5])
marker_snapshot = Path(sys.argv[6])

def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

archive_path = backup / "BACKUP_ARCHIVE.tar"
manifest_path = backup / "BACKUP_MANIFEST.json"
marker_path = backup / "BACKUP_COMPLETE"
if not all(path.is_file() and not path.is_symlink()
           for path in (archive_path, manifest_path, marker_path)):
    raise SystemExit("full backup files are missing or unsafe")
try:
    marker_bytes = marker_path.read_bytes()
    marker = marker_bytes.decode("ascii").splitlines()
except (OSError, UnicodeDecodeError) as exc:
    raise SystemExit(f"invalid BACKUP_COMPLETE: {exc}")
if len(marker) != 2 or any(len(value) != 64 or set(value) - set("0123456789abcdef")
                           for value in marker):
    raise SystemExit("invalid BACKUP_COMPLETE")
archive_hash, manifest_hash = marker
if digest_file(archive_path) != archive_hash or digest_file(manifest_path) != manifest_hash:
    raise SystemExit("full backup digest mismatch")
try:
    backup_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit(f"invalid full backup manifest: {exc}")
if backup_manifest.get("format") != 3 or backup_manifest.get("archive_sha256") != archive_hash:
    raise SystemExit("unsupported or inconsistent full backup manifest")
if backup_manifest.get("target") != target:
    raise SystemExit("full backup target does not match requested SSH target")

fields = sidecar.read_text(encoding="ascii").split()
if len(fields) != 2 or fields[1] != source.name or len(fields[0]) != 64 \
        or set(fields[0]) - set("0123456789abcdef"):
    raise SystemExit("invalid release sidecar")
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("release package is not a trusted regular file")
    chunks = []
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
        digest.update(chunk)
    after = os.fstat(fd)
finally:
    os.close(fd)
identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                          value.st_uid, value.st_gid, value.st_size,
                          value.st_mtime_ns, value.st_ctime_ns)
if identity(before) != identity(after) or digest.hexdigest() != fields[0]:
    raise SystemExit("release package changed or has an invalid digest")
payload = b"".join(chunks)
try:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as release:
        member = release.getmember("RELEASE_MANIFEST.json")
        release_manifest = json.load(release.extractfile(member))
except (KeyError, OSError, ValueError, tarfile.TarError) as exc:
    raise SystemExit(f"invalid release manifest: {exc}")
release_id = release_manifest.get("release_id")
if not isinstance(release_id, str) or not release_id or release_id in (".", "..") \
        or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in release_id):
    raise SystemExit("unsafe release id")
for path, data in ((snapshot, payload), (marker_snapshot, marker_bytes)):
    out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(out, data)
        os.fsync(out)
    finally:
        os.close(out)
print(release_id)
print(digest.hexdigest())
PY
)
release_id=${metadata%%$'\n'*}
package_digest=${metadata##*$'\n'}
cp "$device_installer" "$local_work/device-install.sh"
chmod 600 "$local_work/device-install.sh"

cat >"$local_work/remote-install.sh" <<'REMOTE'
#!/bin/sh
set -eu
umask 077
work=$1
expected=$2
release_id=$3
log() { printf '[stage7:device] %s\n' "$*"; }
case "$work" in /tmp/pm3000-install-*) :;; *) echo "unsafe install directory" >&2; exit 2;; esac
[ -d "$work" ] && [ ! -L "$work" ] || { echo "install directory missing" >&2; exit 1; }
[ -f "$work/release.tar" ] && [ ! -L "$work/release.tar" ] || { echo "release upload missing" >&2; exit 1; }
[ -f "$work/BACKUP_COMPLETE" ] && [ ! -L "$work/BACKUP_COMPLETE" ] || { echo "backup marker missing" >&2; exit 1; }
[ -f "$work/device-install.sh" ] && [ ! -L "$work/device-install.sh" ] || { echo "device installer missing" >&2; exit 1; }

log "Verifying uploaded release checksum"
actual=$(openssl dgst -sha256 "$work/release.tar" | sed 's/^.*= //')
[ "$actual" = "$expected" ] || { echo "uploaded release digest mismatch" >&2; exit 1; }

log "Checking release archive allowlist"
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

log "Checking private runtime ownership and permissions"
daemon_uid=$(id -u daemon)
case "$daemon_uid" in ''|*[!0-9]*) echo "invalid Apache daemon account" >&2; exit 1;; esac
"$helper" --verify-private-directory /mnt/hdUser/pm3000-revive/rest 2>/dev/null ||
    "$helper" --verify-private-directory-owner /mnt/hdUser/pm3000-revive/rest "$daemon_uid"
"$helper" --verify-private-directory /etc/pm3000-rest 2>/dev/null ||
    "$helper" --verify-private-directory-owner /etc/pm3000-rest "$daemon_uid"
"$helper" --verify-private-regular /mnt/hdUser/pm3000-revive/rest/tokens.json 2>/dev/null ||
    "$helper" --verify-private-regular-owner /mnt/hdUser/pm3000-revive/rest/tokens.json "$daemon_uid"
"$helper" --verify-private-regular /mnt/hdUser/pm3000-revive/rest/tokens.json.lock 2>/dev/null ||
    "$helper" --verify-private-regular-owner /mnt/hdUser/pm3000-revive/rest/tokens.json.lock "$daemon_uid"
"$helper" --verify-private-regular /etc/pm3000-rest/controller.credentials 2>/dev/null ||
    "$helper" --verify-private-regular-owner /etc/pm3000-rest/controller.credentials "$daemon_uid"

log "Running read-only PPC/CGI compatibility health check"
health=$(REQUEST_METHOD=GET PATH_INFO=/health SCRIPT_NAME=/api/v1 HTTPS=on "$rest")
case "$health" in *"Status: 200 OK"*'"apiVersion":"v1","status":"live"'*) :;;
    *) echo "REST health compatibility check failed" >&2; exit 1;;
esac
printf '%s\n' "device_machine=$(uname -m)"
printf '%s\n' "release_sha256=$actual"
printf '%s\n' "atomic_helper.compatible=yes"
printf '%s\n' "rest_health.compatible=yes"
printf '%s\n' "compatibility.complete=yes"
printf '%s\n' "apply=no"

log "Installing release $release_id"
chmod 700 "$work/device-install.sh"
/bin/sh "$work/device-install.sh" "$work/release.tar" "$expected" "$release_id" "$work/BACKUP_COMPLETE"

log "Validating Apache configuration"
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
log "Checking the activated REST health endpoint"
health=$(REQUEST_METHOD=GET PATH_INFO=/health SCRIPT_NAME=/api/v1 HTTPS=on \
    /mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-rest)
case "$health" in *"Status: 200 OK"*'"apiVersion":"v1","status":"live"'*) :;;
    *) echo "installed REST health check failed" >&2; exit 1;;
esac
printf '%s\n' "release_id=$release_id" "package_sha256=$expected" "install.complete=yes"
log "Removing temporary installation files"
rm -rf "$work"
REMOTE
chmod 600 "$local_work/remote-install.sh"

log "Preparing a single-stream installation payload for $release_id"
log "Opening one non-multiplexed SSH connection to $target (one password prompt expected)"
(
    cd "$local_work"
    tar cf - release.tar BACKUP_COMPLETE device-install.sh remote-install.sh
) | ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no "$target" \
    "umask 077; mkdir '$remote_work' && cd '$remote_work' && tar xf - && /bin/sh ./remote-install.sh '$remote_work' '$package_digest' '$release_id'"
installed=yes
log "Installation completed successfully"
printf '%s\n' "release_id=$release_id" "package_sha256=$package_digest" "install.complete=yes"
