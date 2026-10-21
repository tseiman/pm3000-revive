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
[[ -f "$package.sha256" && ! -L "$package.sha256" ]] || { echo "release sidecar missing or unsafe" >&2; exit 1; }
[[ -d "$backup" ]] || { echo "full backup directory missing" >&2; exit 1; }
for command in python3 ssh scp mktemp; do
    command -v "$command" >/dev/null 2>&1 || { echo "$command missing" >&2; exit 1; }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compatibility=$script_dir/stage7-device-compatibility.sh
device_installer=$script_dir/device-install.sh
[[ -x "$compatibility" && -f "$device_installer" && ! -L "$device_installer" ]] || {
    echo "deployment helpers missing or unsafe" >&2; exit 1;
}

local_work=$(mktemp -d /tmp/pm3-install.XXXXXX)
chmod 700 "$local_work"
control_path=$local_work/control
remote_work=/tmp/pm3000-install-$(date -u +%Y%m%dT%H%M%SZ)-$$
master_open=no
installed=no
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [[ "$master_open" == yes ]]; then
        if [[ "$installed" == yes ]]; then
            ssh "${ssh_options[@]}" "$target" "rm -rf '$remote_work'" >/dev/null 2>&1 || true
        else
            printf 'remote_diagnostics=%s\n' "$remote_work" >&2
        fi
        ssh "${ssh_options[@]}" -O exit "$target" >/dev/null 2>&1 || true
    fi
    rm -rf "$local_work"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

ssh_options=(-o ControlMaster=no -o ControlPath="$control_path")
scp_options=(-O -o ControlMaster=no -o ControlPath="$control_path")
ssh -o ControlMaster=yes -o ControlPath="$control_path" -o ControlPersist=60 -MNf "$target"
master_open=yes

# The existing check validates the full backup, archive allowlist, package digest,
# target PPC executables and CGI health without installing anything.
compatibility_output=$(PM3000_SSH_CONTROL_PATH=$control_path \
    "$compatibility" "$target" "$package" "$backup")
printf '%s\n' "$compatibility_output"
case "$compatibility_output" in *"compatibility.complete=yes"*"apply=no"*) :;;
    *) echo "device compatibility did not complete" >&2; exit 1;;
esac

metadata=$(python3 - "$package" "$package.sha256" "$local_work/release.tar" <<'PY'
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
snapshot = Path(sys.argv[3])
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
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        member = archive.getmember("RELEASE_MANIFEST.json")
        manifest = json.load(archive.extractfile(member))
except (KeyError, OSError, ValueError, tarfile.TarError) as exc:
    raise SystemExit(f"invalid release manifest: {exc}")
release_id = manifest.get("release_id")
if not isinstance(release_id, str) or not release_id or release_id in (".", "..") \
        or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in release_id):
    raise SystemExit("unsafe release id")
out = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(out, payload)
    os.fsync(out)
finally:
    os.close(out)
print(release_id)
print(digest.hexdigest())
PY
)
release_id=${metadata%%$'\n'*}
package_digest=${metadata##*$'\n'}
cp "$backup/BACKUP_COMPLETE" "$local_work/BACKUP_COMPLETE"
cp "$device_installer" "$local_work/device-install.sh"
chmod 600 "$local_work/BACKUP_COMPLETE" "$local_work/device-install.sh"

ssh "${ssh_options[@]}" "$target" "umask 077; mkdir '$remote_work'"
scp "${scp_options[@]}" \
    "$local_work/release.tar" "$local_work/BACKUP_COMPLETE" "$local_work/device-install.sh" \
    "$target:$remote_work/"
ssh "${ssh_options[@]}" "$target" sh -s "$remote_work" "$package_digest" "$release_id" <<'REMOTE'
set -eu
work=$1
expected=$2
release_id=$3
case "$work" in /tmp/pm3000-install-*) :;; *) echo "unsafe install directory" >&2; exit 2;; esac
[ -d "$work" ] && [ ! -L "$work" ] || { echo "install directory missing" >&2; exit 1; }
chmod 700 "$work/device-install.sh"
/bin/sh "$work/device-install.sh" "$work/release.tar" "$expected" "$release_id" "$work/BACKUP_COMPLETE"
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
health=$(REQUEST_METHOD=GET PATH_INFO=/health SCRIPT_NAME=/api/v1 HTTPS=on \
    /mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-rest)
case "$health" in *"Status: 200 OK"*'"apiVersion":"v1","status":"live"'*) :;;
    *) echo "installed REST health check failed" >&2; exit 1;;
esac
printf '%s\n' "install.complete=yes"
REMOTE
installed=yes
printf '%s\n' "release_id=$release_id" "package_sha256=$package_digest" "install.complete=yes"
