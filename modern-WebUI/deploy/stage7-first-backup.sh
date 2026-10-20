#!/usr/bin/env bash
# Create a private first-install backup record on the Mac using read-only SSH probes.
set -euo pipefail
umask 077

target=
backup_parent=
while (($#)); do
    case "$1" in
        --target) target=${2:?missing SSH target}; shift 2 ;;
        --backup-dir) backup_parent=${2:?missing backup directory}; shift 2 ;;
        --help)
            printf '%s\n' 'usage: stage7-first-backup.sh --target USER@HOST --backup-dir ABSOLUTE_DIRECTORY'
            exit 0
            ;;
        *) printf 'stage7-first-backup.sh: unsupported argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

[[ -n $target && -n $backup_parent ]] || { printf '%s\n' 'target and backup directory are required' >&2; exit 2; }
case "$target" in ''|*[!A-Za-z0-9._@:-]*|-*) printf '%s\n' 'unsafe SSH target' >&2; exit 2;; esac
case "$backup_parent" in /*) :;; *) printf '%s\n' 'backup directory must be absolute' >&2; exit 2;; esac

if [[ ! -e $backup_parent ]]; then
    mkdir -p -- "$backup_parent"
fi
[[ -d $backup_parent && ! -L $backup_parent ]] || { printf '%s\n' 'unsafe backup directory' >&2; exit 1; }
chmod 700 -- "$backup_parent"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
temporary="$backup_parent/.stage7-first-backup-$timestamp-$$.tmp"
final="$backup_parent/stage7-first-backup-$timestamp-$$"
[[ ! -e $temporary && ! -e $final ]] || { printf '%s\n' 'backup destination collision' >&2; exit 1; }
mkdir -m 700 -- "$temporary"
cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    if [[ $status -ne 0 && -d $temporary && ! -L $temporary ]]; then
        rm -rf -- "$temporary"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

inventory="$temporary/REMOTE_INVENTORY.txt"
ssh -T -o ClearAllForwardings=yes "$target" sh -s >"$inventory" <<'EOF_REMOTE'
set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
printf '%s\n' 'pm3000_first_backup.format=1'
printf 'system.kernel=%s\n' "$(uname -s)"
printf 'system.release=%s\n' "$(uname -r)"
printf 'system.machine=%s\n' "$(uname -m)"
if [ -f /etc/version ] && [ ! -L /etc/version ]; then
    firmware_output=$(openssl dgst -sha256 /etc/version) || exit 1
    firmware_hash=${firmware_output##*= }
    case "$firmware_hash" in *[!0-9a-f]*|'') exit 1;; esac
    [ "${#firmware_hash}" -eq 64 ] || exit 1
    printf 'firmware.sha256=%s\n' "$firmware_hash"
else
    printf '%s\n' 'firmware.sha256=absent'
fi
for item in /mnt/hdUser/pm3000-revive /etc/apache2/conf.d/pm3000-revive.conf; do
    case "$item" in
        /mnt/hdUser/pm3000-revive) key=pm3000_revive ;;
        /etc/apache2/conf.d/pm3000-revive.conf) key=apache_config ;;
    esac
    if [ -L "$item" ]; then type=symlink
    elif [ -d "$item" ]; then type=directory
    elif [ -f "$item" ]; then type=file
    elif [ -e "$item" ]; then type=other
    else type=absent
    fi
    printf 'path.%s=%s\n' "$key" "$type"
done
printf '%s\n' 'pm3000_first_backup.complete=yes'
EOF_REMOTE

chmod 600 -- "$inventory"
[[ $(sed -n '1p' "$inventory") == pm3000_first_backup.format=1 ]] || { printf '%s\n' 'invalid remote inventory header' >&2; exit 1; }
[[ $(sed -n '$p' "$inventory") == pm3000_first_backup.complete=yes ]] || { printf '%s\n' 'incomplete remote inventory' >&2; exit 1; }
[[ $(grep -c '^path\.pm3000_revive=absent$' "$inventory") -eq 1 ]] || { printf '%s\n' 'managed PM3000 path is not absent; full backup required' >&2; exit 1; }
[[ $(grep -c '^path\.apache_config=absent$' "$inventory") -eq 1 ]] || { printf '%s\n' 'managed Apache config is not absent; full backup required' >&2; exit 1; }

manifest="$temporary/BACKUP_MANIFEST.json"
python3 - "$target" "$inventory" >"$manifest" <<'PY_MANIFEST'
import datetime
import hashlib
import json
import secrets
import sys
from pathlib import Path

target, inventory_path = sys.argv[1:]
inventory = Path(inventory_path).read_bytes()
manifest = {
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "entries": [
        {"path": "/mnt/hdUser/pm3000-revive", "type": "absent"},
        {"path": "/etc/apache2/conf.d/pm3000-revive.conf", "type": "absent"},
    ],
    "format": 2,
    "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
    "target": target,
    "transaction_id": secrets.token_hex(16),
}
sys.stdout.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
PY_MANIFEST
chmod 600 -- "$manifest"

archive="$temporary/BACKUP_ARCHIVE.tar"
tar -cf "$archive" -C "$temporary" REMOTE_INVENTORY.txt
[[ $(tar -tf "$archive") == REMOTE_INVENTORY.txt ]] || { printf '%s\n' 'local backup archive validation failed' >&2; exit 1; }
chmod 600 -- "$archive"

archive_hash=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
manifest_hash=$(shasum -a 256 "$manifest" | cut -d ' ' -f 1)
for digest in "$archive_hash" "$manifest_hash"; do
    case "$digest" in *[!0-9a-f]*|'') printf '%s\n' 'local SHA-256 calculation failed' >&2; exit 1;; esac
    [[ ${#digest} -eq 64 ]] || { printf '%s\n' 'invalid local SHA-256 length' >&2; exit 1; }
done
printf '%s\n%s\n' "$archive_hash" "$manifest_hash" >"$temporary/BACKUP_COMPLETE"
chmod 600 -- "$temporary/BACKUP_COMPLETE"

python3 - "$temporary" <<'PY_FSYNC'
import os
import sys
from pathlib import Path
root = Path(sys.argv[1])
for name in ("REMOTE_INVENTORY.txt", "BACKUP_MANIFEST.json", "BACKUP_ARCHIVE.tar", "BACKUP_COMPLETE"):
    with (root / name).open("rb") as stream:
        os.fsync(stream.fileno())
descriptor = os.open(root, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY_FSYNC

mv -- "$temporary" "$final"
python3 - "$backup_parent" <<'PY_PARENT_FSYNC'
import os
import sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY_PARENT_FSYNC
trap - EXIT HUP INT TERM
printf 'backup_dir=%s\n' "$final"
printf 'archive_sha256=%s\n' "$archive_hash"
printf 'manifest_sha256=%s\n' "$manifest_hash"
printf '%s\n' 'backup_complete=yes'
