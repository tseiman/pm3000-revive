#!/usr/bin/env bash
# Stream a full PM3000 filesystem backup to a private macOS/Linux host directory.
set -euo pipefail
umask 077

sha256_file()
{
    python3 - "$1" <<'PY_SHA256'
import hashlib
import sys
from pathlib import Path
with Path(sys.argv[1]).open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha256") if hasattr(hashlib, "file_digest") else None
    if digest is None:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
print(digest.hexdigest())
PY_SHA256
}

target=
backup_parent=
while (($#)); do
    case "$1" in
        --target) target=${2:?missing SSH target}; shift 2 ;;
        --backup-dir) backup_parent=${2:?missing backup directory}; shift 2 ;;
        --help)
            printf '%s\n' 'usage: stage7-first-backup.sh --target USER@HOST --backup-dir DIRECTORY'
            exit 0
            ;;
        *) printf 'stage7-first-backup.sh: unsupported argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

[[ -n $target && -n $backup_parent ]] || { printf '%s\n' 'target and backup directory are required' >&2; exit 2; }
case "$target" in ''|-*) printf '%s\n' 'unsafe SSH target' >&2; exit 2;; esac
case "$backup_parent" in -*) printf '%s\n' 'backup path must not start with a dash' >&2; exit 2;; esac

if [[ ! -e $backup_parent ]]; then
    mkdir -p "$backup_parent"
fi
[[ -d $backup_parent ]] || { printf '%s\n' 'backup path is not a directory' >&2; exit 1; }
backup_parent=$(cd "$backup_parent" && pwd -P)
chmod 700 "$backup_parent"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
temporary="$backup_parent/.stage7-full-backup-$timestamp-$$.tmp"
final="$backup_parent/stage7-full-backup-$timestamp-$$"
[[ ! -e $temporary && ! -e $final ]] || { printf '%s\n' 'backup destination collision' >&2; exit 1; }
mkdir -m 700 "$temporary"
cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    if [[ $status -ne 0 && -d $temporary && ! -L $temporary ]]; then
        rm -rf "$temporary"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

inventory="$temporary/REMOTE_INVENTORY.txt"
ssh -T -o ClearAllForwardings=yes "$target" sh -s >"$inventory" <<'EOF_INVENTORY'
set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
printf '%s\n' 'pm3000_full_backup.format=1'
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
printf '%s\n' 'excluded.virtual=dev,proc,sys'
printf '%s\n' 'pm3000_full_backup.complete=yes'
EOF_INVENTORY
chmod 600 "$inventory"
[[ $(sed -n '1p' "$inventory") == pm3000_full_backup.format=1 ]] || { printf '%s\n' 'invalid remote inventory header' >&2; exit 1; }
[[ $(sed -n '$p' "$inventory") == pm3000_full_backup.complete=yes ]] || { printf '%s\n' 'incomplete remote inventory' >&2; exit 1; }

archive="$temporary/BACKUP_ARCHIVE.tar"
ssh -T -o ClearAllForwardings=yes "$target" sh -s >"$archive" <<'EOF_ARCHIVE'
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
cd /
set --
for item in ./* ./.[!.]* ./..?*; do
    if [ ! -e "$item" ] && [ ! -L "$item" ]; then
        continue
    fi
    name=${item#./}
    case "$name" in dev|proc|sys) continue;; esac
    set -- "$@" "$item"
done
[ "$#" -gt 0 ] || exit 1
tar cf - "$@"
EOF_ARCHIVE
chmod 600 "$archive"
[[ -s $archive ]] || { printf '%s\n' 'remote backup archive is empty' >&2; exit 1; }

archive_hash=$(sha256_file "$archive")
manifest="$temporary/BACKUP_MANIFEST.json"
python3 - "$target" "$inventory" "$archive" "$archive_hash" >"$manifest" <<'PY_MANIFEST'
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import secrets
import sys
import tarfile

target, inventory_path, archive_path, archive_hash = sys.argv[1:]
inventory = Path(inventory_path).read_bytes()
entries = []
seen = set()
roots = set()
with tarfile.open(archive_path, "r:") as archive:
    for member in archive:
        name = member.name
        while name.startswith("./"):
            name = name[2:]
        pure = PurePosixPath(name)
        if not name or pure.is_absolute() or ".." in pure.parts or name in seen:
            raise SystemExit(f"unsafe archive member: {member.name}")
        if pure.parts[0] in {"dev", "proc", "sys"}:
            raise SystemExit(f"virtual filesystem included unexpectedly: {member.name}")
        seen.add(name)
        roots.add(pure.parts[0])
        if member.isfile():
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"cannot read archive member: {member.name}")
            digest = hashlib.sha256()
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
            entry = {"path": name, "type": "file", "size": member.size, "sha256": digest.hexdigest()}
        elif member.isdir():
            entry = {"path": name, "type": "directory"}
        elif member.issym():
            entry = {"path": name, "type": "symlink", "target": member.linkname}
        elif member.islnk():
            entry = {"path": name, "type": "hardlink", "target": member.linkname}
        elif member.ischr():
            entry = {"path": name, "type": "character-device"}
        elif member.isblk():
            entry = {"path": name, "type": "block-device"}
        elif member.isfifo():
            entry = {"path": name, "type": "fifo"}
        else:
            entry = {"path": name, "type": "other"}
        entry.update({"mode": member.mode, "uid": member.uid, "gid": member.gid, "mtime": member.mtime})
        entries.append(entry)
if not {"etc", "mnt", "usr"}.issubset(roots):
    missing = sorted({"etc", "mnt", "usr"} - roots)
    raise SystemExit("incomplete full backup; missing roots: " + ",".join(missing))
manifest = {
    "archive_sha256": archive_hash,
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "entries": entries,
    "excluded_virtual_filesystems": ["dev", "proc", "sys"],
    "format": 3,
    "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
    "target": target,
    "transaction_id": secrets.token_hex(16),
}
sys.stdout.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
PY_MANIFEST
chmod 600 "$manifest"

manifest_hash=$(sha256_file "$manifest")
for digest in "$archive_hash" "$manifest_hash"; do
    case "$digest" in *[!0-9a-f]*|'') printf '%s\n' 'local SHA-256 calculation failed' >&2; exit 1;; esac
    [[ ${#digest} -eq 64 ]] || { printf '%s\n' 'invalid local SHA-256 length' >&2; exit 1; }
done
printf '%s\n%s\n' "$archive_hash" "$manifest_hash" >"$temporary/BACKUP_COMPLETE"
chmod 600 "$temporary/BACKUP_COMPLETE"

python3 - "$temporary" <<'PY_FSYNC'
import errno
import os
from pathlib import Path
import sys
root = Path(sys.argv[1])
for name in ("REMOTE_INVENTORY.txt", "BACKUP_MANIFEST.json", "BACKUP_ARCHIVE.tar", "BACKUP_COMPLETE"):
    with (root / name).open("rb") as stream:
        os.fsync(stream.fileno())
descriptor = os.open(root, os.O_RDONLY)
try:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in (errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)):
            raise
finally:
    os.close(descriptor)
PY_FSYNC

mv "$temporary" "$final"
python3 - "$backup_parent" <<'PY_PARENT_FSYNC'
import errno
import os
import sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in (errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)):
            raise
finally:
    os.close(descriptor)
PY_PARENT_FSYNC
trap - EXIT HUP INT TERM
printf 'backup_dir=%s\n' "$final"
printf 'archive_sha256=%s\n' "$archive_hash"
printf 'manifest_sha256=%s\n' "$manifest_hash"
printf 'archive_bytes=%s\n' "$(wc -c <"$final/BACKUP_ARCHIVE.tar" | tr -d ' ')"
printf '%s\n' 'backup_complete=yes'
