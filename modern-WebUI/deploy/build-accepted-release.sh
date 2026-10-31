#!/bin/sh
set -eu

usage()
{
    echo "usage: $0 RELEASE_ID ACCEPTED_PM3000_ACME [OUTPUT_DIRECTORY]" >&2
    exit 2
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
release_id=$1
accepted_acme=$2
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
MODERN=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
REPOSITORY=$(CDPATH= cd "$MODERN/.." && pwd)
output_directory=${3:-$MODERN/dist}
expected_acme_sha256=0aa205b837fa357cf3d7d0eb8a67c3df10fd929d9a8dc5c3a41c0383416832c0
compiler=$REPOSITORY/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-gcc

[ -f "$accepted_acme" ] && [ ! -L "$accepted_acme" ] || {
    echo "accepted pm3000-acme is not a regular non-symlink file: $accepted_acme" >&2
    exit 1
}
[ -x "$compiler" ] || { echo "PPC toolchain missing: $compiler" >&2; exit 1; }
for command_name in python3 make git; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name missing" >&2; exit 1; }
done

actual_acme_sha256=$(python3 - "$accepted_acme" <<'PY'
import hashlib
from pathlib import Path
import sys
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
[ "$actual_acme_sha256" = "$expected_acme_sha256" ] || {
    echo "accepted pm3000-acme SHA-256 mismatch" >&2
    exit 1
}

git_revision=$(git -C "$REPOSITORY" rev-parse --short=12 HEAD)
case "$git_revision" in ''|*[!0-9a-f]*) echo "unsafe Git revision" >&2; exit 1;; esac
mkdir -p "$output_directory"
output=$output_directory/pm3000-release-$release_id.tar
[ ! -e "$output" ] && [ ! -e "$output.sha256" ] || {
    echo "release output already exists: $output" >&2
    exit 1
}

# Rebuild every target component except the immutable hardware-accepted ACME CLI.
make -C "$MODERN/native" clean target
make -C "$MODERN/deploy" clean target
python3 "$MODERN/deploy/deployment.py" package \
    --source "$MODERN" \
    --release-id "$release_id" \
    --git-revision "$git_revision" \
    --acme-binary "$accepted_acme" \
    --acme-sha256 "$expected_acme_sha256" \
    --output "$output"

packaged_acme_sha256=$(python3 - "$output" <<'PY'
import hashlib
import sys
import tarfile
with tarfile.open(sys.argv[1], "r:") as archive:
    payload = archive.extractfile("bin/pm3000-acme").read()
print(hashlib.sha256(payload).hexdigest())
PY
)
[ "$packaged_acme_sha256" = "$expected_acme_sha256" ] || {
    echo "packaged pm3000-acme SHA-256 mismatch" >&2
    exit 1
}
printf 'accepted_acme_sha256=%s\nrelease_tar=%s\nrelease_sidecar=%s\n' \
    "$packaged_acme_sha256" "$output" "$output.sha256"
