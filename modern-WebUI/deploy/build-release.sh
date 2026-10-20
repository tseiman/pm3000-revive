#!/bin/sh
set -eu

usage() {
    echo "usage: $0 RELEASE_ID [OUTPUT_DIRECTORY]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
release_id=$1
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
MODERN=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
REPOSITORY=$(CDPATH= cd "$MODERN/.." && pwd)
output_directory=${2:-$MODERN/dist}
compiler=$REPOSITORY/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-gcc

[ -x "$compiler" ] || {
    echo "PPC toolchain missing: $compiler" >&2
    echo "On Linux run components/dropbear/fetch-sources.sh and components/dropbear/build-toolchain.sh first, or use the modern-webui-v* GitHub workflow." >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || { echo "python3 missing" >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make missing" >&2; exit 1; }

mkdir -p "$output_directory"
output=$output_directory/pm3000-release-$release_id.tar
[ ! -e "$output" ] && [ ! -e "$output.sha256" ] || {
    echo "release output already exists: $output" >&2
    exit 1
}

make -C "$MODERN/native" target
make -C "$MODERN/deploy" target
python3 "$MODERN/deploy/deployment.py" package \
    --source "$MODERN" \
    --release-id "$release_id" \
    --output "$output"

python3 - "$output" <<'PY'
import hashlib
from pathlib import Path
import sys

archive = Path(sys.argv[1])
sidecar = Path(str(archive) + ".sha256")
fields = sidecar.read_text(encoding="ascii").split()
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if fields != [actual, archive.name]:
    raise SystemExit("release sidecar verification failed")
print(f"release_sha256={actual}")
PY

if command -v qemu-ppc >/dev/null 2>&1; then
    helper=$MODERN/deploy/build/pm3000-atomic-publish-ppc32
    rest=$MODERN/native/build/pm3000-rest-ppc32
    qemu-ppc -cpu e300c3 "$helper" --verify-regular "$helper"
    health=$(REQUEST_METHOD=GET PATH_INFO=/health SCRIPT_NAME=/api/v1 HTTPS=on \
        qemu-ppc -cpu e300c3 "$rest")
    case "$health" in *"Status: 200 OK"*'"apiVersion":"v1","status":"live"'*)
        echo "qemu_e300c3=yes";;
        *) echo "QEMU REST health check failed" >&2; exit 1;;
    esac
else
    echo "qemu_e300c3=skipped"
fi

printf 'release_tar=%s\n' "$output"
printf 'release_sidecar=%s\n' "$output.sha256"
