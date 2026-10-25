#!/bin/sh
set -eu

binary=${1:?usage: verify-ppc-product.sh <binary>}
component_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
allowed_imports="$component_dir/abi-allowed-imports.txt"
max_bytes=${PM3000_ACME_MAX_BINARY_BYTES:-458752}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pm3000-acme-verify.XXXXXX")
chmod 700 "$tmp_dir"
tmp=$tmp_dir/result
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

file "$binary" >"$tmp"
grep -q 'ELF 32-bit MSB' "$tmp"
grep -q 'PowerPC' "$tmp"

readelf -h "$binary" >"$tmp"
grep -Eq 'Class:[[:space:]]+ELF32' "$tmp"
grep -Eq 'Data:[[:space:]]+2.s complement, big endian' "$tmp"
grep -Eq 'Machine:[[:space:]]+PowerPC' "$tmp"

readelf -l "$binary" >"$tmp"
grep -Fq '[Requesting program interpreter: /lib/ld.so.1]' "$tmp"

readelf -d "$binary" >"$tmp"
if grep -Eq '\((RPATH|RUNPATH)\)' "$tmp"; then
    echo 'RPATH/RUNPATH is forbidden' >&2
    exit 1
fi
sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' "$tmp" | LC_ALL=C sort -u >"$tmp.needed"
printf '%s\n' libc.so.6 libcrypto.so.1.0.0 libssl.so.1.0.0 | LC_ALL=C sort >"$tmp"
if ! cmp -s "$tmp" "$tmp.needed"; then
    echo 'unexpected DT_NEEDED set:' >&2
    sed -n '1,20p' "$tmp.needed" >&2
    exit 1
fi

readelf -Ws "$binary" >"$tmp"
if readelf -Ws "$binary" | grep -Eq '__fstat_time64|__lstat_time64|__stack_chk'; then
    echo "forbidden runtime symbol present" >&2
    exit 1
fi
export LC_ALL=C
readelf -Ws "$binary" | awk '$7 == "UND" && $8 != "" {
    name=$8; sub(/@.*/, "", name); print name
}' | sort -u >"$tmp.imports"
if ! cmp -s "$allowed_imports" "$tmp.imports"; then
    echo "dynamic import allowlist mismatch" >&2
    diff -u "$allowed_imports" "$tmp.imports" >&2 || true
    exit 1
fi
readelf --version-info "$binary" | sed -n 's/.*Name: \(GLIBC_[0-9.]*\).*/\1/p' \
    | LC_ALL=C sort -u >"$tmp.versions"
python3 - "$tmp.versions" <<'PY'
import pathlib, sys
for value in pathlib.Path(sys.argv[1]).read_text().splitlines():
    version = tuple(int(part) for part in value.removeprefix("GLIBC_").split("."))
    if version > (2, 3, 5):
        raise SystemExit("unsupported symbol version: " + value)
PY

bytes=$(wc -c <"$binary" | tr -d ' ')
if test "$bytes" -gt "$max_bytes"; then
    printf 'binary exceeds limit: %s > %s bytes\n' "$bytes" "$max_bytes" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    hash=$(sha256sum "$binary" | sed 's/[[:space:]].*//')
else
    hash=$(shasum -a 256 "$binary" | sed 's/[[:space:]].*//')
fi
printf 'ppc.product.verify.complete=yes\n'
printf 'ppc.product.bytes=%s\n' "$bytes"
printf 'ppc.product.sha256=%s\n' "$hash"
