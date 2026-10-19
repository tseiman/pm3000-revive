#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/output-buildroot"
for tool in make gcc g++ patch perl rsync cpio unzip bzip2 xz python3 file curl; do command -v "$tool" >/dev/null 2>&1 || { echo "missing host tool: $tool" >&2; exit 1; }; done
[ -f "$ROOT/buildroot/Makefile" ] || { echo "run ./fetch-sources.sh first" >&2; exit 1; }
mkdir -p "$OUT"
make -C "$ROOT/buildroot" O="$OUT" BR2_DEFCONFIG="$ROOT/configs/buildroot-pm3000_defconfig" defconfig
make -j6 -C "$ROOT/buildroot" O="$OUT" toolchain
