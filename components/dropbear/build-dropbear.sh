#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLCHAIN="$ROOT/output-buildroot/host"
CC="$TOOLCHAIN/bin/powerpc-buildroot-linux-musl-gcc"
STRIP="$TOOLCHAIN/bin/powerpc-buildroot-linux-musl-strip"
SRC_ARCHIVE="$ROOT/sources/dropbear-2026.94.tar.bz2"
BUILD="$ROOT/work/dropbear-2026.94"
OUT="$ROOT/artifacts"
[ -x "$CC" ] || { echo "missing toolchain: $CC" >&2; exit 1; }
mkdir -p "$BUILD" "$OUT/bin" "$OUT/debug" "$OUT/logs"
if [ ! -f "$BUILD/configure" ]; then
  tar -xf "$SRC_ARCHIVE" -C "$BUILD" --strip-components=1
else
  printf 'NOTICE: reusing local Dropbear work tree: %s\n' "$BUILD"
fi
cp "$ROOT/configs/localoptions.h" "$BUILD/localoptions.h"
cd "$BUILD"
if CC="$CC" CFLAGS="-Os -g3" ./configure --host=powerpc-buildroot-linux-musl --enable-static --disable-zlib --disable-syslog --disable-lastlog --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx >"$OUT/logs/configure-dropbear.log" 2>&1; then
  cat "$OUT/logs/configure-dropbear.log"
else
  status=$?
  cat "$OUT/logs/configure-dropbear.log" >&2
  exit "$status"
fi
if make -j2 PROGRAMS="dropbear dropbearkey" >"$OUT/logs/build-dropbear.log" 2>&1; then
  cat "$OUT/logs/build-dropbear.log"
else
  status=$?
  cat "$OUT/logs/build-dropbear.log" >&2
  exit "$status"
fi
cp dropbear dropbearkey "$OUT/debug/"
cp dropbear dropbearkey "$OUT/bin/"
"$STRIP" --strip-all "$OUT/bin/dropbear" "$OUT/bin/dropbearkey"
"$CC" -dumpfullversion > "$OUT/logs/gcc-version.txt"
