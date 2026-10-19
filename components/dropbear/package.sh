#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=2026.94
DIST="$ROOT/dist"
STAGE="$ROOT/package-stage"
RUNTIME="$STAGE/pm3000-dropbear-runtime-$VERSION"
BUILD="$STAGE/pm3000-dropbear-build-debug-$VERSION"

rm -rf "$STAGE"
mkdir -p "$DIST" "$RUNTIME/bin" "$RUNTIME/licenses" \
  "$BUILD/artifacts/debug" "$BUILD/artifacts/logs" "$BUILD/configs" \
  "$BUILD/patches/linux-headers" "$BUILD/patches/dropbear" "$BUILD/tests" \
  "$BUILD/sources" "$BUILD/licenses/runtime" "$BUILD/licenses/build"

cp "$ROOT/artifacts/bin/dropbear" "$ROOT/artifacts/bin/dropbearkey" "$RUNTIME/bin/"
cp "$ROOT/README.md" "$ROOT/BUILD-MANIFEST.md" "$ROOT/SECURITY-NOTES.md" "$ROOT/TEST-REPORT.md" "$ROOT/DEVICE-TEST.md" "$RUNTIME/"
cp "$ROOT/licenses/runtime/"* "$RUNTIME/licenses/"
(
  cd "$RUNTIME"
  find . -type f ! -name CHECKSUMS.sha256 -print0 | sort -z | xargs -0 sha256sum > CHECKSUMS.sha256
)

cp "$ROOT/README.md" "$ROOT/BUILD-MANIFEST.md" "$ROOT/SECURITY-NOTES.md" "$ROOT/TEST-REPORT.md" "$ROOT/DEVICE-TEST.md" "$BUILD/"
cp "$ROOT/fetch-sources.sh" "$ROOT/build-toolchain.sh" "$ROOT/build-dropbear.sh" "$ROOT/verify.sh" "$ROOT/package.sh" "$BUILD/"
cp "$ROOT/Dockerfile.test" "$ROOT/.dockerignore" "$BUILD/"
cp "$ROOT/configs/buildroot-pm3000_defconfig" "$ROOT/configs/localoptions.h" "$BUILD/configs/"
cp "$ROOT/output-buildroot/.config" "$BUILD/configs/buildroot-resolved.config"
cp "$ROOT/patches/linux-headers/0001-unifdef-rename-getline.patch" "$BUILD/patches/linux-headers/"
cp "$ROOT/patches/dropbear/"*.patch "$BUILD/patches/dropbear/"
cp "$ROOT/tests/login-shell.sh" "$BUILD/tests/"
cp "$ROOT/sources/dropbear-2026.94.tar.bz2" "$ROOT/sources/dropbear-2026.94.tar.bz2.asc" "$ROOT/sources/linux-2.6.23.tar.xz" "$BUILD/sources/"
cp "$ROOT/artifacts/debug/dropbear" "$ROOT/artifacts/debug/dropbearkey" "$BUILD/artifacts/debug/"
cp "$ROOT/artifacts/logs/"* "$BUILD/artifacts/logs/"
cp "$ROOT/licenses/runtime/"* "$BUILD/licenses/runtime/"
cp "$ROOT/licenses/build/"* "$BUILD/licenses/build/"
(
  cd "$BUILD"
  find . -type f ! -name CHECKSUMS.sha256 -print0 | sort -z | xargs -0 sha256sum > CHECKSUMS.sha256
)

RUNTIME_ARCHIVE="pm3000-dropbear-runtime-$VERSION.tar.xz"
BUILD_ARCHIVE="pm3000-dropbear-build-debug-$VERSION.tar.xz"
rm -f "$DIST/$RUNTIME_ARCHIVE" "$DIST/$BUILD_ARCHIVE" "$DIST/"*.sha256 "$DIST/SHA256SUMS"
tar --sort=name --mtime='UTC 2026-10-18' --owner=0 --group=0 --numeric-owner -C "$STAGE" -cJf "$DIST/pm3000-dropbear-runtime-$VERSION.tar.xz" "$(basename "$RUNTIME")"
tar --sort=name --mtime='UTC 2026-10-18' --owner=0 --group=0 --numeric-owner -C "$STAGE" -cJf "$DIST/pm3000-dropbear-build-debug-$VERSION.tar.xz" "$(basename "$BUILD")"
(
  cd "$DIST"
  sha256sum "$RUNTIME_ARCHIVE" > "$RUNTIME_ARCHIVE.sha256"
  sha256sum "$BUILD_ARCHIVE" > "$BUILD_ARCHIVE.sha256"
  cat "$RUNTIME_ARCHIVE.sha256" "$BUILD_ARCHIVE.sha256" > SHA256SUMS
)

VERIFY=$(mktemp -d)
trap 'rm -rf "$VERIFY"' EXIT INT TERM
tar -xJf "$DIST/pm3000-dropbear-runtime-$VERSION.tar.xz" -C "$VERIFY"
(cd "$VERIFY/$(basename "$RUNTIME")" && sha256sum -c CHECKSUMS.sha256)
rm -rf "$VERIFY/$(basename "$RUNTIME")"
tar -xJf "$DIST/pm3000-dropbear-build-debug-$VERSION.tar.xz" -C "$VERIFY"
(cd "$VERIFY/$(basename "$BUILD")" && sha256sum -c CHECKSUMS.sha256)
printf 'PACKAGES_OK\n'
