#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$ROOT/sources"

fetch() {
  url=$1
  dest=$2
  if [ ! -f "$dest" ]; then
    curl -fL --retry 3 -o "$dest.tmp" "$url"
    mv "$dest.tmp" "$dest"
  fi
}

fetch "https://matt.ucc.asn.au/dropbear/releases/dropbear-2026.94.tar.bz2" "$ROOT/sources/dropbear-2026.94.tar.bz2"
fetch "https://matt.ucc.asn.au/dropbear/releases/dropbear-2026.94.tar.bz2.asc" "$ROOT/sources/dropbear-2026.94.tar.bz2.asc"
fetch "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.23.tar.xz" "$ROOT/sources/linux-2.6.23.tar.xz"

echo 'e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81  sources/dropbear-2026.94.tar.bz2' > "$ROOT/sources/SHA256SUMS.required"
echo '3abdc50d03cb05b2d454139359dd2a026366b789f3d1de5a68131ed1dc944963  sources/linux-2.6.23.tar.xz' >> "$ROOT/sources/SHA256SUMS.required"
(cd "$ROOT" && sha256sum -c sources/SHA256SUMS.required)

if [ ! -e "$ROOT/buildroot" ]; then
  git clone --depth 1 --branch 2026.08 https://gitlab.com/buildroot.org/buildroot.git "$ROOT/buildroot"
  test "$(git -C "$ROOT/buildroot" rev-parse HEAD)" = d5180309b1b66ef3b8eaccca70ad69be8e0729a1
fi
[ -f "$ROOT/buildroot/Makefile" ] || { echo "buildroot is not a usable Buildroot source tree" >&2; exit 1; }
if git -C "$ROOT/buildroot" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'Buildroot HEAD: %s\n' "$(git -C "$ROOT/buildroot" rev-parse HEAD)"
  if [ -n "$(git -C "$ROOT/buildroot" status --porcelain)" ]; then
    printf 'NOTICE: using locally modified Buildroot sources\n'
  fi
else
  printf 'NOTICE: using a local non-Git Buildroot source tree\n'
fi
printf 'SOURCES_OK\n'
