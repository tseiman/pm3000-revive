#!/bin/sh
set -eu

component_dir=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
repo_root=$(CDPATH= cd "$component_dir/../.." && pwd)
cross_prefix=${CROSS_PREFIX:-"$repo_root/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-"}
cc=${CC_PPC:-"${cross_prefix}gcc"}
out=$component_dir/build/link-stubs
work=$out/.work
ssl_symbols=$component_dir/abi-stubs/libssl.symbols
crypto_symbols=$component_dir/abi-stubs/libcrypto.symbols
libc20_symbols=$component_dir/abi-stubs/libc-glibc20.symbols
libc21_symbols=$component_dir/abi-stubs/libc-glibc21.symbols

for required in "$cc" "$ssl_symbols" "$crypto_symbols" \
    "$libc20_symbols" "$libc21_symbols" \
    "$component_dir/abi-allowed-imports.txt"; do
    [ -e "$required" ] || { printf 'missing link-stub input: %s\n' "$required" >&2; exit 1; }
done
rm -rf "$out"
mkdir -p "$work" "$out/lib" "$out/usr/lib"
LC_ALL=C sort -u "$ssl_symbols" "$crypto_symbols" \
    "$libc20_symbols" "$libc21_symbols" >"$work/combined.symbols"
cmp "$component_dir/abi-allowed-imports.txt" "$work/combined.symbols" >/dev/null || {
    echo "link-stub symbols do not match ABI allowlist" >&2
    diff -u "$component_dir/abi-allowed-imports.txt" "$work/combined.symbols" >&2 || true
    exit 1
}

write_assembly() {
    list=$1
    destination=$2
    : >"$destination"
    printf '.section .text\n' >>"$destination"
    while IFS= read -r symbol; do
        [ -n "$symbol" ] || continue
        printf '.globl %s\n.type %s,@function\n%s:\n    li 3,0\n    blr\n.size %s,.-%s\n' \
            "$symbol" "$symbol" "$symbol" "$symbol" "$symbol" >>"$destination"
    done <"$list"
    printf '.section .note.GNU-stack,"",@progbits\n' >>"$destination"
}

write_assembly "$ssl_symbols" "$work/libssl.S"
write_assembly "$crypto_symbols" "$work/libcrypto.S"
{
    printf '.section .text\n'
    while IFS= read -r symbol; do
        [ -n "$symbol" ] || continue
        printf '.globl %s\n.type %s,@function\n%s:\n    li 3,0\n    blr\n.size %s,.-%s\n' \
            "$symbol" "$symbol" "$symbol" "$symbol" "$symbol"
    done <"$libc20_symbols"
    while IFS= read -r symbol; do
        [ -n "$symbol" ] || continue
        printf '.globl %s\n.type %s,@function\n%s:\n    li 3,0\n    blr\n.size %s,.-%s\n' \
            "$symbol" "$symbol" "$symbol" "$symbol" "$symbol"
    done <"$libc21_symbols"
    printf '.section .data\n.globl stderr\n.type stderr,@object\n.size stderr,4\nstderr:\n    .long 0\n'
    printf '.section .note.GNU-stack,"",@progbits\n'
} >"$work/libc.S"
{
    printf 'GLIBC_2.0 {\n    global:\n'
    while IFS= read -r symbol; do [ -n "$symbol" ] && printf '        %s;\n' "$symbol"; done <"$libc20_symbols"
    printf '        stderr;\n'
    printf '};\nGLIBC_2.1 {\n    global:\n'
    while IFS= read -r symbol; do [ -n "$symbol" ] && printf '        %s;\n' "$symbol"; done <"$libc21_symbols"
    printf '    local: *;\n} GLIBC_2.0;\n'
} >"$work/libc.map"

"$cc" -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
    -Wl,-soname,libssl.so.1.0.0 -o "$out/usr/lib/libssl.so.1.0.0" "$work/libssl.S"
"$cc" -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
    -Wl,-soname,libcrypto.so.1.0.0 -o "$out/usr/lib/libcrypto.so.1.0.0" "$work/libcrypto.S"
"$cc" -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
    -Wl,-soname,libc.so.6,--version-script="$work/libc.map" \
    -o "$out/lib/libc-2.3.5.so" "$work/libc.S"
rm -rf "$work"
printf 'link_stubs.build.complete=yes\n'
