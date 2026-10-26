#!/bin/sh
set -eu

component_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo_root=$(CDPATH= cd -- "$component_dir/../.." && pwd)
firmware_root=${FIRMWARE_ROOT:-"$repo_root/../pm3000-firmware-analysis/rootfs"}
cross_prefix=${CROSS_PREFIX:-"$repo_root/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-"}
cc=${CC_PPC:-"${cross_prefix}gcc"}
ld=${LD_PPC:-"${cross_prefix}ld"}
strip=${STRIP_PPC:-"${cross_prefix}strip"}
out=${1:-"$component_dir/build/pm3000-acme"}
obj_dir="$component_dir/build/ppc-obj"

for required in "$cc" "$ld" "$strip" \
    "$firmware_root/lib/libc-2.3.5.so" \
    "$firmware_root/usr/lib/libssl.so.1.0.0" \
    "$firmware_root/usr/lib/libcrypto.so.1.0.0"; do
    test -e "$required" || { printf 'missing build input: %s\n' "$required" >&2; exit 1; }
done

rm -rf "$obj_dir"
mkdir -p "$obj_dir" "$(dirname -- "$out")"

sources='main app config state store publish certificate client transport tls http challenge protocol json url jws crypto base64url stat_compat syscall_compat'
for name in $sources; do
    "$cc" -DPM3000_FIRMWARE_ABI -I"$component_dir/include" \
        -I"$component_dir/src" -std=c99 -Os -Wall -Wextra -Werror \
        -pedantic -fno-stack-protector -fno-pic -ffunction-sections \
        -fdata-sections -mcpu=e300c3 -msoft-float \
        -c "$component_dir/src/$name.c" -o "$obj_dir/$name.o"
done
"$cc" -mcpu=e300c3 -msoft-float -c "$component_dir/src/start.S" \
    -o "$obj_dir/start.o"

libgcc=$($cc -print-libgcc-file-name)
"$ld" -m elf32ppclinux --gc-sections --allow-shlib-undefined \
    --dynamic-linker /lib/ld.so.1 -o "$out" \
    "$obj_dir"/*.o "$libgcc" \
    "$firmware_root/usr/lib/libssl.so.1.0.0" \
    "$firmware_root/usr/lib/libcrypto.so.1.0.0" \
    "$firmware_root/lib/libc-2.3.5.so"
"$strip" --strip-unneeded "$out"
"$component_dir/scripts/verify-ppc-product.sh" "$out"
if [ "${PM3000_ACME_LINK_ONLY:-0}" = 1 ]; then
    echo "ppc.product.runtime_gate=link-stubs-only"
    exit 0
fi
command -v qemu-ppc >/dev/null 2>&1 || {
    echo "qemu-ppc missing; PPC runtime gate cannot run" >&2
    exit 1
}
set +e
qemu_output=$(LD_BIND_NOW=1 LD_LIBRARY_PATH=/lib:/usr/lib \
    qemu-ppc -cpu e300c3 -L "$firmware_root" \
    "$out" renew --invalid 2>&1)
qemu_status=$?
set -e
if test "$qemu_status" -ne 2; then
    printf 'PPC runtime gate failed: exit=%s\n%s\n' \
        "$qemu_status" "$qemu_output" >&2
    exit 1
fi
printf 'ppc.product.qemu_bind_now.complete=yes\n'
