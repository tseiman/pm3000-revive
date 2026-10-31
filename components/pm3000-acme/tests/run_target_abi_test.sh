#!/bin/sh
set -eu

component_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo_root=$(CDPATH= cd -- "$component_dir/../.." && pwd)
firmware_root=${FIRMWARE_ROOT:-"$repo_root/../pm3000-firmware-analysis/rootfs"}
cross_prefix=${CROSS_PREFIX:-"$repo_root/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-"}
cc=${CC_PPC:-"${cross_prefix}gcc"}
ld=${LD_PPC:-"${cross_prefix}ld"}
obj_dir="$component_dir/build/target-abi-test"
out="$obj_dir/test_tls_target_abi"

for required in "$cc" "$ld" "$firmware_root/lib/libc-2.3.5.so"; do
    test -e "$required" || { printf 'missing ABI test input: %s\n' "$required" >&2; exit 1; }
done
command -v qemu-ppc >/dev/null 2>&1 || {
    echo "qemu-ppc missing; target ABI test cannot run" >&2
    exit 1
}

rm -rf "$obj_dir"
mkdir -p "$obj_dir"
"$cc" -DPM3000_FIRMWARE_ABI -I"$component_dir/include" \
    -I"$component_dir/src" -std=c99 -Os -Wall -Wextra -Werror -pedantic \
    -fno-stack-protector -fno-pic -ffunction-sections -fdata-sections \
    -mcpu=e300c3 -msoft-float \
    -c "$component_dir/tests/test_tls_target_abi.c" -o "$obj_dir/test.o"
"$cc" -mcpu=e300c3 -msoft-float -c "$component_dir/src/start.S" \
    -o "$obj_dir/start.o"
libgcc=$($cc -print-libgcc-file-name)
"$ld" -m elf32ppclinux --gc-sections --allow-shlib-undefined \
    --dynamic-linker /lib/ld.so.1 -o "$out" \
    "$obj_dir/start.o" "$obj_dir/test.o" "$libgcc" \
    "$firmware_root/lib/libc-2.3.5.so"
LD_BIND_NOW=1 LD_LIBRARY_PATH=/lib:/usr/lib \
    qemu-ppc -cpu e300c3 -L "$firmware_root" "$out"
