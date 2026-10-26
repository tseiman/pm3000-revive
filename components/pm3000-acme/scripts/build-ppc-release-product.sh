#!/bin/sh
set -eu

component_dir=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
"$component_dir/scripts/build-link-stubs.sh"
FIRMWARE_ROOT="$component_dir/build/link-stubs" \
PM3000_ACME_LINK_ONLY=1 \
    "$component_dir/scripts/build-ppc-product.sh"
printf 'ppc.release_product.build.complete=yes\n'
