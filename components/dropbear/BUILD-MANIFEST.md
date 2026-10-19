# Build Manifest

Generated: 2026-10-18T23:44:06Z

## Target

- CPU: PowerPC 32-bit, big-endian, `e300c3`
- Floating point ABI: soft-float
- Kernel userspace header baseline: Linux 2.6.23
- Linkage: fully static
- Reproducibility scope: pinned and repeatable build process; bit-for-bit identity across hosts is not currently claimed (`BR2_REPRODUCIBLE` was not enabled for the validated toolchain).

## Pinned components

- Dropbear: 2026.94
  - Source: `https://matt.ucc.asn.au/dropbear/releases/dropbear-2026.94.tar.bz2`
  - SHA-256: `e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81`
  - Detached signature fingerprint used: `F7347EF2EE2E07A267628CA944931494F29C6773`
  - Signature was cryptographically valid; owner trust was not independently established.
- Buildroot: tag `2026.08`, commit `d5180309b1b66ef3b8eaccca70ad69be8e0729a1`
- GCC: 14.4.0
- GNU Binutils: 2.44
- musl: 1.2.6
- Linux headers/source: 2.6.23
  - Source SHA-256: `3abdc50d03cb05b2d454139359dd2a026366b789f3d1de5a68131ed1dc944963`
- Test image: `debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587`

## Local compatibility patch

`patches/linux-headers/0001-unifdef-rename-getline.patch` renames an internal host utility function in Linux 2.6.23's `scripts/unifdef.c` to avoid collision with modern libc `getline(3)`. It does not alter target headers or ABI.

## Build commands

```sh
./fetch-sources.sh
./build-toolchain.sh
./build-dropbear.sh
./verify.sh
./package.sh
```

The build/debug archive receives the actual `output-buildroot/.config` used by that build as `configs/buildroot-resolved.config`; the version-controlled minimal input is `configs/buildroot-pm3000_defconfig`.
