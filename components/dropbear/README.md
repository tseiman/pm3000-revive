# Static Dropbear Component for Avocent PM3000

This project builds a server-focused Dropbear 2026.94 for 32-bit big-endian PowerPC e300c3 systems with a Linux 2.6.23 userspace ABI baseline.

## Runtime properties

- ELF32, PowerPC, big-endian, soft-float, secure PLT
- Fully static musl linkage; no dependency on the firmware's glibc 2.3.5
- `dropbear` and `dropbearkey`
- Ed25519 and RSA/SHA-256 signatures
- Curve25519, sntrup761/x25519, and DH group14/SHA-256 KEX
- ChaCha20-Poly1305 and AES-CTR ciphers; HMAC-SHA2-256
- No SHA-1 signatures/MACs, DSS, ECDSA, CBC, 3DES, compression, X11, agent forwarding, TCP/stream forwarding, or SFTP server
- Two-phase installer: one parallel test on port 2222, then explicitly confirmed activation on port 22
- Re-exec disabled because Linux 2.6.23 lacks the modern `fexecve` path
- Project extension `--login-shell /absolute/path` optionally replaces the session shell after successful account authentication and authorization.

Without `--login-shell`, Dropbear uses the account shell exactly as upstream does. With the option, the selected shell is used for SSH shell requests and for remote commands executed with `shell -c`. The path must name an existing executable regular file and is rejected during server startup otherwise. The override is server-wide for all accounts accepted by that instance; it does not change `/etc/passwd`, authentication, account-shell validation, forced-command selection, or `authorized_keys` restrictions.

## Build

Prerequisites: Linux host, GNU make, GCC/G++, patch, Perl, rsync, cpio, unzip, bzip2, xz, Python 3, file, curl, Git, Docker (for tests), and sufficient disk space.

```sh
git clone https://github.com/tseiman/pm3000-revive.git
cd pm3000-revive/components/dropbear
./fetch-sources.sh
./build-toolchain.sh
./build-dropbear.sh
./verify.sh
./package.sh
```

`build-toolchain.sh` builds only the Buildroot cross-toolchain. It does not contact a target device. Buildroot sources are pinned in `BUILD-MANIFEST.md`; source integrity is checked using Buildroot's hashes plus the checksums shipped here.

## Outputs

- `dist/pm3000-dropbear-runtime-2026.94.tar.xz`: target runtime, two-phase installer, rollback tool, service script, licenses, checksums, and operator documentation.
- `dist/pm3000-dropbear-runtime-2026.94.tar.xz.sha256`: checksum sidecar for verifying the runtime archive before extraction.
- `dist/pm3000-dropbear-build-debug-2026.94.tar.xz`: build scripts, the effective Buildroot configuration, patches, source inputs, logs, and debug binaries.
- `dist/pm3000-dropbear-build-debug-2026.94.tar.xz.sha256`: checksum sidecar for the build/debug archive.
- `dist/SHA256SUMS`: combined checksum manifest for both archives.

## Installation

Read the [installer README](https://github.com/tseiman/pm3000-revive/blob/main/components/dropbear/installer/README.md) and the [full installation guide](https://github.com/tseiman/pm3000-revive/blob/main/docs/INSTALL_DROPBEAR.md). The recommended path has exactly two phases:

1. `01-prepare.sh` installs protected persistent files and starts one parallel test listener while preserving vendor OpenSSH on port 22.
2. `02-activate.sh --confirmed-test` provisionally takes port 22 and finalizes SysV startup only after a new port-22 login is explicitly confirmed.

`rollback.sh` restores the original init script and OpenSSH on port 22. No installer command reboots the PDU.

## Safety boundary

Builds, tests, and packaging never contact, upload to, restart, or reconfigure a PM3000. Device changes occur only when an operator deliberately transfers the runtime package and runs its installer as root. Keep a vendor SSH session and out-of-band recovery available until activation is confirmed.
