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
- Default test port 2222; existing device SSH service is not replaced
- Re-exec disabled because Linux 2.6.23 lacks the modern `fexecve` path

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

- `dist/pm3000-dropbear-runtime-2026.94.tar.xz`: target runtime, licenses, checksums, and safe manual test procedure.
- `dist/pm3000-dropbear-runtime-2026.94.tar.xz.sha256`: checksum sidecar for verifying the runtime archive before extraction.
- `dist/pm3000-dropbear-build-debug-2026.94.tar.xz`: build scripts, the effective Buildroot configuration, patches, source inputs, logs, and debug binaries.
- `dist/pm3000-dropbear-build-debug-2026.94.tar.xz.sha256`: checksum sidecar for the build/debug archive.
- `dist/SHA256SUMS`: combined checksum manifest for both archives.

## Safety boundary

No deployment is automated. Nothing in this project connects to, uploads to, restarts, or reconfigures a PM3000. Follow `DEVICE-TEST.md` manually and retain the vendor SSH service.
