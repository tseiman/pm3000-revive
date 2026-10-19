# Verification Report

Date: initial verification 2026-10-18 UTC; component-path rebuild and verification repeated 2026-10-19 UTC.

## Passed checks

- Cross-toolchain completed successfully with GCC 14.4.0, Binutils 2.44, musl 1.2.6, and Linux 2.6.23 headers.
- Both binaries built and stripped successfully.
- `file`: ELF 32-bit MSB PowerPC executables, statically linked.
- `readelf`: no `PT_INTERP`, no `DT_NEEDED`, no dynamic section, non-executable GNU stack.
- Target compiler defaults: `-mcpu=e300c3`, `-msoft-float`, secure PLT enabled.
- QEMU user-mode executed `dropbear -V` and algorithm queries.
- QEMU user-mode generated an Ed25519 host key with target `dropbearkey`.
- OpenSSH verified the generated Ed25519 host key.
- Isolated server accepted Ed25519 public-key authentication.
- Non-PTY remote command returned `COMMAND_OK`.
- OpenSSH reported `PTY allocation request accepted`.
- A subsequent independent SSH connection returned `RECONNECT_OK`.

The machine-readable test markers are in `artifacts/logs/qemu-user-ssh-test.txt`.

## Advertised algorithms

- KEX: sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com, curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group14-sha256
- Signatures: ssh-ed25519, rsa-sha2-256
- Ciphers: chacha20-poly1305@openssh.com, aes256-ctr, aes128-ctr
- MAC: hmac-sha2-256

## Sizes and hashes

- `dropbear`: 394756 bytes; SHA-256 `bac507ee52198ea337c8573cf9489109c9d6ef71706f13b25302f143b47b693b`
- `dropbearkey`: 263328 bytes; SHA-256 `97cd3e35b4f9db7ea7a23041f862abe6144b84ee0a6c53fadafedf2996a65d8c`
- Combined binary size: 658084 bytes, below the requested 2 MiB target.

## Limitations

QEMU user mode runs PPC userspace code on the host kernel; it does not emulate the PM3000's Linux 2.6.23 kernel, vendor filesystem, NSS/account database, entropy devices, or hardware. During the forced-PTY test, OpenSSH confirmed successful PTY allocation, but executing a native x86 shell from the PPC QEMU process is a mixed-architecture harness limitation. Full PTY command execution must be confirmed on the device using `DEVICE-TEST.md`.

No target device was contacted or modified.
