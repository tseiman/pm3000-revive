# Verification Report

Date: initial verification 2026-10-18 UTC; component-path rebuild and login-shell extension verified 2026-10-19 UTC; installer simulation added 2026-10-20 UTC.

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
- `--login-shell` help and startup validation passed for relative, missing, directory, non-executable, missing-argument, and duplicate-option cases.
- Startup with no override retained the account shell (`sh|/bin/sh`).
- A remote command with `--login-shell /bin/bash` ran through Bash and exported `SHELL=/bin/bash`.
- The login-shell test server accepted a PTY allocation with the override enabled.
- `authorized_keys` `command=` and global `-c` forced commands remained effective, retained `SSH_ORIGINAL_COMMAND`, and used the selected session shell.
- The existing global forced command retained precedence when both forced-command mechanisms were present.
- An account with a shell absent from `/etc/shells` remained rejected, and the existing `-w` root-login restriction was not bypassed.
- `-G root` allowed the root account, rejected the non-member test account, and continued to use `/bin/bash` only for the admitted session.
- The two-phase installer simulation passed real `/proc/net/tcp` socket-to-PID resolution, OpenSSH detection without an explicit port argument, package-corruption rejection, rejection of payload-plus-manifest replacement after initial verification, pre-mutation rejection of protected child-directory symlinks, non-use of legacy runtime-log symlinks, foreign test-port detection with an unrelated PID file, exact historical-build no-op handling despite an unrelated occupied test port, fresh preparation, root-only staging cleanup, launch-PID rollback of a child delayed longer than the former wait bound, idempotent preparation, rollback-prepare-rollback repetition, host-key retention, explicit activation gates, rejected activation recovery, failed-TERM fail-closed behavior, successful activation, active-installation no-op behavior, targeted listener shutdown, original-init content/mode restoration, preserved-`$0` OpenSSH startup fallback after a managed-binary validation failure, and OpenSSH rollback.

The machine-readable test markers are in `artifacts/logs/qemu-user-ssh-test.txt`, `artifacts/logs/login-shell-test.txt`, and `artifacts/logs/installer-test.txt`.

## Reported PM3000 hardware results

The operator reported successful tests of this exact Dropbear build on a PM3000 running firmware `2.0.1.23`: program startup and help, Ed25519 host-key generation, modern Ed25519 handshake, password login for root and a regular account, interactive Bash, remote commands, classic `scp -O`, background operation on port 22, and SysV startup after a real reboot. SFTP was not installed or tested.

These are historical device results supplied by the operator. The new packaged installer scripts were not executed on a PM3000 during repository development and must follow the manual acceptance sequence in `installer/README.md`.

## Advertised algorithms

- KEX: sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com, curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group14-sha256
- Signatures: ssh-ed25519, rsa-sha2-256
- Ciphers: chacha20-poly1305@openssh.com, aes256-ctr, aes128-ctr
- MAC: hmac-sha2-256

## Sizes and hashes

- `dropbear`: 394756 bytes; SHA-256 `ed00d4f9f3e034f4991da8304269876f457615f7e786f45d26b829d8cc11b2a1`
- `dropbearkey`: 263328 bytes; SHA-256 `97cd3e35b4f9db7ea7a23041f862abe6144b84ee0a6c53fadafedf2996a65d8c`
- Combined binary size: 658084 bytes, below the requested 2 MiB target.

## Limitations

QEMU user mode runs PPC userspace code on the host kernel; it does not emulate the PM3000's Linux 2.6.23 kernel, vendor filesystem, NSS/account database, entropy devices, or hardware. OpenSSH confirmed successful PTY allocation, but executing a host-native shell in the PPC QEMU PTY child is a mixed-architecture harness limitation. The installer regression suite uses isolated host-native fake daemons and filesystem roots; it proves state transitions and process-selection behavior, not target-kernel compatibility or boot persistence.

No target device was contacted or modified.
