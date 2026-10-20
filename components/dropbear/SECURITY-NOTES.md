# Security Notes

Assessment date: 2026-10-18.

- Dropbear 2026.94 (released 2026-07-23) was the current stable upstream release.
- Primary release page: https://matt.ucc.asn.au/dropbear/
- Upstream release: https://github.com/mkj/dropbear/releases/tag/DROPBEAR_2026.94
- Upstream security advisories: https://github.com/mkj/dropbear/security/advisories
- Upstream changelog: https://github.com/mkj/dropbear/blob/master/CHANGES

No newer stable release or published upstream GitHub Security Advisory affecting 2026.94 was identified during the assessment. This is not a guarantee that no unknown vulnerability exists.

Upstream had post-release commits, including an SCP terminal-escaping fix dated 2026-10-05. This build contains neither the Dropbear client nor SCP, so that client-side code path is outside the packaged attack surface.

Hardening choices in this build:

- Server and key generator only; no dbclient, SCP, or SFTP server.
- No forwarding, agent forwarding, X11, compression, CBC, 3DES, DSS, ECDSA, SHA-1 signatures, or SHA-1 MACs.
- Modern advertised algorithms are captured in `TEST-REPORT.md`.
- Static musl linkage avoids dependence on the device's legacy glibc.
- Re-exec is disabled for Linux 2.6.23 compatibility.
- The two-phase installer uses one non-conflicting test port before confirmed activation on port 22. It does not create accounts, install client keys, request passwords, or change the build's authentication mechanisms.

## Login-shell extension

`--login-shell /absolute/path` is a project-specific, optional server setting. At startup, before listeners are created, Dropbear requires the path to be absolute and to identify an existing executable regular file. The configured value is global to that server instance.

The override is applied only in the already-authorized session child. User lookup, authentication, the account's original login-shell check, `-w` root-login restriction, UID/GID setup, and other account controls continue to use the original account data. It does not make an otherwise rejected account eligible to log in.

Command policy remains separate from shell selection. A global `-c` forced command and an `authorized_keys` `command=` restriction still select the allowed command and preserve `SSH_ORIGINAL_COMMAND`; the optional session shell only determines which shell executes that selected command. When both forced-command mechanisms exist, Dropbear's existing global forced-command precedence remains unchanged.

Operational security still depends on file ownership/modes, account policy, entropy quality, host-key protection, network filtering, and preserving a recovery path. Re-check upstream releases and advisories before deployment if these artifacts are no longer current.

## Installer boundary

- Package files and their hashes are verified before persistent changes. The verified manifest hash is checked before and after verification and again after root-only staging, preventing a payload-plus-manifest replacement between those steps. The outer GitHub release checksum must still be verified before running any package script.
- Persistent files, state, backup, and host key are root-only. An existing host key and original init backup are retained rather than overwritten.
- Existing protected directories, including every installation child directory, are rejected if they are symlinks, have an unexpected owner/type, or are group/world writable; these checks occur before `mkdir` or `chmod` can follow an existing child symlink.
- The installer never replaces `/usr/sbin/sshd`, changes account records, remounts filesystems, rotates an existing host key, or reboots the PDU.
- Listener processes are identified by PID, executable, and actual LISTEN-socket ownership resolved from `/proc/net/tcp*` through `/proc/<pid>/fd`; managed Dropbear is also matched against its PID-file and port arguments. This avoids unsupported BusyBox 1.5 `netstat -p`. No `killall`, `pkill`, or executable-wide stop action is used.
- Runtime listener and launch PID files live on `/dev` (tmpfs), not persistent flash. Dropbear runs with `-F` in the background of the service shell, making its launch PID the listener PID; stdout and stderr are redirected to `/dev/null`, so no growing session log is retained.
- The project login-shell override is server-wide. Every account admitted by the configured Dropbear authentication and account checks receives `/bin/bash`; normal UID/GID permissions still apply, but this is broader shell access than the vendor `/usr/bin/cli` environment and must match local policy.
- The preserved OpenSSH start path is a boot/start fallback on port 22, not continuous monitoring. A later Dropbear crash is not automatically repaired.
- Activation does not claim success until an operator confirms a new port-22 session. Reboot persistence remains a separate manual acceptance test.
- Phase 1 records `STATUS=preparing`, its build hash, and test port before launch. Dropbear runs with `-F`; an atomically written launch PID is verified against the exact binary, managed PID-file argument, and port argument, allowing rollback to stop a launch even before it publishes a socket. Normal termination signals are deferred across spawn and state publication so that no unrecorded launch crosses that boundary.
