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
- The manual test procedure uses public-key-only mode (`-s`) and a non-conflicting port.

## Login-shell extension

`--login-shell /absolute/path` is a project-specific, optional server setting. At startup, before listeners are created, Dropbear requires the path to be absolute and to identify an existing executable regular file. The configured value is global to that server instance.

The override is applied only in the already-authorized session child. User lookup, authentication, the account's original login-shell check, `-w` root-login restriction, UID/GID setup, and other account controls continue to use the original account data. It does not make an otherwise rejected account eligible to log in.

Command policy remains separate from shell selection. A global `-c` forced command and an `authorized_keys` `command=` restriction still select the allowed command and preserve `SSH_ORIGINAL_COMMAND`; the optional session shell only determines which shell executes that selected command. When both forced-command mechanisms exist, Dropbear's existing global forced-command precedence remains unchanged.

Operational security still depends on file ownership/modes, account policy, entropy quality, host-key protection, network filtering, and preserving a recovery path. Re-check upstream releases and advisories before deployment if these artifacts are no longer current.
