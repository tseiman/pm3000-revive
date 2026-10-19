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

Operational security still depends on file ownership/modes, account policy, entropy quality, host-key protection, network filtering, and preserving a recovery path. Re-check upstream releases and advisories before deployment if these artifacts are no longer current.
