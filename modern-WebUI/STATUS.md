# Modern Web UI status

## Current checkpoint

The compact write-capable candidate is complete offline and awaits controlled device validation. The previously installed `0.1` pilot remains the live baseline; no current session, token-admin, or outlet-action code has been installed or executed on the appliance.

## Implemented

- Static C99 CGI for PPC32 big-endian e300c3 soft-float.
- Existing-PM3000 username/password login, server-side GSP sessions, 15-minute idle expiry, hardened cookie, CSRF, logout, and bounded session cleanup.
- Server-derived, fixed-allowlist navigation and conservative rights gates.
- External REST bearer authentication with `read`, `control`, and `admin` scopes and optional outlet allowlists.
- Token list/create/enable/disable/revoke; digest-only persistence, one-time secret output, final-administrator protection, and preserved production store at `/mnt/hdUser/pm3000-revive/rest/tokens.json`.
- Outlet inventory plus `on`, `off`, and `cycle`: closed JSON input, stale-inventory check, fresh topology read, server-side row resolution, fixed Avtrans shape, exact action confirmation, and logout cleanup.
- Dependency-free browser UI using PM3000 sessions rather than bearer-token login.
- Full rights-filtered observed navigation; non-migrated pages continue through the legacy UI.
- Backup-first one-command host installer using a temporary OpenSSH ControlMaster; manual rollback remains separate.
- Firmware update is not implemented.

## Current verification

- Repository suite: 148 tests passing.
- Host C99 build: `-Wall -Wextra -Werror -pedantic` passing.
- Static PPC target build and QEMU `-cpu e300c3` health/utility checks passing.
- PPC REST binary: 197,876 bytes.
- Production Web assets: 36,568 bytes.
- Deterministic candidate release archive: 317,440 bytes.
- Release allowlist contains only manifests, Apache configuration, two PPC binaries, and three Web assets.
- Added-line secret/injection scan: no matches.

## Controlled device-validation boundary

The next operation is not automatic. It requires an approved maintenance window and must stop after each minimal check:

1. Install a new candidate through `deploy/stage7-install.sh` using the completed private backup.
2. Verify Apache syntax, `/`, `/modern/`, and `/api/v1/health` without changing settings.
3. Verify login/logout and navigation first with an administrator, then a restricted PM3000 account.
4. Verify token create/list/disable/enable/revoke and confirm the secret is shown once.
5. On one designated test outlet only, verify `on`, `off`, and `cycle` separately with physical confirmation.

No writable modern settings form is enabled yet. Firmware evidence proves the Network Settings `save` path and primary fields, but checkbox sections contain additional server-generated parameters. A sanitized real `get` response and matching `save` request are required before implementing a closed serializer; partial saves are intentionally rejected rather than risk network loss. See `DEFERRED-IMPROVEMENTS.md`.

## Safety statement

Offline development and tests never contacted `/dev/avtrans_socket`, changed a setting, restarted the appliance, switched an outlet, or wrote firmware. Vendor firmware, raw captures, credentials, sessions, private backups, and production token data remain outside Git and release artifacts.
