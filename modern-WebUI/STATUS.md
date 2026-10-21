# Modern Web UI status

## Current checkpoint

The current offline candidate implements PM3000-backed WebUI sessions, token administration, validated outlet and PDU inventory, fixed power actions, self-service password change, typed DSView/NIS settings, and seven session-only read-only system and monitoring endpoints with typed C99 parsers, OpenAPI v1.3.0 schemas, and dependency-free browser views. The previously installed `0.1` pilot remains the live baseline; none of the current write-capable code has been installed or executed on the appliance.

## Implemented

- Static C99 CGI for PPC32 big-endian e300c3 soft-float.
- Existing-PM3000 username/password login, server-side GSP sessions, 15-minute idle expiry, hardened cookie, CSRF, logout, and bounded session cleanup.
- Server-derived, fixed-allowlist navigation and conservative rights gates.
- External REST bearer authentication with `read`, `control`, and `admin` scopes and optional outlet allowlists.
- Token list/create/enable/disable/revoke with digest-only persistence, one-time secret output, final-administrator protection, and preservation of `/mnt/hdUser/pm3000-revive/rest/tokens.json`.
- Outlet inventory and `on`, `off`, and `cycle`. Public actions map to firmware controls `targPowerOn`, `targPowerOff`, and `targCycle` on `units.topology` / `topologyTable` after a fresh server-side row lookup.
- PDU inventory plus PDU-wide `on`, `off`, and `cycle` on `units.powermanagement.pdu_management` / `pdu_devices_table`, also using a fresh server-side row lookup.
- Inventory-revision checks reject stale client mappings. Neither outlet nor PDU APIs accept raw controller row IDs.
- Power `on`/`off` writes return success only when a validated operation-specific inventory response reports the targeted outlet or PDU in the requested state. A `cycle` cannot be confirmed from a stable state and therefore returns `action_outcome_unknown` after dispatch. Password changes require the exact firmware-derived success-form hierarchy; settings writes require exact typed read-back of every submitted field. A transport failure, mismatch, or unexpected response after dispatch is never retried automatically.
- Session-only password change with `units.change_password` authorization, CSRF, old password, matching new-password confirmation, secret zeroing, and expected response path `units.change_password.changedPassword`.
- Session-only complete-replacement settings for DSView HTTPS allowance (`SecurityDSView` / `dsviewControl`) and NIS (`nis` / `nisserver`). Both use fixed paths, actions, form structure/order, PM3000 navigation rights, CSRF, closed JSON, fresh-read UI gating, and fail-closed response parsing. They do not infer PM3000 configuration rights from REST bearer scopes. DSView remains supported at this level but is not a priority for further expansion.
- Session-only read-only system and monitoring endpoints: `GET /api/v1/system/information` (appliance identity fields, serial number excluded), `GET /api/v1/system/usage/memory` (memory rows), `GET /api/v1/system/usage/flash` (filesystem rows), `GET /api/v1/monitoring/network/devices` (device rows), `GET /api/v1/monitoring/network/routes/ipv4` (IPv4 route rows), `GET /api/v1/monitoring/network/routes/ipv6` (IPv6 route rows), `GET /api/v1/monitoring/serial-ports` (serial port statistics rows). All seven reject bearer tokens with 401, use cookie session with navigation-path capability gates, return 503 on transport failure and 502 on malformed backend response, and are documented in OpenAPI v1.3.0 with closed `additionalProperties: false` schemas.
- Dependency-free browser UI for outlet and PDU inventory/actions, password change, REST-token administration, and all seven new read-only monitoring/system views with loading state, error state, and textContent rendering. No innerHTML. No browser storage. Non-migrated pages remain available through the legacy UI.
- Backup-first host installer using a temporary OpenSSH ControlMaster; manual rollback remains separate.

## Static write-contract analysis

Offline correlation of `avrel.xml`, the legacy JavaScript/XSL serializer, feature modules, validation definitions, and observed sanitized reads found 30 `COMPLETE_STATIC` contracts: 20 fixed settings actions and 10 fixed create/save flows. They are not all implemented yet. Dynamic object-edit families remain deferred until each runtime row/path/form variant can be resolved from a fresh GET without guessing.

Firmware update, setup wizard, reboot, reset, shutdown, factory default, and configuration restore remain excluded.

## Current verification

- Current complete repository suite: 177 tests passing.
- Strict host C99 build with `-Wall -Wextra -Werror -pedantic` passes.
- Static PPC32 big-endian target build passes and is identified as a stripped, statically linked 32-bit MSB PowerPC ELF.
- QEMU `-cpu e300c3` executes the production binary and returns the expected HTTPS-only health response.
- Two independent read-only review passes completed. Findings on production credential paths and prerequisites, stale settings UI state, exact XML form validation, operation-specific write confirmation, password-success parsing and secret wiping, transport/protocol status separation, and OpenAPI consistency are resolved; the final review reports no release blocker. The proposed 100-character NIS change was rejected because the firmware contract is strictly `< 100`, i.e. at most 99 payload bytes.

## Controlled device-validation boundary

No appliance action is automatic. A future device test requires an approved maintenance window and a designated target. Because no sanitized successful or failed write-response capture exists, the first approved test must capture and sanitize the response and compare it with the static response parser before any broader rollout.

## Safety statement

Offline development and tests have not contacted `/dev/avtrans_socket`, changed a setting, restarted the appliance, switched an outlet, changed a password, or written firmware. Vendor firmware, raw captures, credentials, sessions, private backups, and production token data remain outside Git and release artifacts.
