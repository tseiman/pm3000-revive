# Modern Web UI Status

## Current checkpoint

Stages 4, 5, and 6 are implemented, locally verified, independently reviewed with PASS, and published. The operator-provided Stage 7 preflight confirmed the initial managed paths are absent and identified OpenSSL as the device SHA-256 provider. A macOS/Linux full-device SSH backup completed, and fixed selective restore profiles can produce local component-only restore artifacts. No upload or installation has run. Nothing has been installed on a PM3000.

## Completed through Stage 3

- Clean-room architecture analysis and bounded, sanitized Avtrans evidence.
- Strict OpenAPI 3.1 REST v1 contract with opaque IDs and closed schemas.
- Host-side digest-only token store and administration tool.
- `read`, `control`, and `admin` scopes with outlet allowlists and final-administrator protection.
- Reserved outlet-action contract that remains `503 action_disabled` without a backend request.

## Stage 4 implementation

- Native C99 CGI runtime for PPC32 big-endian e300c3 soft-float.
- Fixed read-only Avtrans login, `get units.topology`, and logout sequence.
- Bounded XML validation and strict outlet collection/detail projection.
- Native Stage 3 token-store reader, authorization, atomic writer, and all five administrator routes.
- Production paths fixed at compile time; environment overrides exist only in the `PM3000_TESTING` host build.
- HTTPS requirement and `no-store`/`nosniff` response headers.
- Outlet actions remain disabled and do not open the Avtrans socket.
- Build, security boundary, deployment preconditions, and rollback design documented in `docs/NATIVE-ADAPTER.md`.

## Stage 5 implementation

- Dependency-free HTML, CSS, and JavaScript assets.
- Responsive PM3000-style Monitoring and Administration groupings.
- Read-only outlet inventory/status with no outlet-action controls.
- **REST API tokens** submenu for list, create, enable, disable, and revoke.
- Restricted outlet allowlists use explicit opaque IDs; omitted list means unrestricted and an empty list means deny all.
- Safe DOM construction without HTML sinks.
- Bearer token held only in memory and cleared on disconnect/page hide.
- One-time created token cleared on native dialog close, including `Esc`.
- Local-only fake adapter and readiness-aware Firefox WebDriver check with synthetic data.
- Production release manifest contains exactly `index.html`, `styles.css`, and `app.js`.

## Stage 6 implementation

- Fixed-interface host package, deploy, and rollback commands; remote targets remain disabled.
- Complete recursive no-follow backup of managed Web UI, REST, deployment-state, Apache-config, and private REST-config scopes.
- Private remote/local archives, SHA-256 comparison, safe archive inspection, descriptor-bound capture, and durable `BACKUP_COMPLETE` before package staging.
- Transaction UUID, UTC capture time, synthetic target/firmware identity, integrity-bound deployment state, and one active-transaction record.
- Versioned immutable release directories and one atomic `current` pointer for CGI plus Web assets.
- Static PPC `renameat(2)`/parent-`fsync(2)` helper; staged and pre-existing release trees require an exact allowlist, trusted effective-UID ownership, fixed root/subdirectory/file modes, regular single-link payload inodes, and canonical package-anchored checksum verification in the device scripts.
- Full release-tree drift checks, single-open package snapshots, backup-bound recovery intent before release-tree creation, crash recovery during temporary-tree creation, first payload write, and final rename, plus resumable, integrity-bound `ROLLBACK_PENDING` recovery.
- Apache pilot maps `/modern/` to static assets and `/api/v1` to the CGI with tested `SCRIPT_NAME` plus `PATH_INFO` routing.
- Token store and controller credentials are backed up but not replaced by normal deployment or rollback.

## Verified gates

- The historical Stage 4/5 gate passed all 93 sanitizer, fixture, REST-contract, token-store, native-adapter, and UI-asset tests. The expanded repository suite passes all 142 tests, including the Stage 7 read-only preflight, portable macOS/Linux backup, selective restore, and adversarial end-to-end fixed `/tmp` device-compatibility contracts.
- Two clean native target builds are byte-identical.
- Target binary: stripped static ELF32, big-endian PowerPC, no dynamic interpreter.
- Build uses `-mcpu=e300c3 -msoft-float`; disassembly contains no PPC floating-point instruction matches.
- QEMU `-cpu e300c3` executes the target health CGI and returns HTTP/CGI 200 with the REST v1 health payload.
- Target binary: 132,340 bytes.
- Current target SHA-256 after Stage 6 CGI path integration: `b2500ab6fc83e7b53ecbe58e53b214dc4e02be589e56831a7a1856a83ef656ae`.
- Three production Web assets: 29,366 bytes.
- Atomic publication helper: 66,408 bytes; SHA-256 `2c868b6f3efbd1d4fbeeab2b28d727761d625aed64c2a0701f8845603c4caecd`.
- REST binary, atomic helper, and Web assets total 228,114 bytes of the 409,600-byte budget.
- Deterministic eight-member release archive: 245,760 bytes.
- Browser gate renders eight synthetic outlets and three initial tokens; proves cancel-safe and duplicate-safe creation; verifies restricted and unrestricted payloads; checks the one-time 47-character bearer value; clears it through native dialog close and disconnect; verifies `204` disable, enable, and revoke handling; and confirms an operable Disconnect control with zero horizontal overflow at Firefox's actual 438-CSS-pixel narrow viewport.
- Desktop and narrow screenshots contain only synthetic identifiers and generic outlet names.

## Open evidence and later-stage blockers

- Login failure, session expiry, authorization denial, malformed response, and timeout still lack observed device fixtures.
- Exact state-changing payloads for outlet `on`, `off`, and `cycle` remain unknown and must not be guessed.
- Apache CGI `Authorization` forwarding, `AcceptPathInfo`, and the complete target-device Unix-socket behavior require Stage 7 passive/device validation.
- A dedicated least-privilege vendor service account has not been provisioned or tested.
- A fixed backup-gated SSH/SCP compatibility command is ready but has not yet been run against the appliance. Target execution, ownership/modes, and BusyBox behavior therefore remain unverified; physical-filesystem directory `fsync` also remains outside this `/tmp` check and live deployment stays disabled.

## Safety statement

No PM3000 was contacted for Stage 4, Stage 5, or Stage 6 development, builds, tests, simulations, or screenshots. No setting was changed, no service was restarted, no firmware was written, and no outlet was switched.

## Next step

After the Stage 6 independent PASS and release commit, proceed only to the user-approved Stage 7 read-only preflight and manual pilot. Outlet-action dispatch remains deferred to a separately approved Stage 8 capture and implementation.
