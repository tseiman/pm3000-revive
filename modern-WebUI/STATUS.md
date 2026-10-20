# Modern Web UI Status

## Current checkpoint

Stages 4 and 5 are implemented, locally verified, and independently reviewed with PASS. Nothing has been installed on a PM3000.

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

## Verified gates

- All 93 sanitizer, fixture, REST-contract, token-store, native-adapter, and UI-asset tests pass.
- Two clean native target builds are byte-identical.
- Target binary: stripped static ELF32, big-endian PowerPC, no dynamic interpreter.
- Build uses `-mcpu=e300c3 -msoft-float`; disassembly contains no PPC floating-point instruction matches.
- QEMU `-cpu e300c3` executes the target health CGI and returns HTTP/CGI 200 with the REST v1 health payload.
- Target binary: 132,340 bytes.
- Target SHA-256: `226a7d45df550cdaa94de5c15c7570661738e14e00186d9a57b51e113d7e0b0f`.
- Three production Web assets: 29,366 bytes.
- Combined native plus Web assets: 161,706 bytes of the 409,600-byte budget.
- Browser gate renders eight synthetic outlets and three initial tokens; proves cancel-safe and duplicate-safe creation; verifies restricted and unrestricted payloads; checks the one-time 47-character bearer value; clears it through native dialog close and disconnect; verifies `204` disable, enable, and revoke handling; and confirms an operable Disconnect control with zero horizontal overflow at Firefox's actual 438-CSS-pixel narrow viewport.
- Desktop and narrow screenshots contain only synthetic identifiers and generic outlet names.

## Open evidence and later-stage blockers

- Login failure, session expiry, authorization denial, malformed response, and timeout still lack observed device fixtures.
- Exact state-changing payloads for outlet `on`, `off`, and `cycle` remain unknown and must not be guessed.
- Apache CGI `Authorization` forwarding and the complete target-device Unix-socket behavior require later passive/device deployment validation.
- A dedicated least-privilege vendor service account has not been provisioned or tested.
- No installer or device deployment has been implemented.

## Safety statement

No PM3000 was contacted for Stage 4 or Stage 5 development, builds, tests, or screenshots. No setting was changed, no service was restarted, no firmware was written, and no outlet was switched.

## Next step

Proceed to Stage 6 only as a separate backup-first installer/fallback milestone. Outlet-action dispatch remains deferred to a separately approved Stage 8 capture and implementation.
