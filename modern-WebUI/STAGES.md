# PM3000 Modern Web UI Stages

Stages describe the project lifecycle. Large stages may be split into smaller, independently reviewed milestones. Finish, verify, commit, and push each named milestone before starting the next one. A milestone release is an offline, reproducible repository checkpoint; only Stage 10 is the final appliance cutover and product release.

**Legend:** ✅ completed · 🟡 in progress or offline implementation complete with a live-device gate still open · ⬜ pending

## ✅ Stage 0 — Analysis baseline

- Preserve verified architecture, footprint, security boundaries, and unknowns.
- Publish no vendor payload or private device data.
- **Deliverables:** `ANALYSIS.md`, this file, `docs/PROTOCOL.md`, `STATUS.md`.

## ✅ Stage 1 — Sanitized protocol evidence

**Status:** complete for the read-only contract. Reviewed `observed-sanitized` firmware 2.0.1.23 fixtures cover login/header, navigation, topology, PDU/outlet inventory, status, and logout. State-changing captures remain deferred to Stage 8 and require explicit hardware approval.

- Build a local Avtrans sanitizer.
- Add synthetic fixtures for login, navigation, inventory, status, errors, and authorization denial.
- Obtain user-run sanitized captures from the real Web UI.
- Do not transmit outlet actions automatically.
- **Gate:** no credential/SID data and no unsupported schema assumptions.

## ✅ Stage 2 — Strict REST contract

**Status:** complete. The tested OpenAPI contract exposes local health, fixed read-only outlet list/detail projections, and a closed individual-action request shape that Stage 2 always rejects without constructing or sending Avtrans XML.

- Define health, outlet list/detail, and individual outlet actions.
- Reject arbitrary backend paths, unknown fields/actions, malformed JSON/XML, and oversized input.
- Explicitly exclude PDU-wide actions, reboot, firmware, factory default, and generic configuration.
- **Gate:** every read request maps to one fixed backend template; health is local-only; Stage 2 actions have no backend template and no success response.

## ✅ Stage 3 — Multiple bearer tokens

**Status:** complete for the persistent model, host administration tool, and REST contract. The Stage 4 native adapter must port the validated store reader/writer and authorization semantics; the visual administration submenu remains a Stage 5 deliverable.

- Store only SHA-256 token digests.
- Support labels, `read`, `control`, and `admin` scopes, optional outlet allowlists, disable, enable, and revoke.
- Create the first admin token via a host-side bootstrap command; expose only closed `admin`-only management operations for the later Web UI submenu.
- **Gate:** atomic fault-tested persistence retains the previous valid token set after every pre-commit failure and reports post-rename durability uncertainty distinctly.

## ✅ Stage 4 — Read-only native adapter

**Status:** complete. The native adapter, token administration, disabled-action boundary, PPC target, failure semantics, and security/boundary matrix are locally verified and independently reviewed with PASS.

- Implement a small PPC32 big-endian CGI adapter.
- Reuse Avtrans/uicontrold and a dedicated least-privilege vendor account.
- Start with inventory and status only.
- **Gate:** static target verification and fake-controller tests; state-changing code remains disabled.

## ✅ Stage 5 — Read-only modern UI

**Status:** complete. The REST-v1-only Web UI, token administration flows, in-memory secret lifecycle, responsive layout, fake adapter, and Firefox browser gates are locally verified and independently reviewed with PASS.

- Add a responsive, dependency-free UI with familiar PM3000 functional groupings.
- Add the **REST API tokens** administration submenu.
- Use safe DOM APIs, keyboard-accessible controls, and compact bundled SVG only where useful.
- **Gate:** fake-adapter browser check at desktop and narrow widths; release remains within the size budget.

## ✅ Stage 6 — Backup-first deployment and rollback

**Status:** complete, independently reviewed, committed, and published. The host entry points remain
simulation-only and fail closed for remote targets. Live SSH/SCP and appliance
installation remain blocked on the Stage 7 observations below.

- Create host-side `deploy.sh` and `rollback.sh` plus a minimal device installer.
- Before any installation write: create a complete remote archive, transfer it to private host storage, compare remote/local SHA-256, inspect contents, and publish `BACKUP_COMPLETE` locally. Stage 6 proves this sequence with isolated transport simulation; Stage 7 must verify SCP and target identity on the appliance.
- Install from a checksummed allowlist into a versioned persistent directory.
- Restore exactly the previous files and remove only files created by the selected deployment.
- Never reboot or switch an outlet.
- **Gate:** isolated failure-injection simulation proves no install write before backup, exact release-tree validation, recovery from real process exits at publication boundaries, and byte-identical rollback.

## ✅ Stage 7 — Manual read-only device pilot

**Status:** release `0.1` is the installed read-only pilot and remains the live baseline. The current Stage 9 candidate, including every write-capable route, has not been installed or executed on the appliance. No real setting write or power action has been performed. Backup, rollback, and Apache acceptance gates remain explicit operator checks for every later candidate.

The operator-provided preflight confirms PPC Linux 2.6.23, BusyBox 1.5.0,
Apache 2.2.23 with CGI/SSL/Alias support, valid Apache syntax, writable `/etc`
and `/mnt/hdUser` mounts, and `/dev/avtrans_socket`. Device integrity checks use
the confirmed `openssl dgst -sha256`; the appliance has no `sha256sum` command.

- User runs preflight, backup, `/modern/` pilot installation, status checks, and one rollback.
- Preserve the legacy UI at `/`.
- Verify Apache Authorization-header handling rather than assuming it.
- **Gate:** user-approved read-only report and successful rollback.

## 🟡 Stage 8 — Individual outlet control

**Status:** implemented and independently reviewed offline. Outlet and PDU `on`, `off`, and `cycle` use fixed contracts, fresh server-side identity resolution, revisions, rights, and no automatic retry. The live gate remains open because no real device action has been approved or executed.

- Enable only captured and verified `on`, `off`, and `cycle` templates.
- Enforce token scope, optional outlet allowlist, fresh inventory mapping, confirmations, and no automatic `cycle` retry.
- A timeout after dispatch is reported as an unknown result.
- **Gate:** the user explicitly chooses a non-critical outlet and approves one manual action at a time.

## 🟡 Stage 9 — Legacy-function parity

**Status:** in progress through the resumable milestones below. Development may continue offline, but no write-capable milestone is considered device-validated until its explicit Stage 8/9 operator gate has been completed.

- Inventory every legacy menu/page and classify it as migrated, intentionally retired, or retained through the legacy route.
- Migrate required read/write functions one module at a time from sanitized captured contracts.
- Never use a generic backend-path executor to obtain apparent parity.
- **Gate:** user-approved parity matrix; every required function has a focused contract test or an explicit working legacy fallback.

### ✅ Stage 9 milestone 1 — Typed read-only system and monitoring

**Status:** complete, independently reviewed, committed, and published as `20d7b66`.

- Adds seven session-only typed reads for system information, memory, flash, network devices, IPv4/IPv6 routes, and serial-port statistics.
- Rejects bearer authentication before backend access and exposes no raw XML, backend IDs, hidden fields, or private serial number.

### ✅ Stage 9 milestone 2A — Fixed-form foundation and first revisioned settings

**Status:** complete, independently reviewed with `BLOCKERS: NO`, committed, and published as `d2c97e6`.

- Adds the reusable typed fixed-form parser/serializer and `GET|PUT` resources for Help and Language and Data Buffering.
- Requires a fresh validated GET, exact capability, cookie session, CSRF, strong `ETag`/`If-Match`, complete replacement, exact typed read-back, and no retry after an uncertain dispatch.
- The full suite contains 195 passing tests; strict host C99, OpenAPI, JavaScript, PPC32 big-endian, and QEMU e300c3 gates pass.
- No real PM3000 setting write was performed; synthetic fixtures do not replace an approved device test.

### 🟡 Stage 9 milestone 2B — Remaining low-risk fixed settings

**Status:** in progress. Appliance Logging is published at `0ee3fbc`. Time Zone is the next bounded offline candidate; final release gates and independent review remain open.

- Validates the exact nested firmware form, fixed destination/timestamp choices, booleans, and ten 64-byte alert strings.
- Uses a closed conditional request union: inactive descendants are omitted from the save and must remain unchanged in the typed post-save response.
- Requires cookie session, exact `configuration.event-notify:w` capability, CSRF, strong `ETag`/`If-Match`, and no retry after uncertain dispatch.
- Applies to newly opened sessions only. No real setting write or runtime-effect validation has been performed.
- Adds conditional Time Zone `GET|PUT` with inherited `management.date:w`, firmware-bound runtime choices, predefined/custom/custom-with-DST serialization, inactive-state preservation, exact typed read-back, and a cross-process settings-write lock.
- The parser's fixed 569-choice capacity covers the 521 firmware-provided predefined zones plus 48 fixed transition choices. The zones remain runtime values, not a hard-coded enum.
- No observed Time Zone GET/save capture exists. Firmware file/script side effects and post-commit error ordering remain unverified; no live write or installation is authorized by this offline slice.
- Further lockout-sensitive network, security, boot, and authentication writes require a documented recovery path and explicit device-test approval.

### ⬜ Stage 9 milestone 3 — Static create/save flows

**Status:** pending. Implement only statically closed create/save contracts with field-specific request, authorization, and success semantics.

### ⬜ Stage 9 milestone 4 — Runtime-resolved CRUD

**Status:** pending. Dynamic object edits require a fresh validated GET, opaque project IDs, revisions, complete state preservation, and exact operation-specific confirmation.

### ⬜ Stage 9 milestone 5 — Parity closure

**Status:** pending. Reconcile all 43 terminal legacy menu entries as migrated, intentionally retained, or excluded, then repeat complete platform, security, documentation, and independent release review gates.

## ⬜ Stage 10 — Cutover and release

**Status:** not started. Stage 9 milestone releases are not Stage 10 or proof of live firmware behavior.

- Make the modern UI the normal entry only after pilot acceptance.
- Keep a documented legacy recovery route and host-side backup.
- Package from allowlists, verify checksums and footprint, and publish tested artifacts.

## Resume rule

Read `STATUS.md`, `ANALYSIS.md`, and this file, then check `git status`. Continue only the named next stage; do not repeat completed analysis or introduce a broad test matrix without a concrete blocker.
