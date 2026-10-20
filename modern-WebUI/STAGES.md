# PM3000 Modern Web UI Stages

Each stage is a separate resumable milestone. Finish, verify, commit, and push one stage before starting the next. Do not broaden a stage unless a concrete test failure requires it.

## Stage 0 — Analysis baseline

- Preserve verified architecture, footprint, security boundaries, and unknowns.
- Publish no vendor payload or private device data.
- **Deliverables:** `ANALYSIS.md`, this file, `docs/PROTOCOL.md`, `STATUS.md`.

## Stage 1 — Sanitized protocol evidence

**Status:** complete for the read-only contract. Reviewed `observed-sanitized` firmware 2.0.1.23 fixtures cover login/header, navigation, topology, PDU/outlet inventory, status, and logout. State-changing captures remain deferred to Stage 8 and require explicit hardware approval.

- Build a local Avtrans sanitizer.
- Add synthetic fixtures for login, navigation, inventory, status, errors, and authorization denial.
- Obtain user-run sanitized captures from the real Web UI.
- Do not transmit outlet actions automatically.
- **Gate:** no credential/SID data and no unsupported schema assumptions.

## Stage 2 — Strict REST contract

- Define health, outlet list/detail, and individual outlet actions.
- Reject arbitrary backend paths, unknown fields/actions, malformed JSON/XML, and oversized input.
- Explicitly exclude PDU-wide actions, reboot, firmware, factory default, and generic configuration.
- **Gate:** every accepted REST request maps to one fixed backend template.

## Stage 3 — Multiple bearer tokens

- Store only SHA-256 token digests.
- Support labels, `read`, `control`, and `admin` scopes, optional outlet allowlists, disable, and revoke.
- Create the first admin token via a host-side bootstrap command; manage subsequent tokens through the new Web UI submenu.
- **Gate:** atomic fault-tested persistence retains the previous valid token set after any failure.

## Stage 4 — Read-only native adapter

- Implement a small PPC32 big-endian CGI adapter.
- Reuse Avtrans/uicontrold and a dedicated least-privilege vendor account.
- Start with inventory and status only.
- **Gate:** static target verification and fake-controller tests; state-changing code remains disabled.

## Stage 5 — Read-only modern UI

- Add a responsive, dependency-free UI with familiar PM3000 functional groupings.
- Add the **REST API tokens** administration submenu.
- Use safe DOM APIs, keyboard-accessible controls, and compact bundled SVG only where useful.
- **Gate:** fake-adapter browser check at desktop and narrow widths; release remains within the size budget.

## Stage 6 — Backup-first deployment and rollback

- Create host-side `deploy.sh` and `rollback.sh` plus a minimal device installer.
- Before any installation write: create a complete remote archive, transfer it to the host with SCP, compare remote/local SHA-256, inspect contents, and publish `BACKUP_COMPLETE` locally.
- Install from a checksummed allowlist into a versioned persistent directory.
- Restore exactly the previous files and remove only files created by the selected deployment.
- Never reboot or switch an outlet.
- **Gate:** isolated failure-injection simulation proves no install write before backup and byte-identical rollback.

## Stage 7 — Manual read-only device pilot

- User runs preflight, backup, `/modern/` pilot installation, status checks, and one rollback.
- Preserve the legacy UI at `/`.
- Verify Apache Authorization-header handling rather than assuming it.
- **Gate:** user-approved read-only report and successful rollback.

## Stage 8 — Individual outlet control

- Enable only captured and verified `on`, `off`, and `cycle` templates.
- Enforce token scope, optional outlet allowlist, fresh inventory mapping, confirmations, and no automatic `cycle` retry.
- A timeout after dispatch is reported as an unknown result.
- **Gate:** the user explicitly chooses a non-critical outlet and approves one manual action at a time.

## Stage 9 — Legacy-function parity

- Inventory every legacy menu/page and classify it as migrated, intentionally retired, or retained through the legacy route.
- Migrate required read/write functions one module at a time from sanitized captured contracts.
- Never use a generic backend-path executor to obtain apparent parity.
- **Gate:** user-approved parity matrix; every required function has a focused contract test or an explicit working legacy fallback.

## Stage 10 — Cutover and release

- Make the modern UI the normal entry only after pilot acceptance.
- Keep a documented legacy recovery route and host-side backup.
- Package from allowlists, verify checksums and footprint, and publish tested artifacts.

## Resume rule

Read `STATUS.md`, `ANALYSIS.md`, and this file, then check `git status`. Continue only the named next stage; do not repeat completed analysis or introduce a broad test matrix without a concrete blocker.
