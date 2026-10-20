# Modern Web UI Status

## Current checkpoint

Stage 3 is complete. The tested REST v1 contract now includes closed administrator-only token management, and the repository contains a fault-tested host-side token-store/reference administration implementation. No native adapter, replacement UI, or device installation exists yet.

## Completed

- Stage 0 analysis of the supplied firmware-derived Web UI/backend archive.
- Static mapping of Apache, `mod_avtrans`, `/dev/avtrans_socket`, `uicontrold`, GSP/CACPD, and the power backend.
- Legacy Web-root footprint measurement and initial REST/token/deployment boundaries.
- Local Avtrans sanitizer with bounded XML input, structural validation, explicit redaction, and atomic mode-`0600` output.
- Twenty focused sanitizer/fixture tests developed with red-green cycles, including UTF-16 DTD, namespace, mixed-content, SID-subtree, operator-name/serial, attribute, symlink, FIFO, and observed-fixture provenance cases.
- Eight parseable synthetic Avtrans fixtures plus a machine-readable provenance manifest.
- Twelve parseable `observed-sanitized` Avtrans fixtures plus a machine-readable provenance manifest.
- A short, passive browser capture procedure that forbids replay and Stage 1 outlet actions.
- Operator-reported storage snapshot documenting 28.9 MiB free on `/`, 27.8 MiB on `/var`, and 2.3 MiB on `/mnt/hdUser`.
- Authenticated read-only device pages confirmed firmware 2.0.1.23, model/CPU identity fields, and live memory/flash table schemas without changing configuration or power state.
- A machine-readable OpenAPI 3.1 REST v1 contract and normative contract document.
- Opaque outlet/PDU identifiers, inventory-revision semantics, exact route/method allowlists, closed JSON schemas, bounded input, and fixed read templates.
- A reserved `on`/`off`/`cycle` request shape whose Stage 3 response remains `503 action_disabled` with no backend request.
- A host-side strict token store with digest-only persistence, `read`/`control`/`admin` scopes, outlet allowlists, enable/disable/revoke, and final-administrator protection.
- Directory-FD-anchored locking and atomic persistence with strict JSON/owner/mode/link validation, bounded reads, pre-commit preservation, and explicit post-commit durability semantics.
- A host administration command that bootstraps and manages tokens without placing administrator credentials in command arguments or environment variables.
- Closed `admin`-only REST token-management operations with no HTTP bootstrap, digest export, plaintext recovery, generic patch, or backend request.

## Verified gate

- All 60 sanitizer, fixture, REST-contract, token-store, and token-administration tests pass.
- Every synthetic XML fixture parses with `<avtrans>` as its root.
- Every XML fixture is declared with evidence level `synthetic` in `manifest.json`.
- Every observed XML fixture parses with `<avtrans>` as its root and is declared with evidence level `observed-sanitized`.
- A transport timeout is modeled as no response, not invented backend XML.
- The PM3000 was contacted only through authenticated read-only HTTPS requests and logout; no configuration or outlet/PDU action was sent.
- No firmware binary was executed.
- No vendor payload or raw device capture was copied into the repository.
- Every non-health REST route requires bearer authentication; outlet reads/actions have explicit scope and allowlist behavior, and token administration requires `admin`.
- The action route has no backend template and no 2xx response in Stage 3.
- Token plaintext is flushed exactly once before publication, never persisted or listed; output failure publishes no record, and post-commit durability uncertainty retains the already delivered credential.
- Store and lock symlinks/non-regular files, malformed/deep JSON, invalid Unicode, duplicate members/IDs/digests, unsafe permissions, and final-administrator removal fail closed.
- Every REST response disables caching and content sniffing.

## Open evidence and later-stage blockers

- Login failure, session-expiry, authorization-denial, malformed-response, and timeout behavior still lack observed fixtures.
- Exact state-changing request payloads for individual outlet `on`, `off`, and `cycle` remain unknown. Observed response control IDs and row structures must not be converted into action templates without a separately approved hardware capture.
- The active-device copies of the historical compatibility loader and modified xWire file are not available for fallback validation.
- Unix-socket framing and Apache CGI `Authorization`-header behavior are not yet proven.
- A dedicated least-privilege vendor service account has not been provisioned or tested.

## Next step

Proceed to Stage 4: implement a small PPC32 big-endian native adapter for local health, fixed read-only outlet projections, and the validated Stage 3 token-store/authorization contract. Outlet-action dispatch remains disabled and is a separately approved Stage 8 task.
