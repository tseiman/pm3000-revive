# Modern Web UI Status

## Current checkpoint

Stage 1 is complete for the read-only contract. Reviewed, sanitized firmware 2.0.1.23 fixtures now cover login/header, navigation, topology, PDU/outlet inventory, status, and logout. State-changing evidence remains intentionally deferred to Stage 8 and requires explicit hardware approval.

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

## Verified gate

- All 20 sanitizer and fixture tests pass.
- Every synthetic XML fixture parses with `<avtrans>` as its root.
- Every XML fixture is declared with evidence level `synthetic` in `manifest.json`.
- Every observed XML fixture parses with `<avtrans>` as its root and is declared with evidence level `observed-sanitized`.
- A transport timeout is modeled as no response, not invented backend XML.
- The PM3000 was contacted only through authenticated read-only HTTPS requests and logout; no configuration or outlet/PDU action was sent.
- No firmware binary was executed.
- No vendor payload or raw device capture was copied into the repository.

## Open evidence and later-stage blockers

- Login failure, session-expiry, authorization-denial, malformed-response, and timeout behavior still lack observed fixtures.
- Exact state-changing request payloads for individual outlet `on`, `off`, and `cycle` remain unknown. Observed response control IDs and row structures must not be converted into action templates without a separately approved hardware capture.
- The active-device copies of the historical compatibility loader and modified xWire file are not available for fallback validation.
- Unix-socket framing and Apache CGI `Authorization`-header behavior are not yet proven.
- A dedicated least-privilege vendor service account has not been provisioned or tested.

## Next step

Define the narrow Stage 2 REST contract from the observed read-only fixtures. Keep arbitrary backend paths, PDU-wide operations, configuration, and state-changing outlet actions outside the contract; action enablement remains a separately approved Stage 8 task.
