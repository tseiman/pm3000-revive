# Modern Web UI Status

## Current checkpoint

Stage 1 tooling and synthetic evidence are implemented. Stage 1 remains at the operator-evidence checkpoint until reviewed, sanitized request/response XML from firmware 2.0.1.23 is available.

## Completed

- Stage 0 analysis of the supplied firmware-derived Web UI/backend archive.
- Static mapping of Apache, `mod_avtrans`, `/dev/avtrans_socket`, `uicontrold`, GSP/CACPD, and the power backend.
- Legacy Web-root footprint measurement and initial REST/token/deployment boundaries.
- Local Avtrans sanitizer with bounded XML input, structural validation, explicit redaction, and atomic mode-`0600` output.
- Seventeen focused sanitizer/fixture tests developed with red-green cycles, including UTF-16 DTD, namespace, mixed-content, SID-subtree, attribute, symlink, and FIFO adversarial cases.
- Eight parseable synthetic Avtrans fixtures plus a machine-readable provenance manifest.
- A short, passive browser capture procedure that forbids replay and Stage 1 outlet actions.
- Operator-reported storage snapshot documenting 28.9 MiB free on `/`, 27.8 MiB on `/var`, and 2.3 MiB on `/mnt/hdUser`.

## Verified gate

- All 17 sanitizer and fixture tests pass.
- Every synthetic XML fixture parses with `<avtrans>` as its root.
- Every XML fixture is declared with evidence level `synthetic` in `manifest.json`.
- A transport timeout is modeled as no response, not invented backend XML.
- No PM3000 was contacted or modified.
- No firmware binary was executed.
- No vendor payload or raw device capture was copied into the repository.

## Open evidence and later-stage blockers

- Sanitized real request/response fixtures are still required for login/header, navigation, inventory, and read-only outlet status.
- Exact outlet-action paths, control/action IDs, and row IDs remain unknown and must never be inferred from synthetic labels. The `OutletTable` and `outlet_details` identifiers are statically confirmed but still require live-response confirmation.
- The active-device copies of the historical compatibility loader and modified xWire file are not available for fallback validation.
- Unix-socket framing and Apache CGI `Authorization`-header behavior are not yet proven.
- A dedicated least-privilege vendor service account has not been provisioned or tested.

## Next step

Follow [`docs/CAPTURE.md`](docs/CAPTURE.md) on the existing Web UI and provide only the manually reviewed, sanitized XML files. No power action is part of this capture. The resulting observed evidence will close Stage 1 and become the input for the narrow Stage 2 protocol contract.
