# Synthetic Avtrans Fixtures

These files are clean-room examples derived from structures confirmed in the legacy JavaScript/XSL and backend configuration. They are **not captures** and do not prove backend-supplied device paths, control/action IDs, labels, row IDs, or response completeness.

## Static evidence retained in the examples

- The `<avtrans>` envelope, `sid`, `action`, `agents`, `paths`, optional `payload`, and request actions are emitted by `scripts-20150511.js` in `XML_request()` (analyzed source lines 1661–1740).
- The initial browser request uses `path=login` and `action=get`; login submission uses action `login` (`transformation.xsl` analyzed source lines 5–27 and 278–386).
- `login`, `navigation`, `content`, `nav`, `table`, and form/table parameter structures are handled by templates in `transformation.xsl`.
- `OutletTable`, `outlet_details`, `status`, and `outlet_status` are explicit legacy XSL identifiers (`transformation.xsl` analyzed source lines 621–686).
- `ON` and `OFF` are legacy status values handled by that stylesheet.
- XML errors use an `error` element with `severity` and `label` attributes.

Every backend-supplied or device-specific example value that is not statically confirmed uses a `SYNTHETIC_*` marker. Credentials and session IDs use explicit redaction placeholders. In particular, login field IDs and control IDs are synthetic because the backend supplies them.

`manifest.json` records each file's direction, purpose, and synthetic evidence level. A transport timeout is recorded as `no-response` because inventing timeout XML would incorrectly claim backend behavior.

Real sanitized captures are kept separate until manually reviewed. Raw captures are never repository content.
