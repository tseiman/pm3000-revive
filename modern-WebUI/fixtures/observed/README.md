# Observed and Sanitized Avtrans Fixtures

These fixtures were observed on an Avocent PM3000 running firmware 2.0.1.23. They establish concrete browser/backend request and response shapes that the synthetic fixtures could not prove.

## Collection boundary

The collection used HTTPS with normal certificate and hostname verification. It performed only:

- the initial unauthenticated login-form read;
- one authenticated login;
- navigation reads;
- topology, inventory, outlet-status, and PDU-status reads;
- logout.

No configuration form was submitted. No outlet `on`, `off`, `cycle`, lock, or unlock control was invoked. No PDU-wide action, reboot, reset, factory-default, or firmware operation was invoked.

## Sanitization boundary

- Credentials and session IDs are replaced with explicit placeholders.
- Internal hostnames, private addresses, appliance/operator names, serial numbers, and user-assigned device/outlet names are removed.
- Control definitions in responses are passive backend metadata; their presence does not mean the controls were executed.
- The capture directory was outside the repository, used mode-`0600` files, and the raw XML was deleted after the reviewed sanitizer output passed the leak gate.
- Runtime status and public product/model values remain because they are part of the observed response schema. They must not be treated as stable inventory.

`manifest.json` records direction, purpose, provenance, and the `observed-sanitized` evidence level for every XML file. Files not declared in that manifest fail the fixture allowlist test.

Exact state-changing request/response bodies remain intentionally absent. They require a separately approved hardware test plan and must not be inferred from response labels alone.
