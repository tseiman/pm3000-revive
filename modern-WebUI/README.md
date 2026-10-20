# PM3000 Modern Web UI

This directory contains the clean-room design and future implementation of a compact modern Web UI and bearer-token REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

**Stages 0 through 2 are complete.** The repository contains reviewed protocol evidence and a strict REST v1 contract, but no replacement UI, REST adapter, or device installer yet.

Confirmed architecture:

```text
browser -> Apache /appliance/avtrans -> mod_avtrans -> /dev/avtrans_socket
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

The design keeps Apache and the vendor backend. The active REST scope is deliberately narrow: read-only outlet inventory/status. The `on`, `off`, and `cycle` request shape is reserved, but Stage 2 always rejects it without sending a backend request. Exact action templates remain deferred until separately approved hardware evidence exists.

## Documents

- [Architecture and security analysis](ANALYSIS.md)
- [Implementation stages](STAGES.md)
- [Protocol boundary](docs/PROTOCOL.md)
- [REST API v1 contract](docs/REST-V1.md)
- [Machine-readable OpenAPI v1 contract](api/openapi-v1.json)
- [Manual Avtrans capture procedure](docs/CAPTURE.md)
- [Reported device storage baseline](docs/DEVICE-STORAGE.md)
- [Synthetic fixture notes](fixtures/synthetic/README.md)
- [Observed sanitized fixture notes](fixtures/observed/README.md)
- [Resume status](STATUS.md)
- [Legacy compatibility patch](../fix-WebUI/README.md)

## Safety boundary

- No PM3000 is contacted automatically.
- No script reboots a device or switches an outlet without an explicit later operator test.
- Vendor firmware files, binaries, credentials, sessions, certificates, and private backups are not repository content.
- Deployment will require a complete verified remote-to-host backup before the first remote installation write.
