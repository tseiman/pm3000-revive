# PM3000 Modern Web UI

This directory contains the clean-room design and future implementation of a compact modern Web UI and bearer-token REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

**Stages 4 and 5 are implemented, locally verified, and independently reviewed with PASS. Stage 6 is implemented as an offline-only backup-first deployment and rollback transaction and is awaiting its final release review.** Remote deployment remains disabled until the Stage 7 device preflight. Nothing has been installed on a PM3000, and the legacy UI remains the required fallback.

Confirmed architecture:

```text
browser -> Apache /appliance/avtrans -> mod_avtrans -> /dev/avtrans_socket
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

The design keeps Apache and the vendor backend. The native adapter exposes strict read-only outlet projections and local token administration. The Stage 5 browser uses only REST v1, stores its bearer token only in memory, and contains no outlet-action control. The `on`, `off`, and `cycle` request shape remains reserved and always returns `503 action_disabled` without an Avtrans request. Exact action templates remain deferred until separately approved hardware evidence exists.

## Documents

- [Architecture and security analysis](ANALYSIS.md)
- [Implementation stages](STAGES.md)
- [Protocol boundary](docs/PROTOCOL.md)
- [REST API v1 contract](docs/REST-V1.md)
- [Bearer-token store and host administration](docs/TOKEN-STORE.md)
- [Native REST v1 adapter build, operation, and rollback](docs/NATIVE-ADAPTER.md)
- [Stage 5 Web UI and local browser verification](web/README.md)
- [Stage 6 backup-first deployment and rollback](deploy/README.md)
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
