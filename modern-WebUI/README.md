# PM3000 Modern Web UI

This directory contains the clean-room implementation of a compact modern Web UI and REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

The backup-first installer, native REST runtime, PM3000-backed Web sessions, rights-filtered navigation, REST-token administration, and outlet inventory are implemented and verified offline. Outlet `on`, `off`, and `cycle` input is validated but backend dispatch is disabled: observed topology controls use `targPowerOn`, `targPowerOff`, and `targCycle`, while plain action names belong to detail tables. Release `0.1` remains the installed read-only pilot. The vendor UI at `/` remains the fallback.

Confirmed architecture:

```text
browser -> Apache /appliance/avtrans -> mod_avtrans -> /dev/avtrans_socket
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

The implementation keeps Apache and the vendor backend. Browser users authenticate with existing PM3000 credentials; GSP SIDs remain in short-lived server-side files and browser mutations require CSRF tokens. External clients continue to use scoped REST bearer tokens. Outlet-action input, authentication, authorization, and CSRF are validated, but dispatch is disabled before any Avtrans socket access until an observed action contract exists. Writable settings remain on the legacy UI until each closed form contract has a sanitized real request/response fixture; see [deferred improvements](DEFERRED-IMPROVEMENTS.md).

## Documents

- [Architecture and security analysis](ANALYSIS.md)
- [Implementation stages](STAGES.md)
- [Protocol boundary](docs/PROTOCOL.md)
- [Legacy menu capability cross-check](docs/MENU-CAPABILITY-CROSSCHECK.md)
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
