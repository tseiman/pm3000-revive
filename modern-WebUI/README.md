# PM3000 Modern Web UI

This directory contains the clean-room implementation of a compact modern Web UI and REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

Stage 9 milestone 2A is published and independently reviewed. The backup-first installer, native REST runtime, PM3000-backed Web sessions, rights-filtered navigation, REST-token administration, outlet/PDU inventory and fixed power actions, self-service password change, typed DSView/NIS settings, revisioned Help and Language and Data Buffering settings, and seven typed system/monitoring reads are implemented offline. Release `0.1` remains the installed read-only pilot; none of the current write-capable code has been deployed or run on the appliance. The vendor UI at `/` remains the fallback. Stage 10 cutover and final product release have not started.

Confirmed legacy/vendor architecture:

```text
browser -> Apache 2.2 -> /appliance/avtrans -> mod_avtrans.so
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

Modern sidecar architecture:

```text
browser or API client -> Apache 2.2 CGI -> pm3000-rest
                      -> /dev/avtrans_socket -> uicontrold -> GSP/CACPD
```

The implementation keeps Apache and the vendor backend. Browser users authenticate with existing PM3000 credentials; GSP SIDs remain in short-lived server-side files and browser mutations require CSRF tokens. External clients use scoped REST bearer tokens. Outlet and PDU actions use fixed path/table/action mappings, fresh server-resolved row identities, revision guards, and no automatic retry after an uncertain result. Revisioned settings additionally require a fresh typed GET, strong `ETag`/`If-Match`, complete replacement, and exact read-back. Further settings are added only through typed, compile-time-allowlisted contracts; see [deferred improvements](DEFERRED-IMPROVEMENTS.md).

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
