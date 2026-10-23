# PM3000 Modern Web UI

This directory contains the clean-room implementation of a compact modern Web UI and REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

Production release `0.3.0` is published as the first complete release containing the native REST runtime, fixed-purpose local GSP session helper, backup-first installer, PM3000-backed Web sessions, rights-filtered navigation, REST-token administration, outlet/PDU inventory and fixed power actions, self-service password change, typed settings, and system/monitoring reads. The hardware-validated predecessor `local-gsp-reviewed-v4` is currently active: health and ten authenticated read-only outlet inventories passed, the helper was installed as `root:daemon 4750`, and no helper process remained. No real outlet, PDU, setting, password, reboot, or firmware write was executed. The next device installation is the workflow-built production release, not another local test release. The vendor UI at `/` remains the fallback. Changes after `0.3.0`, including the additive name-based outlet action request, are not installed until a later reviewed release is built and deployed.

Confirmed legacy/vendor architecture:

```text
browser -> Apache 2.2 -> /appliance/avtrans -> mod_avtrans.so
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

Modern sidecar architecture:

```text
browser or API client -> Apache 2.2 CGI -> pm3000-rest
pm3000-rest -> private socketpair -> setuid GSP helper -> libgsp_auth.so
pm3000-rest -> SID-bound /dev/avtrans_socket -> uicontrold -> GSP/CACPD
```

The implementation keeps Apache and the vendor backend. Browser users authenticate with existing PM3000 credentials and browser mutations require CSRF tokens. External clients use scoped REST bearer tokens. Each controller access obtains a fresh local GSP session for the fixed identity `pm3000-rest`; its SID exists only in helper/adapter process memory and their private socketpair, never in a file, log, command line, CGI environment, or HTTP response. Outlet and PDU actions use fixed path/table/action mappings and fresh server-resolved row identities. Outlet actions can use an opaque ID or an exact unique name; optional inventory revisions provide an additional stale-inventory guard. Name resolution always precedes authorization against the canonical opaque outlet ID. Uncertain action results are never retried automatically. Revisioned settings require a fresh typed GET, strong `ETag`/`If-Match`, complete replacement, and exact read-back. See the [deployment communication diagram](deploy/README.md#production-communication-architecture) and [native adapter security boundaries](docs/NATIVE-ADAPTER.md#security-boundaries).

## Documents

- [Architecture and security analysis](ANALYSIS.md)
- [Implementation stages](STAGES.md)
- [Protocol boundary](docs/PROTOCOL.md)
- [Legacy menu capability cross-check](docs/MENU-CAPABILITY-CROSSCHECK.md)
- [REST API v1 contract](docs/REST-V1.md)
- [Bearer-token store and host administration](docs/TOKEN-STORE.md)
- [Native REST v1 adapter build, operation, and rollback](docs/NATIVE-ADAPTER.md)
- [Stage 5 Web UI and local browser verification](web/README.md)
- [Production backup-first deployment, architecture, and rollback](deploy/README.md)
- [Machine-readable OpenAPI v1 contract](api/openapi-v1.json)
- [Manual Avtrans capture procedure](docs/CAPTURE.md)
- [Reported device storage baseline](docs/DEVICE-STORAGE.md)
- [Synthetic fixture notes](fixtures/synthetic/README.md)
- [Observed sanitized fixture notes](fixtures/observed/README.md)
- [Resume status](STATUS.md)
- [Legacy compatibility patch](../fix-WebUI/README.md)

## REST API quick example

[`docs/REST-V1.md`](docs/REST-V1.md) separates supported, planned/deferred, and intentionally unsupported functionality and includes `curl` examples using `${TOKEN}`.

The additive v1 route accepts an opaque outlet ID or an exact unique outlet name:

```http
POST /api/v1/outlets/actions
{"outlet":"Exact configured outlet name","action":"on"}
```

The existing `POST /api/v1/outlets/{outletId}/actions` route remains compatible. `inventoryRevision` is optional on both forms.

## Safety boundary

- No PM3000 is contacted automatically.
- No script reboots a device or switches an outlet without an explicit later operator test.
- Vendor firmware files, binaries, credentials, sessions, certificates, and private backups are not repository content.
- Deployment will require a complete verified remote-to-host backup before the first remote installation write.
