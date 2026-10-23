# Native REST v1 adapter

This directory provides a bounded C99 CGI runtime for the PM3000 REST v1 contract. It is designed for the existing PowerPC e300c3, big-endian, soft-float firmware environment and preserves the vendor backend chain:

```text
browser -> Apache CGI -> pm3000-rest -> /dev/avtrans_socket -> uicontrold -> GSP/CACPD -> Power API
```

The hardware-validated predecessor `local-gsp-reviewed-v4` is currently installed on the appliance. Bearer-authenticated read-only outlet inventory succeeds live with HTTP 200 for all ten outlets; the local GSP helper is `root:daemon 4750`, and no helper process remains after the reads. An earlier Safari network capture from the historical RC7 deployment proved that Apache exports an empty `HTTP_AUTHORIZATION` CGI variable when the browser sends no Authorization header. Session-capable routes therefore treat an absent or empty value and inherited `Basic` or `Digest` headers as browser-session candidates while still requiring a valid private session cookie. Explicit Bearer and malformed non-empty Authorization headers retain their strict handling. The evidence and appliance validation gate are recorded in [`BACKEND-COMMUNICATION-STATUS.md`](BACKEND-COMMUNICATION-STATUS.md). No real outlet write has been issued through the replacement adapter.

## Implemented routes

- `GET /api/v1/health`
- `POST /api/v1/session`
- `GET /api/v1/session`
- `DELETE /api/v1/session`
- `POST /api/v1/session/password`
- `GET|PUT /api/v1/settings/security/dsview`
- `GET|PUT /api/v1/settings/authentication/nis`
- `GET|PUT /api/v1/settings/help-language`
- `GET|PUT /api/v1/settings/data-buffering`
- `GET|PUT /api/v1/settings/appliance-logging`
- `GET|PUT /api/v1/settings/time-zone`
- `GET /api/v1/system/information`
- `GET /api/v1/system/usage/memory`
- `GET /api/v1/system/usage/flash`
- `GET /api/v1/monitoring/network/devices`
- `GET /api/v1/monitoring/network/routes/ipv4`
- `GET /api/v1/monitoring/network/routes/ipv6`
- `GET /api/v1/monitoring/serial-ports`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
- `POST /api/v1/outlets/actions`
- `POST /api/v1/outlets/{outletId}/actions`
- `GET /api/v1/pdus`
- `POST /api/v1/pdus/{pduId}/actions`
- `GET /api/v1/tokens`
- `POST /api/v1/tokens`
- `POST /api/v1/tokens/{tokenId}/enable`
- `POST /api/v1/tokens/{tokenId}/disable`
- `DELETE /api/v1/tokens/{tokenId}`

Every route requires `HTTPS=on`; no route is exposed over plain HTTP. The health route is unauthenticated after the HTTPS gate. Browser requests use PM3000-backed server-side sessions and CSRF protection. External clients use bearer authorization according to `api/openapi-v1.json`.

## Fixed production paths

Production builds do not accept environment overrides:

- Token store: `/mnt/hdUser/pm3000-revive/rest/tokens.json`
- Token lock: `/mnt/hdUser/pm3000-revive/rest/tokens.json.lock`
- Avtrans socket: `/dev/avtrans_socket`
- Local GSP session helper: `/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-gsp-session-helper`
- Fixed local service identity: `pm3000-rest`
- Browser sessions: `/tmp/pm3000-modern-sessions`

No controller password file is read or required for bearer-authenticated REST access.

`PM3000_TESTING` host builds accept path overrides only for isolated tests. The target Makefile never defines `PM3000_TESTING`.

## Build

Prerequisites:

- the repository was cloned with the pinned Buildroot toolchain already produced under `components/dropbear/output-buildroot/host/`
- GNU Make
- a host C compiler for tests

From the repository root:

```bash
make -C modern-WebUI/native clean target
```

The target uses:

```text
-std=c99 -Os -Wall -Wextra -Werror -pedantic
-static -mcpu=e300c3 -msoft-float
```

The targets are stripped with the matching Buildroot `powerpc-buildroot-linux-musl-strip`. The outputs are:

```text
modern-WebUI/native/build/pm3000-rest-ppc32
modern-WebUI/native/build/pm3000-gsp-session-helper-ppc32
```

The REST adapter is a stripped, statically linked ELF32 MSB PowerPC executable. The fixed-purpose helper is a small dynamically linked ELF32 MSB PowerPC executable using the firmware `/lib/ld.so.1`, `libgsp_auth.so`, and `GLIBC_2.0` symbols. Its build uses the checked-in source-only interfaces under `native/abi-stubs/`; these generate link-time shared objects with the required SONAMEs, symbol names, and GLIBC version binding. The generated stubs are never packaged or installed and contain no vendor implementation. At runtime the helper resolves the same imports from the appliance's existing firmware libraries. This makes local and GitHub Actions builds reproducible without an extracted firmware root filesystem or redistributed firmware binaries.

The helper intentionally uses the firmware's legacy PPC32 SysV PLT ABI: that ABI places `.got` and the lazy-binding `.plt` in an RWE load segment, as do the appliance's own `pmcli` and `libgsp_auth.so`; secure-PLT compatibility with the glibc 2.3.5 loader is not established. The helper stack remains non-executable, and its restricted caller, input, descriptor, and operation surface are the compensating controls. The complete nine-member production archive is subject to a 448 KiB regular-file budget, including the manifest and checksum list; the release producer enforces this limit before creating the TAR.

## Verification

Run all fixture, schema, token-store, adapter, and UI asset tests:

```bash
python3 -m unittest discover -s modern-WebUI/tests -p 'test_*.py'
```

Build and inspect the target:

```bash
make -C modern-WebUI/native clean target
file modern-WebUI/native/build/pm3000-rest-ppc32
components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-readelf \
  -h modern-WebUI/native/build/pm3000-rest-ppc32
```

A local QEMU health check may be run in a disposable container. It mounts only the build directory read-only and does not contact a PM3000:

```bash
docker run --rm \
  -v "$PWD/modern-WebUI/native/build:/work:ro" \
  debian:bookworm-slim \
  sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-user >/dev/null && \
    REQUEST_METHOD=GET PATH_INFO=/api/v1/health HTTPS=on \
    qemu-ppc -cpu e300c3 /work/pm3000-rest-ppc32'
```

Expected status and payload:

```text
Status: 200 OK
{"apiVersion":"v1","status":"live"}
```

## Security boundaries

### Backend projection

The Avtrans client has no generic proxy or free-form command interface. Active routes emit only fixed login, navigation, topology, PDU inventory, password-change, typed setting, system/monitoring read, power-action, and logout requests. The bounded structural XML parser rejects comments, malformed/trailing documents, and explicit controller errors. Each projector validates its required paths, identities, forms, and unique fields while omitting harmless unsupported display data. The revisioned Help and Language and Data Buffering fixed-form projector additionally closes the complete document grammar, attributes, elements, text, controls, declarations, hierarchy, and child ordering. Projectors map only approved fields to REST v1 and never expose raw controller row IDs, hidden fields, or hidden PDU threshold data.

Bearer-authenticated backend operations obtain a fresh local GSP-AAA session for the compile-time identity `pm3000-rest`. The selected deployment architecture for the next update is the narrowly scoped setuid broker: it is owned by `root:daemon` with mode `4750`; no general-purpose or additional setuid component is permitted. The helper accepts no arguments or environment-selected identity and performs no controller operation. It requires the real caller identity `daemon`, verifies both IPC descriptors with `SO_PEERCRED` against its parent, receives an empty environment, and closes every inherited descriptor except the private stdin/stdout socket channel before entering GSP-AAA. Linux socket-option numbers are architecture-specific: the PPC firmware ABI defines `SO_PEERCRED` as `21` (not the x86 value `17`), and the source regression test pins that target value. All required GSP session setters must succeed before the SID is released. The adapter bounds the startup handshake to 10 seconds and bounds helper reaping with TERM/KILL escalation. The helper returns the bounded SID only over that channel, remains alive for the request, and destroys the session when the adapter closes the channel or when the helper receives `SIGHUP`, `SIGINT`, or `SIGTERM`. A failed destroy or abnormal helper exit fails reads as `backend_unavailable`; after a dispatched power action it becomes `action_outcome_unknown`, which clients must not retry automatically. The SID is wiped from adapter memory and is never returned or logged. Browser username/password sessions remain separate and unchanged.

If the local `pm3000-rest` account does not exist, every bearer route requiring controller access returns HTTP `503` with `code: controller_service_user_unavailable` and an actionable message to create that local account and grant its required controller permissions. Other helper or session failures return the generic `backend_unavailable` contract without internal details.

Malformed, oversized, ambiguous, or duplicate required/identity data fails closed; harmless unsupported display fields may be omitted by non-fixed-form projectors. Outlet IDs and inventory revisions are project-owned SHA-256-derived opaque identifiers.

### Token store

The native reader and writer enforce the Stage 3 canonical store contract:

- strict schema and canonical field order
- bounded store, token, and outlet counts
- zero to 128 records; an empty store and no enabled bearer administrator are valid
- SHA-256 digests only; bearer plaintext is never stored
- independent random token record IDs
- exclusive lock during validation and mutation
- descriptor-relative `O_NOFOLLOW` operations
- owner-only regular files and a mode-`0700` owner-only directory
- verified parent-directory `fsync` before each transaction, followed by a same-directory temporary file, file `fsync`, atomic rename, and private-directory `fsync`
- generation increment for every successful mutation
- final-enabled-administrator protection for bearer-authenticated administration; an authorized private browser session may disable or revoke every bearer token and recreate one from an empty store

A created bearer value appears only in its one-time `201` response. While the exclusive lock is held, the candidate store is first written and `fsync`ed to a same-directory temporary file. The response is then written and flushed before the atomic rename. A response-delivery failure removes the candidate and preserves the old store byte-for-byte. A subsequent pre-rename failure can leave the client with an inactive credential, but cannot leave an active credential whose plaintext was not delivered. Once rename succeeds, directory-`fsync` uncertainty is reported locally and never rolled back; the already delivered credential remains the authoritative result. List responses contain metadata only. Error responses and tests must not contain token plaintext or digests.

### Power actions and password change

Power routes validate HTTPS, session or bearer authorization, scope/right, outlet policy, route shape, closed JSON, and browser CSRF. The existing per-ID routes remain compatible. The additive `POST /api/v1/outlets/actions` route accepts an opaque outlet ID or an exact case-sensitive printable-ASCII name in the closed `outlet` request member. The server resolves the selector against fresh topology, rejects missing or ambiguous names, and applies bearer outlet allowlists only to the resolved canonical opaque ID. It then refreshes the relevant inventory again immediately before dispatch, resolves that ID to one row, checks the client inventory revision when supplied for an outlet action, verifies the advertised firmware control, and emits a fixed table payload. PDU-wide actions continue to require an inventory revision. Topology actions map to `targPowerOn`, `targPowerOff`, and `targCycle`; PDU-wide actions use `on`, `off`, and `cycle`.

Password change is session-only, requires `units.change_password`, matching CSRF, and matching new-password confirmation. It emits only the fixed `save` form, accepts only the firmware-derived success-form hierarchy, and clears secret buffers with a non-optimizable wipe.

Help and Language and Data Buffering are session-only complete-replacement resources. Appliance Logging and Time Zone are session-only conditional replacement resources whose inactive descendants are omitted from the save and preserved from the fresh read. Each GET validates the exact fixed-form response and returns a strong revision in the body and `ETag`; PUT requires matching CSRF and `If-Match`, obtains a fresh backend state under a private cross-process write lock, emits only the active fixed firmware branch, and returns success only after exact typed read-back of active writes and preserved state. Lock contention fails immediately with `503 backend_unavailable` before backend access instead of occupying another CGI worker. Bearer authentication is rejected before backend access. Appliance Logging validates the nested title/checkbox hierarchy, both fixed choice sets, ten bounded alert strings, and new-session-only semantics. Time Zone validates its 16-value radio/checkbox hierarchy, firmware-bound predefined choices, and fixed transition choices before serializing predefined, custom, or custom-with-DST state. In both cases success confirms typed configuration read-back, not unobserved runtime side effects.

Power `on`/`off` responses must be valid operation-specific inventories that report the targeted object in the requested state. `cycle` has no stable confirmation state and therefore reports `action_outcome_unknown` after dispatch. A malformed, unrelated, or unexpected response after any write is likewise unknown; no write is retried automatically. No firmware, reboot, reset, factory-default, arbitrary settings, or generic Avtrans operation is exposed.

## Deployment preconditions

Before installing a write-capable candidate, the installer must independently provide and verify:

1. a safe persistent parent for `/mnt/hdUser/pm3000-revive/rest/`; the installer creates the private mode-`0700` directory when absent;
2. optional existing canonical token store and lock files; the installer creates a canonical empty mode-`0600` store and private lock when absent;
3. the local PM3000 account `pm3000-rest` with the intended read/control rights;
4. the release-owned session helper verified as root-owned, daemon-group-executable mode `4750`;
5. an Apache mapping that preserves the existing vendor Web UI as a fallback;
6. HTTPS-only access and the required CGI environment;
7. a staged health check before exposing any additional route.

The compatibility gate and installer fail before activation unless the private token directory, token store, token lock, release tree, and fixed-purpose session helper satisfy their ownership, link-count, regular-file, and mode requirements. A missing service account is reported at request time through the explicit `controller_service_user_unavailable` response because account creation and permission assignment remain operator-controlled.

Do not deploy by overwriting vendor files in place.

## Rollback design

The backup-first installer and separate rollback tooling implement the following design offline. Their current write-capable candidate has not completed controlled live-device acceptance:

1. remove or disable only the new REST/modern-UI Apache mapping;
2. restore the previous Apache configuration from a validated backup;
3. remove only project-owned binaries and assets;
4. leave the vendor Web UI and vendor backend chain untouched;
5. preserve the token store unless an operator explicitly requests its destruction;
6. verify that the legacy Web UI is reachable after rollback.

Rollback must not restore unknown firmware, restart unrelated services, or issue any Avtrans power/settings command.
