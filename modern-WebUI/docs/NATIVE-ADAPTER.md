# Native REST v1 adapter

This directory provides a bounded C99 CGI runtime for the PM3000 REST v1 contract. It is designed for the existing PowerPC e300c3, big-endian, soft-float firmware environment and preserves the vendor backend chain:

```text
browser -> Apache CGI -> pm3000-rest -> /dev/avtrans_socket -> uicontrold -> GSP/CACPD -> Power API
```

The current candidate has not been installed on a device. Development and verification use sanitized fixtures, temporary token stores, a fake Unix-socket controller, and QEMU user-mode execution. No test has contacted a PM3000 or issued a real write.

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
- `GET /api/v1/system/information`
- `GET /api/v1/system/usage/memory`
- `GET /api/v1/system/usage/flash`
- `GET /api/v1/monitoring/network/devices`
- `GET /api/v1/monitoring/network/routes/ipv4`
- `GET /api/v1/monitoring/network/routes/ipv6`
- `GET /api/v1/monitoring/serial-ports`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
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
- Controller credentials: `/etc/pm3000-rest/controller.credentials`
- Browser sessions: `/tmp/pm3000-modern-sessions`

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

The target is stripped with the matching Buildroot `powerpc-buildroot-linux-musl-strip`. The output is:

```text
modern-WebUI/native/build/pm3000-rest-ppc32
```

The target is a stripped, statically linked ELF32 MSB PowerPC executable. The binary and production assets remain subject to the combined 400 KiB release budget.

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

Malformed, oversized, ambiguous, or duplicate required/identity data fails closed; harmless unsupported display fields may be omitted by non-fixed-form projectors. Outlet IDs and inventory revisions are project-owned SHA-256-derived opaque identifiers.

### Token store

The native reader and writer enforce the Stage 3 canonical store contract:

- strict schema and canonical field order
- bounded store, token, and outlet counts
- exactly one enabled administrator or more
- SHA-256 digests only; bearer plaintext is never stored
- independent random token record IDs
- exclusive lock during validation and mutation
- descriptor-relative `O_NOFOLLOW` operations
- owner-only regular files and a mode-`0700` owner-only directory
- verified parent-directory `fsync` before each transaction, followed by a same-directory temporary file, file `fsync`, atomic rename, and private-directory `fsync`
- generation increment for every successful mutation
- protection against disabling or revoking the final enabled administrator

A created bearer value appears only in its one-time `201` response. While the exclusive lock is held, the candidate store is first written and `fsync`ed to a same-directory temporary file. The response is then written and flushed before the atomic rename. A response-delivery failure removes the candidate and preserves the old store byte-for-byte. A subsequent pre-rename failure can leave the client with an inactive credential, but cannot leave an active credential whose plaintext was not delivered. Once rename succeeds, directory-`fsync` uncertainty is reported locally and never rolled back; the already delivered credential remains the authoritative result. List responses contain metadata only. Error responses and tests must not contain token plaintext or digests.

### Power actions and password change

Power routes validate HTTPS, session or bearer authorization, scope/right, outlet policy, route shape, closed JSON, and browser CSRF. The server refreshes the relevant inventory, resolves the opaque ID to one row, verifies the client revision, checks the advertised firmware control, and emits a fixed table payload. Topology actions map to `targPowerOn`, `targPowerOff`, and `targCycle`; PDU-wide actions use `on`, `off`, and `cycle`.

Password change is session-only, requires `units.change_password`, matching CSRF, and matching new-password confirmation. It emits only the fixed `save` form, accepts only the firmware-derived success-form hierarchy, and clears secret buffers with a non-optimizable wipe.

Help and Language and Data Buffering are session-only complete-replacement resources. Each GET validates the exact fixed-form response and returns a strong revision in the body and `ETag`; PUT requires matching CSRF and `If-Match`, obtains a fresh backend state, emits only the fixed firmware form, and returns success only after exact typed read-back. Bearer authentication is rejected before backend access.

Power `on`/`off` responses must be valid operation-specific inventories that report the targeted object in the requested state. `cycle` has no stable confirmation state and therefore reports `action_outcome_unknown` after dispatch. A malformed, unrelated, or unexpected response after any write is likewise unknown; no write is retried automatically. No firmware, reboot, reset, factory-default, arbitrary settings, or generic Avtrans operation is exposed.

## Deployment preconditions

Before installing a write-capable candidate, the installer must independently provide and verify:

1. an owner-only persistent directory at `/mnt/hdUser/pm3000-revive/rest/` with mode `0700`;
2. the canonical token store and lock file with mode `0600`;
3. an owner-only credentials file at `/etc/pm3000-rest/controller.credentials`;
4. an Apache mapping that preserves the existing vendor Web UI as a fallback;
5. HTTPS-only access and the required CGI environment;
6. a staged health check before exposing any additional route.

The compatibility gate and installer fail before activation unless both private directories and all three write-capable runtime files (token store, token lock, and controller credentials) satisfy these ownership, link-count, regular-file, and mode requirements.

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
