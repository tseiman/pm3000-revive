# Native REST v1 adapter

This directory provides a bounded C99 CGI runtime for the PM3000 REST v1 contract. It is designed for the existing PowerPC e300c3, big-endian, soft-float firmware environment and preserves the vendor backend chain:

```text
browser -> Apache CGI -> pm3000-rest -> /dev/avtrans_socket -> uicontrold -> GSP/CACPD -> Power API
```

The current session/token/read-only candidate has not been installed on a device. Development and verification use sanitized fixtures, temporary token stores, a fake Unix-socket controller, and QEMU user-mode execution. Outlet action dispatch is disabled.

## Implemented routes

- `GET /api/v1/health`
- `POST /api/v1/session`
- `GET /api/v1/session`
- `DELETE /api/v1/session`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
- `POST /api/v1/outlets/{outletId}/actions`
  - validates closed `on`, `off`, and `cycle` input
  - validates authentication, authorization, and browser CSRF
  - returns `503 action_contract_unverified` without controller access
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

The Avtrans client has no generic proxy or free-form command interface. Active routes emit only closed, observed login, navigation, topology, and logout requests. Both retained outlet-action helpers return before login or socket access, and the HTTP route is separately fail-closed. A bounded structural XML parser rejects comments, duplicate control fields, malformed/trailing documents, explicit controller errors, and mismatched actions or paths. The topology projector maps only approved fields to REST v1.

Malformed, oversized, ambiguous, duplicate, or unexpected backend data fails closed. Outlet IDs and inventory revisions are project-owned SHA-256-derived opaque identifiers.

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

### Power actions

The action route validates HTTPS, session or bearer authorization, scope/right, outlet permission, route shape, and CSRF, then returns `503 action_contract_unverified` without opening the controller socket. The observed topology page defines `targPowerOn`, `targPowerOff`, and `targCycle`; `on`, `off`, and `cycle` are defined for PDU/outlet detail tables. Existing read-only fixtures do not prove which full request/response contract should back the REST action.

No firmware, reboot, reset, factory-default, arbitrary settings, or generic Avtrans operation is exposed. A future implementation requires sanitized browser-generated action and response fixtures and must preserve the existing no-retry/unknown-outcome safety model.

## Deployment preconditions

Before installing a write-capable candidate, the installer must independently provide and verify:

1. an owner-only persistent directory at `/mnt/hdUser/pm3000-revive/rest/` with mode `0700`;
2. the canonical token store and lock file with mode `0600`;
3. an owner-only credentials file at `/etc/pm3000-rest/controller.credentials`;
4. an Apache mapping that preserves the existing vendor Web UI as a fallback;
5. HTTPS-only access and the required CGI environment;
6. a staged health check before exposing any additional route.

Do not deploy by overwriting vendor files in place.

## Rollback design

A later installer must make rollback an atomic configuration operation:

1. remove or disable only the new REST/modern-UI Apache mapping;
2. restore the previous Apache configuration from a validated backup;
3. remove only project-owned binaries and assets;
4. leave the vendor Web UI and vendor backend chain untouched;
5. preserve the token store unless an operator explicitly requests its destruction;
6. verify that the legacy Web UI is reachable after rollback.

Rollback must not restore unknown firmware, restart unrelated services, or issue any Avtrans power/settings command.
