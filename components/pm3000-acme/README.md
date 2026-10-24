# PM3000 ACME client

Status: implementation in progress.

## Selected target design

The appliance client is a dedicated bounded C99 executable for PPC32 big endian.
It uses the firmware's existing glibc 2.3.5, `libssl.so.1.0.0`, and
`libcrypto.so.1.0.0`. Replacement TLS libraries are not packaged. The target
ABI was validated with the probe under
`spikes/001-firmware-openssl-abi/README.md`.

## Release and installation lineage

Production integration must follow the existing Modern WebUI Stage 7 path, not
introduce a weaker ad-hoc uploader:

```sh
modern-WebUI/deploy/stage7-install.sh \
  root@pdu1 \
  "/Users/tseiman/Downloads/pm3000-release-0.2-rest-control-rc9.tar" \
  "../backup/stage7-full-backup-20261020T221022Z-4266/"
```

The final ACME binary, REST routes, WebUI, and Apache configuration should be
members of one Modern WebUI release transaction so they activate and roll back
as one coherent version. Persistent ACME state and account/certificate keys
must remain outside release directories under `/mnt/hdUser/pm3000-revive/acme`.
Issuance or renewal must not be an implicit installation side effect.

Before adding any release member, update and test every closed allowlist and
shape verifier, including:

- `modern-WebUI/deploy/deployment.py` source map, manifest allowlist, and modes;
- `modern-WebUI/deploy/atomic-publish.c` release tree verifier;
- `modern-WebUI/deploy/stage7-install.sh` upload/preflight allowlist and modes;
- `modern-WebUI/deploy/device-install.sh` checksum, extraction, member, and mode
  checks;
- `modern-WebUI/deploy/device-rollback.sh` package and active-tree checks;
- corresponding deployment, Stage 7 install, rollback, and compatibility tests.

The installer must retain the existing invariants: local package and backup
snapshot verification, one non-multiplexed SSH connection, POSIX ustar stream,
root-owned staging, exact archive membership, PPC compatibility preflight,
transaction-aware activation, Apache configuration validation, and rollback on
activation failure.

## GitHub Actions

Once the production PPC binary exists, CI must use the same shared toolchain
cache contract as `.github/workflows/modern-webui.yml`, `dropbear.yml`, and
`ppc-toolchain-cache.yml`:

- pinned `actions/checkout`, `actions/cache`, and artifact actions;
- cache paths `components/dropbear/buildroot/dl`,
  `components/dropbear/output-buildroot/host`, and
  `components/dropbear/output-buildroot/.config`;
- the existing `pm3000-toolchain-v1-...` key expression;
- `components/dropbear/fetch-sources.sh` before cache restore;
- `components/dropbear/build-toolchain.sh` only on a cache miss;
- host tests before the PPC build;
- exact ELF interpreter, `DT_NEEDED`, imported-symbol, size, archive-member, and
  checksum gates before artifact upload.

Because ACME is part of the Modern WebUI transaction, the production release
should be built by the Modern WebUI workflow. A separate ACME workflow is only
appropriate for component-level host/PPC verification; it must not publish a
second independently installable production layout.

## Current host tests

```sh
make -C components/pm3000-acme clean test
```
