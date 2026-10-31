# PM3000 ACME client

Status: implementation in progress.

## Selected target design

The appliance client is a dedicated bounded C99 executable for PPC32 big endian.
It uses the firmware's existing glibc 2.3.5, `libssl.so.1.0.0`, and
`libcrypto.so.1.0.0`. Replacement TLS libraries are not packaged. The target
ABI was validated with the probe under
`spikes/001-firmware-openssl-abi/README.md`.

## Release and installation lineage

Production integration follows the existing Modern WebUI Stage 7 path and does
not introduce a weaker ad-hoc uploader:

```sh
modern-WebUI/deploy/stage7-install.sh \
  root@pdu1 \
  "modern-WebUI/dist/pm3000-release.tar" \
  "backup/stage7-full-backup/"
```

The ACME binary is packaged by the same release producer, but it remains an
independent CLI program and has no Apache or REST runtime dependency. The
separately managed Apache configuration only exposes the static challenge
directory; the client does not edit Apache configuration, load as an Apache
module, call Apache APIs, or reload Apache. Persistent ACME state and
account/certificate keys remain outside release directories under
`/mnt/hdUser/pm3000-revive/acme`. That tree and its `trust` subdirectory are
root-owned mode `0700`; all private regular files, including certificates and
keys, are root-owned mode `0600`. The Apache-readable, non-secret HTTP-01
webroot is a separate sibling at `/mnt/hdUser/pm3000-revive/acme-http-01`; it
must be root-owned and mode `0755`, while published token files are mode `0644`.
Installation creates only missing state/trust/webroot directories and never
invents configuration, a hostname, or a CA. It never triggers issuance, renewal,
certificate rollback, or an ACME-specific Apache reload.

The complete operational interface belongs to `pm3000-acme`: configuration
inspection/replacement, managed CA installation, status, and foreground renewal
must all be available from the CLI. REST/WebUI invokes the same closed operations
through the separate `pm3000-acme-admin` fixed-purpose privileged broker, packaged
as `root:daemon` mode `4750`. The broker executes only the fixed
`/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme` target; `pm3000-rest`
does not link ACME sources or read the private ACME state. No scheduler or cron
integration is installed.

### First-run bootstrap

An empty state is created in two explicit, conditionally-created steps; neither
step invents an ACME directory, DNS name, or CA:

```sh
cat operator-ca-bundle.pem | pm3000-acme ca install --stdin --if-none-match '*'
cat operator-config.json   | pm3000-acme config replace --stdin --if-none-match '*'
pm3000-acme renew --foreground
```

The first command accepts only a validated certificate-only PEM bundle and
publishes it as `acme/trust/managed-ca.pem` mode `0600` while configuration is
still absent. The second accepts the operator's complete configuration only when
`config.json` is absent and the validated managed CA already exists; its
`ca_file` must be the fixed managed path. Both checks and writes occur under the
same renewal lock. A repeated creation returns the stale/precondition exit rather
than overwriting state, so after an interrupted HTTP or CLI response the operator
must inspect/reload state instead of blindly repeating the mutation. Ordinary
configured changes continue to use `--if-match ETAG`; the unconditional CLI forms
remain available for direct root administration.

### Managed CA PEM grammar

Managed CA input is at most 65,536 bytes and contains one through nine X.509
certificate blocks. Lines use LF or CRLF (never bare CR); the final line may omit
its line ending. A certificate block has the exact delimiters
`-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` on lines by
themselves. Between them, only the Base64 alphabet (`A-Z`, `a-z`, `0-9`, `+`,
`/`, `=`), spaces, tabs, and line endings are accepted, with at least four
Base64-alphabet bytes per block. Every block must also parse as an X.509
certificate through OpenSSL.

Outside certificate blocks, blank lines and ordinary ASCII text lines are
accepted; text bytes are printable ASCII or tab. This permits human comments
before, between, and after certificates without requiring a comment prefix.
Outside text must not contain `-----BEGIN` or `-----END`, so private keys, CSRs,
unknown PEM objects, malformed delimiters, embedded delimiter text, and other
ambiguous PEM markers are rejected rather than treated as comments. NULs,
non-ASCII/control bytes, bare CR, junk inside Base64, empty/malformed
certificates, extra PEM object types, excessive certificate counts, and
oversized input are rejected.

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

Although the shared release producer packages ACME, this is distribution
cohesion rather than runtime integration. The production artifact should be
built by the Modern WebUI workflow. A separate ACME workflow is only
appropriate for component-level host/PPC verification; it must not publish a
second independently installable production layout.

## Current host tests

```sh
make -C components/pm3000-acme clean test
```
