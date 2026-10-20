# pm3000-revive

Independent community project for incrementally modernizing Avocent PM3000 PDUs. The long-term scope includes updated remote access, firmware analysis and packaging, a modern web UI, ACME certificate handling, and RPC-based automation integrations. This project is not affiliated with Avocent or Vertiv.

> **Current milestone:** a tested static Dropbear build, a documented compatibility patch for the legacy Web UI, and a verified architecture/stage plan for its compact modern replacement. No complete firmware image or replacement UI is provided yet.

## Firmware baseline

This project assumes Avocent PM3000 firmware `2.0.1.23`, the final firmware release before the product reached end of life. Unless stated otherwise, documented paths, hashes, ABI assumptions, and Web UI compatibility work refer to this baseline.

## Current result

The first component provides:

- Dropbear 2026.94 server and `dropbearkey`
- static musl linkage; no dependency on the device's legacy glibc
- modern SSH algorithms and Ed25519 host keys
- disabled client, SCP/SFTP, forwarding, X11, compression, and SHA-1 algorithms
- pinned, repeatable Buildroot cross-toolchain configuration
- ELF, QEMU-user, key-generation, SSH login, PTY-allocation, and reconnect checks
- a non-invasive device test procedure using TCP port 2222

The stripped binaries total about 643 KiB. The binaries alone do not replace or reconfigure vendor SSH; only the operator-invoked, explicitly confirmed installer phase 2 performs that transition.

## Components

- [`components/dropbear/`](components/dropbear/) — static Dropbear server, build environment, tests, and device-test procedure.
- [`fix-WebUI/`](fix-WebUI/) — firmware `2.0.1.23` compatibility patch, hashes, installation limits, and investigation notes for the legacy browser UI.
- [`modern-WebUI/`](modern-WebUI/) — clean-room architecture analysis and resumable stages for a compact modern UI, bearer-token REST facade, and backup-first deployment.

The modern component is currently analysis and planning only. The compatibility patch is reference material and a recovery aid, not the architecture of the replacement UI.

## Reproduce on Linux

Install the prerequisites listed in [Reproducing the current milestone](docs/REPRODUCING.md), then run:

```bash
git clone https://github.com/tseiman/pm3000-revive.git
cd pm3000-revive/components/dropbear
./fetch-sources.sh
./build-toolchain.sh
./build-dropbear.sh
./verify.sh
./package.sh
```

Validated binaries are written to `components/dropbear/artifacts/bin/`. Release archives are written to `components/dropbear/dist/`.

The modern PM3000 release is versioned independently from Dropbear. On Linux,
after the shared PPC toolchain above has been built, create it with:

```bash
modern-WebUI/deploy/build-release.sh 2026-10-21.1
```

Outputs are written to `modern-WebUI/dist/`. A `dropbear-v*` tag builds only the
Dropbear component; a `modern-webui-v*` tag builds, QEMU-checks, and publishes the
corresponding `pm3000-release-*.tar`. Both release workflows restore the same
PPC cross-toolchain cache seeded on `main`, but do not couple their component
versions.

## Install and test

Installation is operator-initiated and uses the packaged two-phase installer. Read [Installing Dropbear on the PM3000](docs/INSTALL_DROPBEAR.md) before copying anything to a device. Phase 1 runs one parallel test on port 2222 while preserving vendor OpenSSH; phase 2 takes port 22 and enables SysV startup only after explicit confirmation of both the test login and a new port-22 login. No installer command reboots the PDU, and `rollback.sh` restores the preserved OpenSSH service.

## Project status and safety

- Current stage: experimental component build; not a complete firmware update.
- No PM3000 deployment is automated.
- Do not overwrite vendor binaries, bootloader data, calibration data, or the original firmware.
- Keep an existing management session and recovery route available during device testing.
- Do not publish vendor firmware images, device dumps, credentials, host keys, or proprietary files in this repository.

See [ROADMAP.md](ROADMAP.md) for the planned incremental work.

## Licensing

Repository-authored files are licensed under [MIT](LICENSE). Third-party components retain their original licenses; see [LICENSES.md](LICENSES.md) and the component license files.
