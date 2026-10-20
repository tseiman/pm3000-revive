# Reproducing the Current Dropbear Milestone

The recommended build host is a recent Debian or Ubuntu x86-64 Linux system with at least 6 CPU threads, 8 GiB RAM, 15 GiB free disk space, Internet access, and Docker.

This procedure provides a tested, pinned starting point for rebuilding the toolchain and binaries. It does not claim bit-for-bit identical output across different hosts or paths. Local source or configuration changes are allowed; after such changes, their functionality is the responsibility of the person making them.

The scripts intentionally permit local development on the build host. Existing `buildroot/`, `output-buildroot/`, and `work/dropbear-2026.94/` trees are reused rather than forcibly reset. Versioned patches are applied forward-only: an already applied patch is retained, while a conflict stops the build without resetting the tree. Delete the affected generated/work directory yourself only when you deliberately want a fresh reference build. Uncommitted local source edits are not automatically embedded in the build/debug archive; preserving and documenting them is the local builder's responsibility.

## 1. Install prerequisites

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential git curl file patch perl rsync cpio unzip \
  bzip2 xz-utils python3 docker.io
```

Allow the current user to run Docker using the distribution's documented rootless-Docker setup or an explicitly approved local configuration. Do not expose the Docker socket over the network.

## 2. Clone and fetch pinned sources

```bash
git clone https://github.com/tseiman/pm3000-revive.git
cd pm3000-revive/components/dropbear
./fetch-sources.sh
```

`fetch-sources.sh` downloads Dropbear 2026.94 and Linux 2.6.23, checks their required SHA-256 digests, and obtains Buildroot tag `2026.08` at commit `d5180309b1b66ef3b8eaccca70ad69be8e0729a1`.

## 3. Build

```bash
./build-toolchain.sh
./build-dropbear.sh
```

The toolchain build is the slow step. It produces a GCC 14.4.0/Binutils 2.44/musl 1.2.6 cross-toolchain under `output-buildroot/`. The application build writes:

```text
artifacts/bin/dropbear
artifacts/bin/dropbearkey
artifacts/debug/dropbear
artifacts/debug/dropbearkey
```

## 4. Verify

```bash
./verify.sh
```

This verifies ELF32 PowerPC big-endian/static properties and runs the target binaries under QEMU user mode. It generates an Ed25519 host key, starts isolated servers, verifies public-key login, confirms PTY allocation, executes commands, and reconnects. It also checks `--login-shell` startup validation, unchanged default shell behavior, Bash remote-command execution, forced-command precedence and `SSH_ORIGINAL_COMMAND`, rejection of an invalid account shell, and preservation of root/group restrictions. A separate isolated filesystem/process simulation exercises installer integrity rejection, idempotency, port collision handling, both activation gates, recovery, and rollback without touching host services.

QEMU user mode does not emulate the PM3000's actual Linux 2.6.23 kernel. A successful device test remains mandatory.

## 5. Package

```bash
./package.sh
cd dist
sha256sum -c SHA256SUMS
```

Expected result: both archives report `OK`. The runtime archive contains the target binaries, two-phase installer, SysV service, rollback tool, licenses, checksums, and operator documentation. The build/debug archive contains sources, configs, patches, installer sources/tests, logs, and unstripped binaries.

## Pinned inputs and evidence

See:

- [`components/dropbear/BUILD-MANIFEST.md`](../components/dropbear/BUILD-MANIFEST.md)
- [`components/dropbear/TEST-REPORT.md`](../components/dropbear/TEST-REPORT.md)
- [`components/dropbear/SECURITY-NOTES.md`](../components/dropbear/SECURITY-NOTES.md)

Stop if a source checksum fails. A checksum proves integrity relative to the repository metadata, not independent publisher authenticity.
