# Stage 6 backup-first deployment

This directory contains the offline-verified Stage 6 transaction. It does not
contact a PM3000, reboot it, change settings, or expose an outlet operation.
The pilot is mounted at `/modern/`; the vendor UI at `/` is not replaced.

## Files

- `deployment.py` — Python-standard-library package builder, backup verifier,
  local device simulation, installer transaction, rollback, and fault injection.
- `deploy.sh`, `rollback.sh` — fixed-interface host entry points. They deliberately
  accept only a synthetic root in Stage 6; they are not generic SSH command proxies.
- `device-install.sh`, `device-rollback.sh` — minimal POSIX `sh` privileged
  publication helpers for the later manually approved device pilot.
- `device-preflight.sh` — read-only Stage 7 inventory; writes its report only to
  standard output and never installs, reloads, restarts, or creates a device file.
- `stage7-first-backup.sh` — Mac/Linux host command that uses fixed read-only SSH
  probes and durably records an initial absent-state backup locally before SCP.
- `pm3000-revive.conf` — isolated Apache 2.2 `/modern/` pilot mapping.

## Prerequisites

Host: Python 3.9 or newer, Bash, `tar`, adequate private backup storage, and a
built PPC adapter at `modern-WebUI/native/build/pm3000-rest-ppc32` and the
atomic publication helper built with `make -C modern-WebUI/deploy target`.
Host backup directories are forced to mode `0700`; backup files are `0600` and
must remain outside Git.

A future device pilot additionally requires BusyBox/POSIX `sh`, `tar`,
`openssl` with `dgst -sha256`, `cat`, `wc`, `cut`, `cp`, `cmp`, `sed`, `id`, `readlink`, `ln`,
`chmod`, `mkdir`, `mktemp`, `dirname`, `pwd`, `rm`, and `sync`, plus the
packaged atomic helper and sufficient space under `/mnt/hdUser` and `/tmp`.
The following Apache commands come from repository evidence but remain
unverified on the appliance:

```text
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
/etc/init.d/apache2 reload
```

Do not run the device helpers until a host-verified `BACKUP_COMPLETE` exists.
Stage 6 intentionally does not automate SSH/SCP against a live appliance; that
transport and all observed path/ownership assumptions are a Stage 7 manual-pilot
gate.

## Build the exact allowlist release

From the repository root:

```sh
python3 modern-WebUI/deploy/deployment.py package \
  --source modern-WebUI \
  --release-id 2026-10-20.1 \
  --output /tmp/pm3000-release.tar
```

The builder reads only the three names in `web/release-files.txt`, the finished
PPC REST binary, the finished PPC atomic-publication helper, and this
directory's Apache configuration. It snapshots each source
once, rejects non-regular/symlink sources and source mutation during a read, and
writes deterministic `RELEASE_MANIFEST.json`, `RELEASE_SHA256SUMS`, and a whole
archive `.sha256` sidecar. Deployment opens the package once with no-follow
semantics, validates the sidecar against that immutable in-memory snapshot, and
uses the same bytes for parsing and staging. Installation verifies the whole archive again after
staging and verifies each finished byte sequence against the internal manifest. The future
device primitive requires root, copies the uploaded package into a private `0700` work
directory, verifies that snapshot against the host-approved package digest, and performs
all listing and extraction from only that snapshot. It executes only the atomic helper
extracted from the digest-approved package; no separately replaceable helper path is accepted.
The rollback primitive likewise snapshots the host-approved package, verifies its
digest, and uses only a private helper copy plus manifest/checksum-list bytes from that
snapshot to authenticate the live release before publication. It accepts restore inputs
only from an effective-UID-owned `0700` directory containing effective-UID-owned,
single-link files.

## Local simulation (default and only enabled host mode)

Create a disposable synthetic root and package, then run:

```sh
modern-WebUI/deploy/deploy.sh \
  --simulate-root /tmp/pm3000-sim \
  --package /tmp/pm3000-release.tar \
  --backup-dir "$HOME/.local/state/pm3000-private-backups"
```

Defaults represented by the transaction are:

- releases: `/mnt/hdUser/pm3000-revive/webui/releases/<release-id>`
- active pointer: `/mnt/hdUser/pm3000-revive/webui/current`
- isolated config: `/etc/apache2/conf.d/pm3000-revive.conf`
- preserved private store: `/mnt/hdUser/pm3000-revive/rest/tokens.json`

The transaction recursively inventories and archives every existing regular
file below the managed `webui`, `rest`, `deploy`, Apache-config, and private
REST-config scopes. Directories and symlinks are represented in the manifest
without following symlinks. Every entry records type, mode, UID/GID, size/hash
or symlink target; absent top-level and touched paths are explicit.
It rejects parent symlinks, unsafe types, and group/world-writable parents. It
creates the simulated remote backup in `/tmp`, copies it to a new private host
backup directory, compares remote/local SHA-256, safely lists every member,
checks completeness and payload hashes, fsyncs manifest/checksum/marker and the
directory, and only then publishes `BACKUP_COMPLETE`. Package staging cannot
start before that event.

Publication uses same-directory temporary files, file fsync, atomic rename or
symlink replacement, and parent-directory fsync. The target package includes a
small static PPC helper that calls `renameat(2)` and `fsync(2)`, avoiding
unverified BusyBox `mv` behavior for symlink-to-directory destinations. Its
`--verify-release` operation rejects extra, missing, symlinked, hard-linked, wrongly owned, or
wrong-mode roots, subdirectories, and payloads in both staged and pre-existing release directories.
The device scripts compose that inode/shape check with the canonical checksum list from
the digest-approved package, so accepted native release bytes match the approved package.
The release directory is
immutable by ID. Apache syntax check precedes reload. Any failure after release,
current-pointer, config, syntax-check, reload, or health boundary restores the
prior pointer and configuration and removes the new release only if that run
created it. A release-publish error is treated as a potentially successful
`renameat()` followed by failed parent `fsync()`: the installer classifies the
destination against private package-bound manifest/checksum copies and removes it
only when that exact transaction-created release is proven. An unauthenticatable
post-rename destination is retained fail-closed and reported explicitly as an
incomplete automatic rollback with the path requiring operator inspection. Before
changing the live pointer or Apache config, deployment
durably publishes backup-bound transaction state and the active transaction.
Rollback accepts only exact pre/post mixtures from that transaction, so a real
process exit after state, active-record, temporary-tree creation, first payload,
final release rename, pointer, or config publication is
recoverable and idempotent.

Deterministic offline faults are available only in simulation, for example:

```sh
modern-WebUI/deploy/deploy.sh --simulate-root /tmp/pm3000-sim \
  --package /tmp/pm3000-release.tar --backup-dir /tmp/private-backups \
  --fault after_config
```

Supported names are shown by `deployment.py deploy-sim --help`.

## Verification

```sh
python3 -m unittest modern-WebUI.tests.test_deployment -v
python3 -m unittest discover -s modern-WebUI/tests -p 'test_*.py'
sh -n modern-WebUI/deploy/device-install.sh modern-WebUI/deploy/device-rollback.sh
bash -n modern-WebUI/deploy/deploy.sh modern-WebUI/deploy/rollback.sh
tar tf /tmp/pm3000-release.tar
(cd /tmp && sha256sum -c pm3000-release.tar.sha256)
```

Tests cover fresh install, update, stale backup, retries, source/package
mutation, digest mismatch, archive traversal, incomplete backup, parent-symlink
attack, package-path replacement, backup/stage copy and check failures, every
post-commit boundary, private device-package snapshot replacement, real subprocess exits at transaction-state/active/temporary-tree/first-payload/final-release/pointer/config
boundaries, interrupted rollback restoration, forged completion markers,
unsafe existing-release trees, config/reload/health failures,
selected-backup rollback, and token-store preservation.

## Rollback

Select the exact private backup directory printed/returned by deployment; never
select by age or silently reuse a stale backup:

```sh
modern-WebUI/deploy/rollback.sh \
  --simulate-root /tmp/pm3000-sim \
  --backup "$HOME/.local/state/pm3000-private-backups/2026-10-20.1-..."
```

Rollback re-verifies `BACKUP_COMPLETE`, archive and manifest SHA-256, safe member
names, completeness, and file payloads. It restores the prior config bytes,
mode and ownership where permitted, restores/removes the prior `current` state,
and removes only a release recorded absent before the selected deployment. It
never restores or deletes the token store. Reload is allowed only after syntax
success, followed by a legacy-root health check (a deterministic callback in
simulation; HTTPS `/` in the Stage 7 pilot).
`ROLLBACK_PENDING` binds retries to the deployment-state and backup-marker
hashes. `ROLLBACK_COMPLETE` is structured and integrity-bound; an idempotent
retry re-verifies the fully restored state instead of trusting marker presence.

## Stage 7 limitations

Run the preflight from an existing device shell while iTerm terminal logging is
enabled:

```sh
sh device-preflight.sh
```

Do not redirect its output on the appliance. The report begins with
`pm3000_preflight.format=1` and is complete only when its final line is
`pm3000_preflight.complete=yes`. It deliberately reports Authorization forwarding,
CGI `PATH_INFO`, static-helper execution, directory `fsync`, and SCP transport as
not tested because those checks require a later approved pilot action or write.

For the confirmed first-install state, run this on the Mac from the repository
root. Replace the local backup directory if desired; the SSH alias may come from
the Mac's existing OpenSSH configuration:

```bash
modern-WebUI/deploy/stage7-first-backup.sh \
  --target root@pdu1 \
  --backup-dir "$HOME/Library/Application Support/pm3000-revive/backups"
```

The remote SSH program only reads kernel, firmware hash, and the two managed
paths. The script refuses to continue unless both managed paths are absent. It
creates `REMOTE_INVENTORY.txt`, `BACKUP_ARCHIVE.tar`, `BACKUP_MANIFEST.json`, and
`BACKUP_COMPLETE` privately on the Mac, flushes them to disk, and prints their
directory and hashes to standard output. No SCP or remote write occurs in this
step.

No real appliance path, free-space value, owner/group IDs, BusyBox tar behavior,
Apache `SetEnvIf`/Authorization forwarding, CGI `PATH_INFO`, HTTPS health
endpoint, or SCP transport has
been observed in Stage 6. Consequently the host wrappers fail closed to local
simulation rather than pretending a remote pilot was verified. The POSIX device
helpers are reviewable pilot primitives, not authorization to run them. A live
pilot must first confirm the inventory and then add/test the narrow SSH/SCP
transport without weakening the backup gate.
