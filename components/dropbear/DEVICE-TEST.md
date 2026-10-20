# Manual PM3000 Acceptance Procedure

This procedure validates the packaged two-phase installer on an Avocent PM3000 running firmware `2.0.1.23`. The repository build and automated tests never contact a PDU.

## Prerequisites

- Approved maintenance window and rollback owner.
- Existing vendor SSH session kept open through both phases.
- Confirmed console or other out-of-band recovery.
- Runtime archive and extracted `CHECKSUMS.sha256` verified on the workstation.
- `/mnt/hdUser`, `/etc`, `/bin/bash`, free space, and port 2222 ready.
- No private client key copied to the PDU.

Follow the [installer README](https://github.com/tseiman/pm3000-revive/blob/main/components/dropbear/installer/README.md) or the [full installation guide](https://github.com/tseiman/pm3000-revive/blob/main/docs/INSTALL_DROPBEAR.md) for transfer and exact commands.

## Phase 1 acceptance

Run `./01-prepare.sh` once on the PDU. Confirm:

- Package, platform, mounts, space, and current port-22 OpenSSH listener pass preflight.
- The original init script is preserved without overwriting an older backup.
- Existing host key is retained, or one new Ed25519 key is generated with mode `0600`.
- Exactly one Dropbear test listener runs on the selected test port, normally 2222.
- Vendor OpenSSH remains available on port 22.
- The displayed host-key fingerprint matches the client-observed fingerprint.

From a local client terminal, perform exactly the required acceptance:

1. A remote command returns `id`, `SHELL=/bin/bash`, and the expected marker.
2. A command-free PTY connection opens interactive Bash instead of failing in `/usr/bin/cli`.
3. A second connection succeeds.
4. For a newly rebuilt artifact, classic `scp -O` succeeds; SFTP is not expected.
5. Account UID/GID and permissions remain appropriate. The shell override must not make a regular account root.

Authentication success without a working shell or remote command is a failure.

## Phase 2 acceptance

Run `./02-activate.sh --confirmed-test` only after phase 1 passes. While the script waits for confirmation:

- Keep the phase-1 connection open.
- Open a **new** client connection to port 22.
- Repeat the remote-command and interactive-shell checks.
- Use client verbose output (`ssh -vv`) to confirm that the new connection's remote software banner identifies Dropbear. The managed init script is not installed until after confirmation, so do not use `/etc/init.d/sshd status` as this pre-confirmation gate.

Type `PORT-22-LOGIN-OK` only after those checks succeed. Then confirm:

- Managed Dropbear owns port 22.
- The test listener is gone.
- `/etc/init.d/sshd check` succeeds.
- `/etc/init.d/sshd status` reports the actual product, port, and PID.
- No permanent OpenSSH listener exists on an additional port.
- The original init script and host key remain protected under `/mnt/hdUser/pm3000-revive/dropbear/`.

If the new login fails, do not confirm. The script must request OpenSSH again on port 22 and retain the test listener. Use `rollback.sh` if the activation terminal is interrupted or state needs explicit restoration.

## Separate reboot acceptance

The installer never reboots and phase 2 does not prove boot persistence. At a separately approved time, account for the possible effect on powered equipment and reboot manually. After boot, confirm:

1. A normal port-22 login and remote command succeed.
2. `/etc/init.d/sshd status` identifies managed Dropbear, or clearly identifies the OpenSSH startup fallback.
3. No test listener or additional permanent SSH port remains.
4. Classic `scp -O` still works when file transfer is required.

## Abort conditions

Stop and retain the current recovery session if any of these occur:

- Unknown process owns port 22 or the selected test port.
- Package or installed-binary hash differs.
- PID, executable, arguments, or listener ownership cannot be verified.
- `/mnt/hdUser` or `/etc` is unavailable/read-only, space is insufficient, or `/bin/bash` is missing.
- Host-key generation/validation, PTY allocation, account mapping, or remote commands fail.
- OpenSSH cannot be restored after a rejected activation.
- Any step would require a filesystem remount, global process kill, automatic reboot, firmware change, or bootloader change.
