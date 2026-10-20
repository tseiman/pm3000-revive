# PM3000 Dropbear Two-Phase Installer

This package installs the verified static Dropbear build on an Avocent PM3000 running firmware `2.0.1.23`. It never reboots the PDU and does not replace `/usr/sbin/sshd`, account data, firmware, or host configuration.

## Safety model

1. `01-prepare.sh` verifies the platform and package, installs persistent private files, preserves the original SSH init script, creates or reuses one Ed25519 host key, and starts exactly one parallel listener (default: port 2222).
2. `02-activate.sh --confirmed-test` runs only after a real test login. It provisionally moves Dropbear to port 22 while the test listener remains available. The init script is replaced and the test listener is removed only after a new port-22 login is explicitly confirmed.
3. `rollback.sh` restores the original init script and OpenSSH listener on port 22. It removes the test listener only after OpenSSH is verified.

No script runs `reboot`, changes `/etc/passwd`, rotates an existing host key, remounts filesystems, or uses process-name-wide kill commands.

## Prerequisites

- Approved maintenance window and an out-of-band recovery method.
- A trusted vendor SSH session kept open throughout both phases.
- Root access on the PDU.
- `/mnt/hdUser` and `/etc` writable in their normal firmware configuration.
- At least 1536 KiB free on `/mnt/hdUser`.
- TCP port 2222 unused, unless one other explicit test port is selected.
- `/bin/bash` present and executable.

Verify and extract the release archive on the Linux workstation before transfer. Transfer the complete extracted directory to the PDU; do not transfer a private client key.

## Phase 1: prepare and test once

**On the PDU, through the retained vendor session:**

```sh
cd /path/to/pm3000-dropbear-runtime-2026.94
./01-prepare.sh
```

The script prints the test PID, port, build hash, and host-key fingerprint. It keeps the vendor OpenSSH listener on port 22 unchanged. If the exact packaged build is already serving port 22 from either the managed path or the known historical `/mnt/hdUser/dropbear-test/dropbear-new` path, preparation reports that fact and exits without migrating or disturbing it.

**On the client workstation:**

```sh
KNOWN_HOSTS=$(mktemp)
ssh-keyscan -p 2222 DEVICE_ADDRESS >"$KNOWN_HOSTS"
ssh-keygen -lf "$KNOWN_HOSTS"
ssh -p 2222 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" USER@DEVICE_ADDRESS 'id; printf "SHELL=%s COMMAND_OK\n" "$SHELL"'
ssh -tt -p 2222 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" USER@DEVICE_ADDRESS
rm -f "$KNOWN_HOSTS"
```

Compare the fingerprint with the value printed through the retained trusted session. Confirm that the remote command succeeds and the interactive connection opens Bash rather than the Avocent CLI. For a newly built artifact, also test classic SCP:

```sh
scp -O -P 2222 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=KNOWN_HOSTS_FILE LOCAL_TEST_FILE USER@DEVICE_ADDRESS:/tmp/
```

Do not continue when authentication alone succeeds but the shell or remote command exits with an Avocent CLI error.

To use one explicitly selected alternative test port, rerun phase 1 only after confirming that the port is free:

```sh
./01-prepare.sh --test-port=PORT
```

The installer never searches through a series of fallback ports.

## Phase 2: activate port 22

Only after the phase-1 shell and remote-command test succeeds, run this through the retained test or vendor session:

```sh
cd /mnt/hdUser/pm3000-revive/dropbear/control
./02-activate.sh --confirmed-test
```

Keep that session open. When prompted, open a **new** client connection to port 22 and repeat the shell and remote-command checks. Return to the activation terminal and type exactly:

```text
PORT-22-LOGIN-OK
```

Without that exact confirmation, the provisional Dropbear listener is stopped, OpenSSH is requested again on port 22, and the phase-1 test listener remains available.

After confirmation, the managed SysV service is installed at `/etc/init.d/sshd` through the existing runlevel links and the test listener is removed. The service supports:

```sh
/etc/init.d/sshd start
/etc/init.d/sshd stop
/etc/init.d/sshd status
/etc/init.d/sshd check
```

`restart` and `reload` are deliberately unsupported. If Dropbear cannot start during boot, the service script tries the preserved vendor OpenSSH service on port 22. This is a startup fallback, not continuous runtime monitoring.

## Rollback

Run through a retained working session:

```sh
cd /mnt/hdUser/pm3000-revive/dropbear/control
./rollback.sh
```

Rollback stops only a verified managed Dropbear listener, atomically restores the preserved original init script, starts and verifies OpenSSH on port 22, and then removes a remaining managed test listener. It never targets established SSH session children by name.

Before starting the phase-1 listener, prepare records a `preparing` state with the verified build hash and test port. If phase 1 is interrupted, rerunning prepare can adopt only the exact verified listener; otherwise run rollback. Rollback waits briefly for a delayed child to publish its PID, verifies its executable, arguments, and socket ownership, and removes it.

## Persistent state

- Installation: `/mnt/hdUser/pm3000-revive/dropbear/`
- Original init backup: `/mnt/hdUser/pm3000-revive/dropbear/backup/sshd.openssh-original`
- Host key: `/mnt/hdUser/pm3000-revive/dropbear/hostkeys/dropbear_ed25519_host_key`
- Machine-readable state: `/mnt/hdUser/pm3000-revive/dropbear/state/installer.state`
- Durable controls: `/mnt/hdUser/pm3000-revive/dropbear/control/`
- Runtime listener and launch PID files: `/dev/pm3000-ssh/`

Dropbear runs with `-F` in the background of the service shell, so the recorded launch PID remains the actual listener PID instead of a short-lived daemon parent. Because this build has syslog disabled, standard output and standard error are redirected to `/dev/null`; the installer does not retain growing session logs.

The state file contains paths, build hash, ports, PIDs, and status only—never passwords, private-key contents, or session tokens. Existing backups and host keys are not overwritten.

## Completion boundary

A successful phase 2 proves a new port-22 login in the current boot. It does **not** prove reboot persistence. Schedule one manual reboot separately only when power-distribution impact is acceptable, then verify a normal login and `/etc/init.d/sshd status`. The installer never reboots automatically.
