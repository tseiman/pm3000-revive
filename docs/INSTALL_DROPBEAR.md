# Installing Dropbear on the PM3000

This procedure targets Avocent PM3000 firmware `2.0.1.23`. It uses one parallel test on port 2222, then an explicitly confirmed move to port 22. No script reboots the PDU.

## 1. Verify the release on the Linux workstation

Download the runtime archive and its matching `.sha256` file from the same expected GitHub release. Keep them in one directory and run:

```bash
sha256sum -c pm3000-dropbear-runtime-2026.94.tar.xz.sha256
```

Continue only when the archive reports `OK`. A checksum proves integrity relative to the checksum file, not publisher authenticity; also confirm the HTTPS repository and expected release tag.

Extract and verify the complete package:

```bash
tar -xJf pm3000-dropbear-runtime-2026.94.tar.xz
cd pm3000-dropbear-runtime-2026.94
sha256sum -c CHECKSUMS.sha256
```

Stop on `FAILED`, a missing file, or any non-zero result.

## 2. Prepare recovery and transfer

Before changing the PDU:

- approve a maintenance window;
- confirm console or another out-of-band recovery path;
- keep a working vendor SSH session open;
- confirm that `/mnt/hdUser`, `/etc`, `/bin/bash`, port 2222, and available space meet the checks described in the package `README.md`;
- do not transfer passwords, private client keys, firmware images, or device backups.

Transfer the entire extracted directory to the PDU using an approved method. If Dropbear is already active, current OpenSSH clients must use classic SCP rather than SFTP:

```bash
cd ..
scp -O -r pm3000-dropbear-runtime-2026.94 USER@DEVICE_ADDRESS:/mnt/hdUser/
```

The original manufacturer SSH can reject remote-exec upload methods because its account shell is the Avocent CLI. When SCP is unavailable, use the manual bootstrap below instead of weakening the modern client globally.

### Optional bootstrap from the manufacturer SSH

This is a manual transport method, not an automated installer feature. First create a plain tar archive on the trusted workstation so the PM3000 does not need XZ support:

```bash
tar -cf pm3000-dropbear-runtime-2026.94.tar pm3000-dropbear-runtime-2026.94
sha256sum pm3000-dropbear-runtime-2026.94.tar
python3 -m http.server 8000
```

Record the displayed SHA-256 through the trusted workstation session. Ensure a temporary client firewall rule permits only the PDU to reach TCP port 8000, and remove that rule and stop the server immediately afterward.

Through the retained PDU session, first confirm sufficient temporary space in `/dev` and persistent space in `/mnt/hdUser`. Then fetch the response using the old two-argument `nc` syntax:

```sh
mkdir -p /dev/pm3000-transfer
{ printf 'GET /pm3000-dropbear-runtime-2026.94.tar HTTP/1.0\r\nHost: CLIENT_ADDRESS\r\nConnection: close\r\n\r\n'; sleep 10; } | nc CLIENT_ADDRESS 8000 > /dev/pm3000-transfer/package.http
```

Inspect the HTTP status and obtain the declared body length:

```sh
sed -n '1p' /dev/pm3000-transfer/package.http
content_length=$(sed -n 's/^[Cc]ontent-[Ll]ength: *\([0-9][0-9]*\)\r*$/\1/p' /dev/pm3000-transfer/package.http | sed -n '1p')
test -n "$content_length"
tail -c "$content_length" /dev/pm3000-transfer/package.http > /dev/pm3000-transfer/package.tar
test "$(wc -c < /dev/pm3000-transfer/package.tar)" = "$content_length"
sha256sum /dev/pm3000-transfer/package.tar
```

Continue only when the first line reports HTTP `200`, the extracted byte count equals `Content-Length`, and the device SHA-256 exactly equals the value recorded on the workstation. A matching old filename, size, or version string is not sufficient.

Extract only after those checks, then remove the temporary response and tar file:

```sh
cd /mnt/hdUser
tar -xf /dev/pm3000-transfer/package.tar
rm -f /dev/pm3000-transfer/package.http /dev/pm3000-transfer/package.tar
rmdir /dev/pm3000-transfer
cd /mnt/hdUser/pm3000-dropbear-runtime-2026.94
sha256sum -c CHECKSUMS.sha256
```

Stop if any checksum fails.

## 3. Phase 1: prepare and test once

On the PDU, through the retained vendor session:

```sh
cd /mnt/hdUser/pm3000-dropbear-runtime-2026.94
./01-prepare.sh
```

The script verifies package integrity, platform, writable mounts, free space, port ownership, and the existing OpenSSH listener before persistent changes. It installs under `/mnt/hdUser/pm3000-revive/dropbear`, preserves the original init script once, generates or reuses one protected host key, and starts exactly one Dropbear listener on port 2222. Port 22 remains on vendor OpenSSH. If the exact packaged build is already active on port 22 from the managed path or the known historical `/mnt/hdUser/dropbear-test/dropbear-new` path, phase 1 is a no-op and does not migrate the working installation.

On the workstation, compare the host-key fingerprint printed by phase 1, then perform one real remote-command test and one interactive login:

```bash
KNOWN_HOSTS=$(mktemp)
ssh-keyscan -p 2222 DEVICE_ADDRESS >"$KNOWN_HOSTS"
ssh-keygen -lf "$KNOWN_HOSTS"
ssh -p 2222 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" USER@DEVICE_ADDRESS 'id; printf "SHELL=%s COMMAND_OK\n" "$SHELL"'
ssh -tt -p 2222 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" USER@DEVICE_ADDRESS
rm -f "$KNOWN_HOSTS"
```

Authentication alone is insufficient. Confirm the remote command succeeds and the interactive session opens Bash rather than failing in `/usr/bin/cli`. For any newly rebuilt binary, additionally test `scp -O`.

## 4. Phase 2: activate and confirm port 22

Only after phase 1 succeeds:

```sh
cd /mnt/hdUser/pm3000-revive/dropbear/control
./02-activate.sh --confirmed-test
```

The script keeps the test listener available, stops only the verified OpenSSH listener parent, and starts Dropbear provisionally on port 22. From a separate workstation terminal, open a **new** port-22 connection and repeat the shell and remote-command checks. Then return to the activation prompt and type exactly:

```text
PORT-22-LOGIN-OK
```

Without this confirmation, the provisional listener is removed, OpenSSH is requested again on port 22, and the phase-1 listener remains available. After confirmation, `/etc/init.d/sshd` is atomically replaced by the managed SysV script and the test listener is removed.

The startup script tries preserved OpenSSH on port 22 if managed Dropbear fails during boot. It does not create a permanent fallback port and is not a runtime watchdog.

## 5. Rollback

Run through a retained working session:

```sh
cd /mnt/hdUser/pm3000-revive/dropbear/control
./rollback.sh
```

Rollback restores the original init script and verifies OpenSSH on port 22 before removing any remaining managed test listener. It targets only verified listener parent PIDs and never uses `killall`, `pkill`, or the original script's broad stop action.

## 6. Reboot acceptance

Phase 2 does not reboot or claim reboot persistence. At a separately approved time, manually reboot the PDU and account for the possible impact on connected equipment. Then verify:

```sh
/etc/init.d/sshd status
```

From the workstation, verify one normal port-22 login and remote command. Classic file transfer remains `scp -O`; SFTP is not included.

For the exact state paths, service commands, interruption behavior, and idempotent reruns, read the runtime package [`README.md`](../components/dropbear/installer/README.md).
