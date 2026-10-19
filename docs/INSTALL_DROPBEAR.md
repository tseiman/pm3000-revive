# Installing the Current Dropbear Milestone

This is an experimental parallel test installation, not a firmware replacement. It must not overwrite or stop the PM3000's existing SSH server.

## 1. Verify the release on the Linux workstation

Keep the runtime archive and its matching `.sha256` file from the same GitHub release in one directory:

```bash
sha256sum -c pm3000-dropbear-runtime-2026.94.tar.xz.sha256
```

Continue only when the runtime archive reports `OK`. The digest proves integrity relative to the checksum file; also confirm that both files came from the intended HTTPS release and expected tag. Then extract it:

```bash
tar -xJf pm3000-dropbear-runtime-2026.94.tar.xz
cd pm3000-dropbear-runtime-2026.94
sha256sum -c CHECKSUMS.sha256
```

Stop on `FAILED`, missing files, or any non-zero command result.

## 2. Prepare the device test

Before copying files:

- obtain an approved maintenance window;
- confirm console or other out-of-band recovery;
- keep the existing vendor SSH session open;
- verify sufficient temporary storage and that TCP port 2222 is unused;
- prepare an Ed25519 public key; never copy a private client key to the PM3000.

Copy the extracted directory to a temporary device path such as `/var/tmp/dropbear-test`. Do not overwrite `/usr/sbin/sshd`, `/usr/sbin/dropbear`, system libraries, startup scripts, or firmware partitions.

## 3. Generate a temporary host key

On the PM3000:

```bash
cd /var/tmp/dropbear-test
chmod 0755 bin/dropbear bin/dropbearkey
mkdir -m 0700 state
./bin/dropbearkey -t ed25519 -f state/dropbear_ed25519_host_key
```

Provision an authorized public key for a temporary test account using an approved local method. Confirm the account has a valid shell and correct UID/GID.

## 4. Start on port 2222

```bash
./bin/dropbear -F -s -p 2222 \
  -r "$PWD/state/dropbear_ed25519_host_key" \
  -P "$PWD/state/dropbear.pid" \
  >"$PWD/state/dropbear.log" 2>&1
```

`-F` keeps the process in the foreground and `-s` disables password login. Keep this session open.

On the PM3000, display the host-key fingerprint through the retained trusted session:

```bash
cd /var/tmp/dropbear-test
./bin/dropbearkey -y -f state/dropbear_ed25519_host_key
```

On the workstation, capture the port-2222 public key in a temporary file and display its fingerprint. Compare it exactly with the fingerprint shown through the retained session before connecting:

```bash
KNOWN_HOSTS=$(mktemp)
ssh-keyscan -p 2222 DEVICE_ADDRESS >"$KNOWN_HOSTS"
ssh-keygen -lf "$KNOWN_HOSTS"

ssh -vv -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  TEST_USER@DEVICE_ADDRESS 'id; uname -a; printf "COMMAND_OK\n"'

ssh -tt -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  TEST_USER@DEVICE_ADDRESS 'tty; printf "PTY_OK\n"'

rm -f "$KNOWN_HOSTS"
```

Also verify a second connection and confirm the original SSH service remains reachable.

## 5. Stop and remove

Terminate the foreground process with Ctrl-C, confirm port 2222 is no longer listening, remove the temporary key authorization/account according to local policy, retain required logs, and delete `/var/tmp/dropbear-test`.

For detailed acceptance and abort criteria, see [`components/dropbear/DEVICE-TEST.md`](../components/dropbear/DEVICE-TEST.md).
