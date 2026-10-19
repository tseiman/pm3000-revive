# Manual PM3000 Test Procedure

This procedure deliberately runs Dropbear in parallel on TCP port 2222. Do not replace, stop, or reconfigure the vendor SSH server.

## Prerequisites

- Approved maintenance window and rollback owner.
- Existing vendor SSH session kept open throughout testing.
- Out-of-band recovery path confirmed.
- Runtime archive checksum verified off-device.
- A temporary writable directory with enough space (at least 2 MiB plus logs and keys).
- An authorized Ed25519 public key. Never copy private keys to the device.

## Stage files

Copy only the extracted runtime directory to a temporary location, for example `/var/tmp/dropbear-test`. Do not overwrite system binaries.

```sh
cd /var/tmp/dropbear-test
sha256sum -c CHECKSUMS.sha256
chmod 0755 bin/dropbear bin/dropbearkey
mkdir -m 0700 state
./bin/dropbearkey -t ed25519 -f state/dropbear_ed25519_host_key
```

Create a temporary test account or authorized-key location using the vendor-approved account-management method. Do not alter the production root account. Confirm that the account has a valid shell and that its `~/.ssh/authorized_keys` contains only the approved public key.

## Start in foreground

First verify that port 2222 is unused using the device's available passive socket-listing tool. Then, from the retained vendor SSH session:

```sh
./bin/dropbear -F -s -p 2222 \
  -r "$PWD/state/dropbear_ed25519_host_key" \
  -P "$PWD/state/dropbear.pid" \
  >"$PWD/state/dropbear.log" 2>&1
```

`-s` disables password authentication. Keep this foreground session open.

## Client checks

Display the host-key fingerprint through the retained vendor SSH session:

```sh
cd /var/tmp/dropbear-test
./bin/dropbearkey -y -f state/dropbear_ed25519_host_key
```

From an approved client, capture the port-2222 key in a temporary file. Display its fingerprint and compare it exactly with the value obtained through the retained session before connecting:

```sh
KNOWN_HOSTS=$(mktemp)
ssh-keyscan -p 2222 DEVICE_ADDRESS >"$KNOWN_HOSTS"
ssh-keygen -lf "$KNOWN_HOSTS"
ssh -vv -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  TEST_USER@DEVICE_ADDRESS 'uname -a; id; printf "COMMAND_OK\n"'
ssh -tt -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  TEST_USER@DEVICE_ADDRESS 'tty; printf "PTY_OK\n"'
rm -f "$KNOWN_HOSTS"
```

Confirm:

- Host-key fingerprint matches the locally generated key.
- Negotiated KEX/cipher/signature is one of those listed in `TEST-REPORT.md`.
- `COMMAND_OK` and `PTY_OK` are returned.
- A second connection succeeds.
- The vendor SSH service remains reachable on its original port.
- No unexpected errors appear in `state/dropbear.log` or the kernel log.

## Stop and clean up

Terminate the foreground Dropbear with Ctrl-C. Confirm port 2222 is no longer listening. Remove the temporary account/key authorization according to the approved procedure, then remove `/var/tmp/dropbear-test` when evidence has been retained.

## Abort conditions

Immediately stop the test if the vendor SSH service changes state, the device reports memory/storage pressure, authentication maps to an unexpected UID/GID, entropy/key generation fails, PTY allocation fails, or any reboot/service replacement would be required.
