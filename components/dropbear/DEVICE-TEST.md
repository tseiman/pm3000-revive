# Manual PM3000 Test Procedure

This procedure deliberately runs Dropbear in parallel on TCP port 2222. Do not replace, stop, or reconfigure the vendor SSH server.

## Prerequisites

- Approved maintenance window and rollback owner.
- Existing vendor SSH session kept open throughout testing.
- Out-of-band recovery path confirmed.
- Runtime archive checksum verified off-device.
- A temporary writable directory with enough space (at least 2 MiB plus logs and keys).
- An authorized Ed25519 public key. Never copy private keys to the device.
- `/bin/bash` exists and is an executable regular file.
- The existing `root` account remains otherwise eligible for SSH login, and the `root` group contains no account that should be excluded from this test.

## Stage files

Copy only the extracted runtime directory to a temporary location, for example `/var/tmp/dropbear-test`. Do not overwrite system binaries.

```sh
cd /var/tmp/dropbear-test
sha256sum -c CHECKSUMS.sha256
chmod 0755 bin/dropbear bin/dropbearkey
mkdir -m 0700 state
./bin/dropbearkey -t ed25519 -f state/dropbear_ed25519_host_key
```

Create an isolated key directory without changing `/root/.ssh/authorized_keys`, `/etc/passwd`, `/etc/shells`, PAM, or the Avocent account configuration:

```sh
mkdir -m 0700 state/auth
cp /approved/path/test_key.pub state/auth/authorized_keys
chmod 0600 state/auth/authorized_keys
id root
```

Inspect the `root` group membership using the commands available on the device. Continue only when `root` is a member and no other account that must be excluded belongs to that group. The original root login shell remains `/usr/bin/cli`; `--login-shell` must not be used to bypass an account that Dropbear otherwise rejects.

## Start in foreground

First verify that port 2222 is unused using the device's available passive socket-listing tool. Then, from the retained vendor SSH session:

```sh
./bin/dropbear -F -s -p 2222 \
  -D "$PWD/state/auth" -G root \
  --login-shell /bin/bash \
  -r "$PWD/state/dropbear_ed25519_host_key" \
  -P "$PWD/state/dropbear.pid" \
  >"$PWD/state/dropbear.log" 2>&1
```

`-s` disables password authentication but leaves public-key authentication enabled. `-D` isolates this instance from existing per-user key files, `-G root` restricts authentication to members of the verified root group, and `--login-shell /bin/bash` replaces `/usr/bin/cli` only after the account has passed Dropbear's normal checks. Keep this foreground session open.

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
  root@DEVICE_ADDRESS 'uname -a; id; printf "SHELL=%s COMMAND_OK\n" "$SHELL"'
ssh -tt -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  root@DEVICE_ADDRESS 'tty; printf "SHELL=%s PTY_OK\n" "$SHELL"'

ssh -tt -p 2222 -i APPROVED_PRIVATE_KEY \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  root@DEVICE_ADDRESS
rm -f "$KNOWN_HOSTS"
```

Confirm:

- Host-key fingerprint matches the locally generated key.
- Negotiated KEX/cipher/signature is one of those listed in `TEST-REPORT.md`.
- `COMMAND_OK` and `PTY_OK` are returned.
- Both command tests report `SHELL=/bin/bash`, and the command-free connection opens an interactive Bash session rather than `/usr/bin/cli`.
- A non-root account using the same test key is rejected by the `-G root` restriction.
- A second connection succeeds.
- The vendor SSH service remains reachable on its original port.
- No unexpected errors appear in `state/dropbear.log` or the kernel log.

## Stop and clean up

Terminate the foreground Dropbear with Ctrl-C. Confirm port 2222 is no longer listening. Remove the temporary key directory with the rest of `/var/tmp/dropbear-test` after required evidence has been retained.

## Abort conditions

Immediately stop the test if the vendor SSH service changes state, the device reports memory/storage pressure, authentication maps to an unexpected UID/GID, entropy/key generation fails, PTY allocation fails, or any reboot/service replacement would be required.
