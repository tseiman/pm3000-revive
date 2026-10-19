#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN="$ROOT/artifacts/bin"
READELF="$ROOT/output-buildroot/host/bin/powerpc-buildroot-linux-musl-readelf"
FILE_OUT="$ROOT/artifacts/logs/elf-file.txt"
READELF_OUT="$ROOT/artifacts/logs/readelf.txt"
mkdir -p "$ROOT/artifacts/logs"
file "$BIN/dropbear" "$BIN/dropbearkey" | tee "$FILE_OUT"
for f in dropbear dropbearkey; do
  header="$ROOT/artifacts/logs/readelf-$f.txt"
  "$READELF" -W -h -l -d "$BIN/$f" > "$header"
  grep -Fq 'Class:                             ELF32' "$header"
  grep -Fq "Data:                              2's complement, big endian" "$header"
  grep -Fq 'Machine:                           PowerPC' "$header"
  if grep -q INTERP "$header"; then echo "$f unexpectedly has PT_INTERP" >&2; exit 1; fi
  if grep -q NEEDED "$header"; then echo "$f unexpectedly has DT_NEEDED" >&2; exit 1; fi
  stack=$(grep 'GNU_STACK' "$header")
  printf '%s\n' "$stack" | grep -q ' RW '
  if printf '%s\n' "$stack" | grep -q ' RWE '; then echo "$f has executable GNU stack" >&2; exit 1; fi
done
cat "$ROOT/artifacts/logs/readelf-dropbear.txt" "$ROOT/artifacts/logs/readelf-dropbearkey.txt" > "$READELF_OUT"
docker build --pull=false -t pm3000-dropbear-test:bookworm -f "$ROOT/Dockerfile.test" "$ROOT"
docker run --rm -v "$BIN:/input:ro" pm3000-dropbear-test:bookworm sh -eu -c '
mkdir -p /tmp/ssh-test /home/tester/.ssh
/usr/bin/qemu-ppc /input/dropbear -V > /tmp/ssh-test/version.txt 2>&1
/usr/bin/qemu-ppc /input/dropbear -Q kex > /tmp/ssh-test/kex.txt 2>&1
/usr/bin/qemu-ppc /input/dropbear -Q sig > /tmp/ssh-test/sig.txt 2>&1
/usr/bin/qemu-ppc /input/dropbear -Q cipher > /tmp/ssh-test/cipher.txt 2>&1
/usr/bin/qemu-ppc /input/dropbear -Q mac > /tmp/ssh-test/mac.txt 2>&1
cat /tmp/ssh-test/version.txt /tmp/ssh-test/kex.txt /tmp/ssh-test/sig.txt /tmp/ssh-test/cipher.txt /tmp/ssh-test/mac.txt
for item in curve25519-sha256 diffie-hellman-group14-sha256; do grep -Fxq "$item" /tmp/ssh-test/kex.txt; done
grep -Fxq ssh-ed25519 /tmp/ssh-test/sig.txt
grep -Fxq rsa-sha2-256 /tmp/ssh-test/sig.txt
for item in chacha20-poly1305@openssh.com aes256-ctr aes128-ctr; do grep -Fxq "$item" /tmp/ssh-test/cipher.txt; done
grep -Fxq hmac-sha2-256 /tmp/ssh-test/mac.txt
for item in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1; do ! grep -Fxq "$item" /tmp/ssh-test/kex.txt; done
for item in ssh-rsa ssh-dss; do ! grep -Fxq "$item" /tmp/ssh-test/sig.txt; done
for item in 3des-cbc aes128-cbc aes256-cbc; do ! grep -Fxq "$item" /tmp/ssh-test/cipher.txt; done
for item in hmac-sha1 hmac-md5; do ! grep -Fxq "$item" /tmp/ssh-test/mac.txt; done
/usr/bin/qemu-ppc /input/dropbearkey -t ed25519 -f /tmp/ssh-test/hostkey
ssh-keygen -q -t ed25519 -N "" -f /tmp/ssh-test/clientkey
cp /tmp/ssh-test/clientkey.pub /home/tester/.ssh/authorized_keys
chown -R tester:tester /home/tester/.ssh
chmod 700 /home/tester/.ssh
chmod 600 /home/tester/.ssh/authorized_keys
printf "[127.0.0.1]:2222 " > /tmp/ssh-test/known_hosts
/usr/bin/qemu-ppc /input/dropbearkey -y -f /tmp/ssh-test/hostkey | grep "^ssh-" >> /tmp/ssh-test/known_hosts
/usr/bin/qemu-ppc /input/dropbear -F -s -p 127.0.0.1:2222 -r /tmp/ssh-test/hostkey -P /tmp/ssh-test/dropbear.pid >/tmp/ssh-test/server.log 2>&1 &
server=$!
trap "kill $server 2>/dev/null || true" EXIT INT TERM
sleep 1
if ! kill -0 "$server" 2>/dev/null; then cat /tmp/ssh-test/server.log >&2; exit 1; fi
for i in 1 2 3 4 5 6 7 8 9 10; do ssh -p 2222 -i /tmp/ssh-test/clientkey -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/ssh-test/known_hosts -o ConnectTimeout=1 tester@127.0.0.1 "printf COMMAND_OK" > /tmp/ssh-test/command.out 2>/tmp/ssh-test/client.err && break; sleep 1; done
if ! test "$(cat /tmp/ssh-test/command.out)" = COMMAND_OK; then cat /tmp/ssh-test/server.log /tmp/ssh-test/client.err >&2; exit 1; fi
ssh -vv -tt -p 2222 -i /tmp/ssh-test/clientkey -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/ssh-test/known_hosts tester@127.0.0.1 "printf PTY_CHILD_STARTED" > /tmp/ssh-test/pty.out 2>>/tmp/ssh-test/client.err || true
grep -q "PTY allocation request accepted" /tmp/ssh-test/client.err
ssh -p 2222 -i /tmp/ssh-test/clientkey -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/ssh-test/known_hosts tester@127.0.0.1 "printf RECONNECT_OK" > /tmp/ssh-test/reconnect.out 2>>/tmp/ssh-test/client.err
test "$(cat /tmp/ssh-test/reconnect.out)" = RECONNECT_OK
kill "$server"
wait "$server" || true
trap - EXIT INT TERM
printf "QEMU_USER_ED25519_OK\nSSH_ALGORITHMS_OK\nSSH_COMMAND_OK\nSSH_PTY_ALLOCATION_OK\nSSH_RECONNECT_OK\n"
' > "$ROOT/artifacts/logs/qemu-user-ssh-test.txt" 2>&1
cat "$ROOT/artifacts/logs/qemu-user-ssh-test.txt"
docker run --rm \
  -v "$BIN:/input:ro" \
  -v "$ROOT/tests:/tests:ro" \
  pm3000-dropbear-test:bookworm /tests/login-shell.sh \
  > "$ROOT/artifacts/logs/login-shell-test.txt" 2>&1
cat "$ROOT/artifacts/logs/login-shell-test.txt"
