#!/bin/sh
set -eu

DROPBEAR=${DROPBEAR:-/input/dropbear}
QEMU=${QEMU:-/usr/bin/qemu-ppc}
TEST_ROOT=${TEST_ROOT:-/tmp/login-shell-test}

rm -rf "$TEST_ROOT"
mkdir -p "$TEST_ROOT"
server=
cleanup() {
    if [ -n "$server" ]; then
        kill "$server" 2>/dev/null || true
        wait "$server" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"$QEMU" "$DROPBEAR" -h >"$TEST_ROOT/help.txt" 2>&1
grep -Fq -- '--login-shell /absolute/path' "$TEST_ROOT/help.txt"
printf 'LOGIN_SHELL_HELP_OK\n'

printf '#!/bin/sh\nexit 0\n' >"$TEST_ROOT/not-executable"
chmod 600 "$TEST_ROOT/not-executable"

expect_rejected() {
    name=$1
    expected=$2
    shift 2
    if "$QEMU" "$DROPBEAR" -F -p 127.0.0.1:2299 "$@" \
            >"$TEST_ROOT/$name.log" 2>&1; then
        echo "$name unexpectedly started" >&2
        exit 1
    fi
    grep -Fq -- "$expected" "$TEST_ROOT/$name.log"
}

expect_rejected relative 'requires an absolute path' --login-shell bin/sh
expect_rejected missing-file 'Cannot stat --login-shell' --login-shell /does/not/exist
expect_rejected directory 'is not a regular file' --login-shell /tmp
expect_rejected non-executable 'is not executable' --login-shell "$TEST_ROOT/not-executable"
expect_rejected missing-argument 'Missing argument for --login-shell' --login-shell
expect_rejected duplicate 'specified more than once' --login-shell /bin/sh --login-shell /bin/bash
printf 'LOGIN_SHELL_INVALID_PATHS_OK\n'

mkdir -p /home/tester/.ssh
"$QEMU" /input/dropbearkey -t ed25519 -f "$TEST_ROOT/hostkey" >/dev/null
ssh-keygen -q -t ed25519 -N "" -f "$TEST_ROOT/clientkey"
cp "$TEST_ROOT/clientkey.pub" /home/tester/.ssh/authorized_keys
chown -R tester:tester /home/tester/.ssh
chmod 700 /home/tester/.ssh
chmod 600 /home/tester/.ssh/authorized_keys
printf '[127.0.0.1]:2298 ' >"$TEST_ROOT/known_hosts"
"$QEMU" /input/dropbearkey -y -f "$TEST_ROOT/hostkey" | grep '^ssh-' >>"$TEST_ROOT/known_hosts"

ssh_test() {
    port=$1
    shift
    ssh -p "$port" -i "$TEST_ROOT/clientkey" -o BatchMode=yes \
        -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$TEST_ROOT/known_hosts" \
        tester@127.0.0.1 "$@"
}

start_server() {
    port=$1
    shift
    "$QEMU" "$DROPBEAR" -F -s -p "127.0.0.1:$port" \
        -r "$TEST_ROOT/hostkey" -P "$TEST_ROOT/dropbear-$port.pid" "$@" \
        >"$TEST_ROOT/server-$port.log" 2>&1 &
    server=$!
    sleep 1
    if ! kill -0 "$server" 2>/dev/null; then
        cat "$TEST_ROOT/server-$port.log" >&2
        exit 1
    fi
}

stop_server() {
    kill "$server"
    wait "$server" || true
    server=
}

start_server 2298
standard=$(ssh_test 2298 'printf "%s|%s" "$0" "$SHELL"')
stop_server
test "$standard" = 'sh|/bin/sh'
printf 'LOGIN_SHELL_DEFAULT_BEHAVIOR_OK\n'

start_server 2298 --login-shell /bin/bash
override=$(ssh_test 2298 'printf "%s|%s" "$0" "$SHELL"')
test "$override" = 'bash|/bin/bash'

stop_server
printf 'LOGIN_SHELL_REMOTE_COMMAND_OK\n'

start_server 2298 --login-shell /bin/bash
ssh -vv -tt -p 2298 -i "$TEST_ROOT/clientkey" -o BatchMode=yes \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$TEST_ROOT/known_hosts" tester@127.0.0.1 \
    'printf PTY_CHILD_STARTED' >"$TEST_ROOT/pty-session.out" \
    2>"$TEST_ROOT/pty-session.err" || true
grep -Fq -- 'PTY allocation request accepted' "$TEST_ROOT/pty-session.err"
stop_server
printf 'LOGIN_SHELL_PTY_ALLOCATION_OK\n'

printf '#!/bin/sh\nprintf "AUTHORIZED_FORCED|%%s|%%s" "$SHELL" "$SSH_ORIGINAL_COMMAND"\n' \
    >"$TEST_ROOT/authorized-command"
printf '#!/bin/sh\nprintf "GLOBAL_FORCED|%%s|%%s" "$SHELL" "$SSH_ORIGINAL_COMMAND"\n' \
    >"$TEST_ROOT/global-command"
chmod 755 "$TEST_ROOT/authorized-command" "$TEST_ROOT/global-command"
printf 'command="%s" ' "$TEST_ROOT/authorized-command" >/home/tester/.ssh/authorized_keys
cat "$TEST_ROOT/clientkey.pub" >>/home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 600 /home/tester/.ssh/authorized_keys

start_server 2298 --login-shell /bin/bash
authorized_forced=$(ssh_test 2298 'printf CLIENT_REQUEST')
stop_server
test "$authorized_forced" = 'AUTHORIZED_FORCED|/bin/bash|printf CLIENT_REQUEST'
printf 'LOGIN_SHELL_AUTHORIZED_KEYS_FORCED_COMMAND_OK\n'

start_server 2298 --login-shell /bin/bash -c "$TEST_ROOT/global-command"
global_forced=$(ssh_test 2298 'printf CLIENT_REQUEST')
stop_server
test "$global_forced" = 'GLOBAL_FORCED|/bin/bash|printf CLIENT_REQUEST'
printf 'LOGIN_SHELL_GLOBAL_FORCED_COMMAND_PRECEDENCE_OK\n'

printf '#!/bin/sh\nexit 0\n' >"$TEST_ROOT/unlisted-shell"
chmod 755 "$TEST_ROOT/unlisted-shell"
useradd -m -s "$TEST_ROOT/unlisted-shell" -p x badshell
mkdir -p /home/badshell/.ssh
cp "$TEST_ROOT/clientkey.pub" /home/badshell/.ssh/authorized_keys
chown -R badshell:badshell /home/badshell/.ssh
chmod 700 /home/badshell/.ssh
chmod 600 /home/badshell/.ssh/authorized_keys
start_server 2298 --login-shell /bin/bash
if ssh -p 2298 -i "$TEST_ROOT/clientkey" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$TEST_ROOT/known_hosts" \
        badshell@127.0.0.1 true >/dev/null 2>&1; then
    echo 'Account with unlisted shell unexpectedly authenticated' >&2
    exit 1
fi
grep -Fq "User 'badshell' has invalid shell, rejected" "$TEST_ROOT/server-2298.log"
stop_server
printf 'LOGIN_SHELL_INVALID_ACCOUNT_SHELL_REJECTED_OK\n'

mkdir -p /root/.ssh
cp "$TEST_ROOT/clientkey.pub" /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
start_server 2298 --login-shell /bin/bash -w
if ssh -p 2298 -i "$TEST_ROOT/clientkey" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$TEST_ROOT/known_hosts" \
        root@127.0.0.1 true >/dev/null 2>&1; then
    echo 'Root restriction unexpectedly bypassed' >&2
    exit 1
fi
grep -Fq 'root login rejected' "$TEST_ROOT/server-2298.log"
stop_server
printf 'LOGIN_SHELL_ACCOUNT_RESTRICTION_PRESERVED_OK\n'

start_server 2298 --login-shell /bin/bash -G root
root_group_result=$(ssh -p 2298 -i "$TEST_ROOT/clientkey" -o BatchMode=yes \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$TEST_ROOT/known_hosts" root@127.0.0.1 \
    'printf "%s|%s" "$USER" "$SHELL"')
test "$root_group_result" = 'root|/bin/bash'
if ssh_test 2298 true >/dev/null 2>&1; then
    echo 'Non-root account unexpectedly bypassed root-group restriction' >&2
    exit 1
fi
grep -Fq "user 'tester' is not a member" "$TEST_ROOT/server-2298.log"
stop_server
printf 'LOGIN_SHELL_ROOT_GROUP_RESTRICTION_OK\n'
