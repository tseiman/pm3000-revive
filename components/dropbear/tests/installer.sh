#!/bin/sh
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
SOURCE="$ROOT/installer"
TMP=${TMPDIR:-/tmp}/pm3000-installer-test.$$
trap 'cleanup' EXIT HUP INT TERM

cleanup() {
    if [ "${PM3000_KEEP_TEST_TMP:-0}" = 1 ]; then
        printf 'Preserving test tree: %s\n' "$TMP" >&2
        return
    fi
    if [ -d "$TMP" ]; then
        if [ -s "$TMP/proc-listener.pid" ]; then
            proc_listener_pid=$(sed -n '1p' "$TMP/proc-listener.pid" 2>/dev/null || true)
            case "$proc_listener_pid" in ''|*[!0-9]*) ;; *) kill "$proc_listener_pid" 2>/dev/null || true ;; esac
        fi
        for f in "$TMP"/*/*.pid "$TMP"/*/device/dev/pm3000-ssh/*.pid "$TMP"/*/device/var/run/*.pid; do
            [ -f "$f" ] || continue
            pid=$(sed -n '1p' "$f" 2>/dev/null || true)
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
        done
        rm -rf "$TMP"
    fi
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_file() {
    [ -f "$1" ] || fail "missing file: $1"
}

assert_contains() {
    grep -F "$2" "$1" >/dev/null 2>&1 || fail "$1 does not contain: $2"
}

assert_not_contains() {
    if grep -F "$2" "$1" >/dev/null 2>&1; then
        fail "$1 contains forbidden text: $2"
    fi
}

make_fake_package() {
    case_dir=$1
    pkg="$case_dir/package"
    mkdir -p "$pkg/bin" "$pkg/service"
    cp "$SOURCE/01-prepare.sh" "$SOURCE/02-activate.sh" "$SOURCE/rollback.sh" "$SOURCE/common.sh" "$pkg/"
    cp "$SOURCE/service/sshd" "$pkg/service/sshd"

    cat >"$pkg/bin/dropbear" <<'FAKE'
#!/bin/sh
pidfile=
port=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -P) pidfile=$2; shift 2 ;;
        -p) port=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$pidfile" ] || exit 2
[ -n "$port" ] || exit 2
if [ -e "$pidfile.delay-start" ]; then
    delay_seconds=$(sed -n '1p' "$pidfile.delay-start")
    case "$delay_seconds" in ''|*[!0-9]*) delay_seconds=15 ;; esac
    sleep "$delay_seconds"
fi
printf '%s\n' "$$" >"$pidfile"
if [ -e "$pidfile.ignore-term" ]; then
    trap ':' TERM
    trap 'rm -f "$pidfile"; exit 0' HUP INT
else
    trap 'rm -f "$pidfile"; exit 0' HUP INT TERM
fi
while :; do sleep 5; done
FAKE
    cat >"$pkg/bin/dropbearkey" <<'FAKE'
#!/bin/sh
mode=
key=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -t) mode=generate; shift 2 ;;
        -y) mode=show; shift ;;
        -f) key=$2; shift 2 ;;
        *) shift ;;
    esac
done
case "$mode" in
    generate) umask 077; printf 'TEST-PRIVATE-HOST-KEY\n' >"$key" ;;
    show) [ -s "$key" ] || exit 1; printf 'Public key portion is: ssh-ed25519 TEST\nFingerprint: SHA256:TEST\n' ;;
    *) exit 2 ;;
esac
FAKE
    chmod 0755 "$pkg/01-prepare.sh" "$pkg/02-activate.sh" "$pkg/rollback.sh" "$pkg/bin/dropbear" "$pkg/bin/dropbearkey" "$pkg/service/sshd"
    (cd "$pkg" && sha256sum 01-prepare.sh 02-activate.sh rollback.sh common.sh service/sshd bin/dropbear bin/dropbearkey > PAYLOAD.sha256)
}

make_device() {
    case_dir=$1
    device="$case_dir/device"
    mkdir -p "$device/mnt/hdUser" "$device/etc/init.d" "$device/etc/rc2.d" "$device/etc/rc3.d" "$device/etc/rc4.d" "$device/etc/rc5.d" "$device/etc/rc0.d" "$device/etc/rc1.d" "$device/etc/rc6.d" "$device/usr/sbin" "$device/bin" "$device/dev" "$device/var/run"
    : >"$device/.pm3000-test-platform"
    cp /bin/sh "$device/bin/bash"
    chmod 0755 "$device/bin/bash"
    cat >"$device/usr/sbin/sshd" <<'FAKE'
#!/bin/sh
pidfile=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -P) pidfile=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$pidfile" ] || exit 2
printf '%s\n' "$$" >"$pidfile"
trap 'rm -f "$pidfile"; exit 0' HUP INT TERM
while :; do sleep 5; done
FAKE
    chmod 0755 "$device/usr/sbin/sshd"
    cat >"$device/etc/init.d/sshd" <<EOF_ORIGINAL
#!/bin/sh
case "\${1:-}" in
start)
    printf '%s\n' "\$0" >"$device/var/run/sshd-start-argv0"
    "$device/usr/sbin/sshd" -P "$device/var/run/sshd.pid" >/dev/null 2>&1 &
    ;;
stop)
    if [ -s "$device/var/run/sshd.pid" ]; then
        kill "\$(sed -n '1p' "$device/var/run/sshd.pid")" 2>/dev/null || true
    fi
    ;;
*) exit 2 ;;
esac
EOF_ORIGINAL
    chmod 0755 "$device/etc/init.d/sshd"
    for runlevel in 2 3 4 5; do ln -s ../init.d/sshd "$device/etc/rc$runlevel.d/S09sshd"; done
    for runlevel in 0 1 6; do ln -s ../init.d/sshd "$device/etc/rc$runlevel.d/K09sshd"; done
    "$device/etc/init.d/sshd" start
    for ignored in 1 2 3 4 5 6 7 8 9 10; do
        [ -s "$device/var/run/sshd.pid" ] && break
        sleep 1
    done
    [ -s "$device/var/run/sshd.pid" ] || fail 'fake OpenSSH failed to start'
}

run_prepare() {
    case_dir=$1
    shift
    PATH=${PM3000_TEST_PATH:-$PATH} PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_dir/device" PM3000_MACHINE=ppc PM3000_KERNEL=2.6.23-test "$case_dir/package/01-prepare.sh" "$@"
}

run_activate() {
    case_dir=$1
    shift
    PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_dir/device" "$case_dir/device/mnt/hdUser/pm3000-revive/dropbear/control/02-activate.sh" "$@"
}

run_rollback() {
    case_dir=$1
    PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_dir/device" "$case_dir/device/mnt/hdUser/pm3000-revive/dropbear/control/rollback.sh"
}

# Contract and syntax.
for file in 01-prepare.sh 02-activate.sh rollback.sh common.sh service/sshd; do
    assert_file "$SOURCE/$file"
    sh -n "$SOURCE/$file"
done
for file in "$SOURCE"/*.sh "$SOURCE/service/sshd"; do
    assert_not_contains "$file" 'killall'
    assert_not_contains "$file" 'pkill'
    assert_not_contains "$file" 'start-stop-daemon -K'
    assert_not_contains "$file" '/sbin/reboot'
    assert_not_contains "$file" '2223'
    assert_not_contains "$file" '2224'
    assert_not_contains "$file" '2225'
    assert_not_contains "$file" '2226'
    assert_not_contains "$file" '2227'
    assert_not_contains "$file" '2228'
done
assert_contains "$SOURCE/service/sshd" 'start)'
assert_contains "$SOURCE/service/sshd" 'stop)'
assert_contains "$SOURCE/service/sshd" 'status)'
assert_contains "$SOURCE/service/sshd" 'check)'
mkdir -p "$TMP"
if "$SOURCE/01-prepare.sh" --test-port=0222 >"$TMP/leading-zero-port.out" 2>&1; then
    fail 'prepare accepted a non-canonical leading-zero port'
fi
assert_contains "$TMP/leading-zero-port.out" 'without leading zeros'

# The production listener lookup maps a real LISTEN socket inode back to its unique PID.
mkdir -p "$TMP"
proc_listener_info="$TMP/proc-listener.info"
python3 - "$proc_listener_info" <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
with open(sys.argv[1], 'w', encoding='ascii') as f:
    f.write(str(s.getsockname()[1]) + '\n')
while True:
    time.sleep(1)
PY
proc_listener_pid=$!
printf '%s\n' "$proc_listener_pid" >"$TMP/proc-listener.pid"
for ignored in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$proc_listener_info" ] && break
    sleep 1
done
[ -s "$proc_listener_info" ] || fail 'real proc listener did not publish its port'
proc_listener_port=$(sed -n '1p' "$proc_listener_info")
proc_owner=$(PM3000_INSTALLER_TESTING=0 sh -c '. "$1"; listener_pid "$2"' sh "$SOURCE/common.sh" "$proc_listener_port")
[ "$proc_owner" = "$proc_listener_pid" ] || fail "proc listener lookup returned PID $proc_owner instead of $proc_listener_pid"
kill "$proc_listener_pid" 2>/dev/null || true
wait "$proc_listener_pid" 2>/dev/null || true
rm -f "$TMP/proc-listener.pid"

mkdir -p "$TMP"

# Existing protected child symlinks must be rejected before their targets are mutated.
case_symlink="$TMP/symlink"
mkdir -p "$case_symlink"
make_fake_package "$case_symlink"
make_device "$case_symlink"
mkdir -p "$case_symlink/device/mnt/hdUser/pm3000-revive/dropbear" "$case_symlink/symlink-target"
chmod 0755 "$case_symlink/symlink-target"
ln -s "$case_symlink/symlink-target" "$case_symlink/device/mnt/hdUser/pm3000-revive/dropbear/bin"
if run_prepare "$case_symlink" >"$case_symlink/out" 2>&1; then
    fail 'prepare accepted a symlinked protected child directory'
fi
[ "$(stat -c '%a' "$case_symlink/symlink-target")" = 755 ] || fail 'prepare mutated a protected child symlink target before rejection'

# Runtime log symlinks must be rejected without touching their targets.
case_log_symlink="$TMP/log-symlink"
mkdir -p "$case_log_symlink"
make_fake_package "$case_log_symlink"
make_device "$case_log_symlink"
mkdir -p "$case_log_symlink/device/dev/pm3000-ssh"
chmod 0700 "$case_log_symlink/device/dev/pm3000-ssh"
printf 'LOG-SYMLINK-SENTINEL\n' >"$case_log_symlink/log-target"
ln -s "$case_log_symlink/log-target" "$case_log_symlink/device/dev/pm3000-ssh/dropbear-test.log"
if ! run_prepare "$case_log_symlink" >"$case_log_symlink/out" 2>&1; then
    fail 'prepare failed merely because an unused legacy runtime log symlink exists'
fi
[ "$(sed -n '1p' "$case_log_symlink/log-target")" = 'LOG-SYMLINK-SENTINEL' ] || fail 'prepare wrote through a runtime log symlink'
run_rollback "$case_log_symlink" >"$case_log_symlink/rollback.out"

# A package and manifest replaced after the first successful check must not be staged.
case_package_race="$TMP/package-race"
mkdir -p "$case_package_race/wrappers"
make_fake_package "$case_package_race"
make_device "$case_package_race"
real_sha256sum=$(command -v sha256sum)
cat >"$case_package_race/wrappers/sha256sum" <<EOF_WRAPPER
#!/bin/sh
if [ "\${1:-}" = -c ] && [ "\${2:-}" = PAYLOAD.sha256 ] && [ ! -e "$case_package_race/replaced" ]; then
    "$real_sha256sum" "\$@" || exit \$?
    : >"$case_package_race/replaced"
    printf '\n# replaced after initial verification\n' >>bin/dropbear
    "$real_sha256sum" 01-prepare.sh 02-activate.sh rollback.sh common.sh service/sshd bin/dropbear bin/dropbearkey >PAYLOAD.sha256
    exit 0
fi
exec "$real_sha256sum" "\$@"
EOF_WRAPPER
chmod 0755 "$case_package_race/wrappers/sha256sum"
if PM3000_TEST_PATH="$case_package_race/wrappers:$PATH" run_prepare "$case_package_race" >"$case_package_race/out" 2>&1; then
    fail 'prepare accepted payload and manifest replacement after initial verification'
fi
[ ! -e "$case_package_race/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state" ] || fail 'package replacement race wrote installer state'

# Corrupt payload must fail before persistent installation.
case_bad="$TMP/bad"
mkdir -p "$case_bad"
make_fake_package "$case_bad"
make_device "$case_bad"
printf 'corrupt\n' >>"$case_bad/package/bin/dropbear"
if run_prepare "$case_bad" >"$case_bad/out" 2>&1; then
    fail 'prepare accepted a corrupt payload'
fi
[ ! -e "$case_bad/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state" ] || fail 'corrupt prepare wrote state'

# A manual listener with an unrelated PID file must block the single test port.
case_collision="$TMP/collision"
mkdir -p "$case_collision"
make_fake_package "$case_collision"
make_device "$case_collision"
cp "$case_collision/package/bin/dropbear" "$case_collision/device/mnt/hdUser/foreign-dropbear"
chmod 0755 "$case_collision/device/mnt/hdUser/foreign-dropbear"
"$case_collision/device/mnt/hdUser/foreign-dropbear" -F -p 0.0.0.0:2222 -P "$case_collision/foreign.pid" >/dev/null 2>&1 &
foreign_pid=$!
for ignored in 1 2 3 4 5; do
    [ -s "$case_collision/foreign.pid" ] && break
    sleep 1
done
if run_prepare "$case_collision" >"$case_collision/out" 2>&1; then
    fail 'prepare ignored a manual listener with a different PID file'
fi
[ ! -e "$case_collision/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state" ] || fail 'port-collision prepare wrote state'
kill "$foreign_pid" 2>/dev/null || true
for ignored in 1 2 3 4 5; do
    kill -0 "$foreign_pid" 2>/dev/null || break
    sleep 1
done
if kill -0 "$foreign_pid" 2>/dev/null; then fail 'manual test listener did not stop'; fi

# An exact historical installation already serving port 22 is a no-op.
case_historical="$TMP/historical"
mkdir -p "$case_historical"
make_fake_package "$case_historical"
make_device "$case_historical"
mkdir -p "$case_historical/device/mnt/hdUser/dropbear-test"
cp "$case_historical/package/bin/dropbear" "$case_historical/device/mnt/hdUser/dropbear-test/dropbear-new"
chmod 0755 "$case_historical/device/mnt/hdUser/dropbear-test/dropbear-new"
historical_pid=$(sed -n '1p' "$case_historical/device/var/run/sshd.pid")
kill "$historical_pid" 2>/dev/null || true
for ignored in 1 2 3 4 5; do kill -0 "$historical_pid" 2>/dev/null || break; sleep 1; done
"$case_historical/device/mnt/hdUser/dropbear-test/dropbear-new" -p 0.0.0.0:22 -P "$case_historical/historical.pid" >/dev/null 2>&1 &
for ignored in 1 2 3 4 5; do [ -s "$case_historical/historical.pid" ] && break; sleep 1; done
historical_pid=$(sed -n '1p' "$case_historical/historical.pid")
cp "$case_historical/package/bin/dropbear" "$case_historical/device/mnt/hdUser/foreign-test-dropbear"
chmod 0755 "$case_historical/device/mnt/hdUser/foreign-test-dropbear"
"$case_historical/device/mnt/hdUser/foreign-test-dropbear" -p 0.0.0.0:2222 -P "$case_historical/foreign-test.pid" >/dev/null 2>&1 &
for ignored in 1 2 3 4 5; do [ -s "$case_historical/foreign-test.pid" ] && break; sleep 1; done
historical_foreign_pid=$(sed -n '1p' "$case_historical/foreign-test.pid")
run_prepare "$case_historical" >"$case_historical/historical.out"
assert_contains "$case_historical/historical.out" 'already active on port 22'
kill -0 "$historical_pid" 2>/dev/null || fail 'historical active build was disturbed'
kill -0 "$historical_foreign_pid" 2>/dev/null || fail 'historical no-op disturbed an unrelated test-port listener'
[ ! -e "$case_historical/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state" ] || fail 'historical no-op created installer state'
kill "$historical_pid" 2>/dev/null || true
kill "$historical_foreign_pid" 2>/dev/null || true
for ignored in 1 2 3 4 5; do kill -0 "$historical_pid" 2>/dev/null || break; sleep 1; done

# An interrupted prepare records enough identity for rollback to catch a delayed child.
case_interrupted="$TMP/interrupted"
mkdir -p "$case_interrupted"
make_fake_package "$case_interrupted"
make_device "$case_interrupted"
mkdir -p "$case_interrupted/device/dev/pm3000-ssh"
printf '15\n' >"$case_interrupted/device/dev/pm3000-ssh/dropbear-test.pid.delay-start"
run_prepare "$case_interrupted" >"$case_interrupted/prepare.out" 2>&1 &
interrupted_prepare_pid=$!
interrupted_state="$case_interrupted/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state"
interrupted_launch_pidfile="$case_interrupted/device/dev/pm3000-ssh/dropbear-test.launch.pid"
for ignored in 1 2 3 4 5 6 7 8 9 10; do
    if [ -s "$interrupted_state" ] && [ -s "$interrupted_launch_pidfile" ] && grep -F 'STATUS=preparing' "$interrupted_state" >/dev/null 2>&1; then break; fi
    sleep 1
done
assert_contains "$interrupted_state" 'STATUS=preparing'
assert_file "$interrupted_launch_pidfile"
kill -TERM "$interrupted_prepare_pid" 2>/dev/null || fail 'could not interrupt preparing process'
wait "$interrupted_prepare_pid" 2>/dev/null || true
run_rollback "$case_interrupted" >"$case_interrupted/rollback.out"
assert_contains "$interrupted_state" 'STATUS=rolled_back'
[ ! -e "$case_interrupted/device/dev/pm3000-ssh/dropbear-test.pid" ] || fail 'interrupted prepare rollback retained the test PID file'
[ ! -e "$interrupted_launch_pidfile" ] || fail 'interrupted prepare rollback retained the launch PID file'
if PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_interrupted/device" sh -c '. "$1"; listener_pid 2222' sh "$case_interrupted/device/mnt/hdUser/pm3000-revive/dropbear/control/common.sh" >/dev/null 2>&1; then
    fail 'interrupted prepare rollback retained the delayed test listener'
fi

# Fresh preparation starts exactly one persistent test listener on 2222.
case_ok="$TMP/ok"
mkdir -p "$case_ok"
make_fake_package "$case_ok"
make_device "$case_ok"
original_mode=$(stat -c '%a' "$case_ok/device/etc/init.d/sshd")
run_prepare "$case_ok" >"$case_ok/prepare.out"
state="$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state"
assert_file "$state"
assert_contains "$state" 'STATUS=prepared'
assert_contains "$state" 'TEST_PORT=2222'
[ -z "$(find "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear" -maxdepth 1 -type d -name 'stage.*' -print)" ] || fail 'temporary payload staging directory remained'
test_pid=$(sed -n 's/^TEST_PID=//p' "$state")
kill -0 "$test_pid" 2>/dev/null || fail 'test listener is not alive'
assert_file "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/backup/sshd.openssh-original"
assert_file "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/hostkeys/dropbear_ed25519_host_key"
assert_contains "$case_ok/prepare.out" 'Exactly one required client test'

# Re-running prepare reuses the key and listener instead of rotating or multiplying.
key_hash=$(sha256sum "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/hostkeys/dropbear_ed25519_host_key")
run_prepare "$case_ok" >"$case_ok/prepare-again.out"
new_test_pid=$(sed -n 's/^TEST_PID=//p' "$state")
[ "$new_test_pid" = "$test_pid" ] || fail 'prepare replaced the healthy test listener'
[ "$(sha256sum "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/hostkeys/dropbear_ed25519_host_key")" = "$key_hash" ] || fail 'prepare rotated host key'

# Activation requires explicit phase-1 confirmation and a second port-22 confirmation.
if run_activate "$case_ok" >"$case_ok/no-confirm.out" 2>&1; then
    fail 'activation succeeded without --confirmed-test'
fi
printf 'PORT-22-LOGIN-OK\n' | run_activate "$case_ok" --confirmed-test >"$case_ok/activate.out"
assert_contains "$state" 'STATUS=active'
prod_pid=$(sed -n 's/^PROD_PID=//p' "$state")
kill -0 "$prod_pid" 2>/dev/null || fail 'production listener is not alive'
if kill -0 "$test_pid" 2>/dev/null; then fail 'test listener remained after activation'; fi
cmp "$case_ok/device/etc/init.d/sshd" "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/service/sshd" >/dev/null || fail 'managed init script not installed'
assert_contains "$case_ok/activate.out" 'A reboot has not been tested'

# Refusing the second confirmation restores OpenSSH and retains the test listener.
case_reject="$TMP/reject"
mkdir -p "$case_reject"
make_fake_package "$case_reject"
make_device "$case_reject"
run_prepare "$case_reject" >"$case_reject/prepare.out"
reject_state="$case_reject/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state"
reject_test_pid=$(sed -n 's/^TEST_PID=//p' "$reject_state")
if printf 'NO\n' | run_activate "$case_reject" --confirmed-test >"$case_reject/activate.out" 2>&1; then
    fail 'activation accepted a rejected port-22 confirmation'
fi
assert_contains "$reject_state" 'STATUS=prepared'
kill -0 "$reject_test_pid" 2>/dev/null || fail 'rejected activation removed the recovery test listener'
reject_openssh_pid=$(sed -n '1p' "$case_reject/device/var/run/sshd.pid")
kill -0 "$reject_openssh_pid" 2>/dev/null || fail 'rejected activation did not restore OpenSSH'
if [ -s "$case_reject/device/dev/pm3000-ssh/dropbear.pid" ]; then
    reject_prod_pid=$(sed -n '1p' "$case_reject/device/dev/pm3000-ssh/dropbear.pid")
    if kill -0 "$reject_prod_pid" 2>/dev/null; then fail 'rejected activation left production Dropbear running'; fi
fi
run_rollback "$case_reject" >"$case_reject/rollback.out"
assert_contains "$reject_state" 'STATUS=rolled_back'
[ ! -e "$case_reject/device/dev/pm3000-ssh/dropbear-test.pid" ] || fail 'prepared-state rollback retained the test PID file'
if PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_reject/device" sh -c '. "$1"; listener_pid 2222' sh "$case_reject/device/mnt/hdUser/pm3000-revive/dropbear/control/common.sh" >/dev/null 2>&1; then
    fail 'prepared-state rollback retained a test-port listener'
fi
run_prepare "$case_reject" >"$case_reject/reprepare.out"
assert_contains "$reject_state" 'STATUS=prepared'
run_rollback "$case_reject" >"$case_reject/second-rollback.out"
assert_contains "$reject_state" 'STATUS=rolled_back'

# A provisional listener that ignores TERM is not misreported as reverted.
case_stuck="$TMP/stuck"
mkdir -p "$case_stuck"
make_fake_package "$case_stuck"
make_device "$case_stuck"
run_prepare "$case_stuck" >"$case_stuck/prepare.out"
touch "$case_stuck/device/dev/pm3000-ssh/dropbear.pid.ignore-term"
if printf 'NO\n' | run_activate "$case_stuck" --confirmed-test >"$case_stuck/activate.out" 2>&1; then
    fail 'activation succeeded when provisional Dropbear ignored TERM'
fi
assert_contains "$case_stuck/activate.out" 'did not stop'
stuck_prod_pid=$(sed -n '1p' "$case_stuck/device/dev/pm3000-ssh/dropbear.pid")
kill -0 "$stuck_prod_pid" 2>/dev/null || fail 'failed TERM path removed the still-running provisional listener'
assert_contains "$case_stuck/device/mnt/hdUser/pm3000-revive/dropbear/state/installer.state" 'STATUS=prepared'
kill -KILL "$stuck_prod_pid" 2>/dev/null || true
rm -f "$case_stuck/device/dev/pm3000-ssh/dropbear.pid" "$case_stuck/device/dev/pm3000-ssh/dropbear.pid.ignore-term"
run_rollback "$case_stuck" >"$case_stuck/rollback.out"

# Active prepare is a no-op and does not create a test listener.
run_prepare "$case_ok" >"$case_ok/prepare-active.out"
[ "$(sed -n 's/^PROD_PID=//p' "$state")" = "$prod_pid" ] || fail 'active prepare changed production PID'
assert_contains "$case_ok/prepare-active.out" 'already active'

# Boot/start failure uses the preserved vendor script with its original $0 path.
kill "$prod_pid" 2>/dev/null || fail 'could not stop managed production listener for fallback test'
for ignored in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$prod_pid" 2>/dev/null || break
    sleep 1
done
kill -0 "$prod_pid" 2>/dev/null && fail 'managed production listener did not stop for fallback test'
rm -f "$case_ok/device/dev/pm3000-ssh/dropbear.pid" "$case_ok/device/var/run/sshd-start-argv0"
printf '\nCORRUPTED-FOR-FALLBACK-TEST\n' >>"$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/bin/dropbear"
PM3000_INSTALLER_TESTING=1 PM3000_ROOT="$case_ok/device" "$case_ok/device/etc/init.d/sshd" start >"$case_ok/fallback-start.out"
assert_contains "$case_ok/fallback-start.out" 'Vendor OpenSSH fallback started'
[ "$(sed -n '1p' "$case_ok/device/var/run/sshd-start-argv0")" = "$case_ok/device/etc/init.d/sshd" ] || fail 'vendor init fallback did not preserve the original init-script $0 path'

# Rollback restores the original init script and keeps verified OpenSSH on port 22.
run_rollback "$case_ok" >"$case_ok/rollback.out"
cmp "$case_ok/device/etc/init.d/sshd" "$case_ok/device/mnt/hdUser/pm3000-revive/dropbear/backup/sshd.openssh-original" >/dev/null || fail 'rollback did not restore original init script'
[ "$(stat -c '%a' "$case_ok/device/etc/init.d/sshd")" = "$original_mode" ] || fail 'rollback changed original init-script mode'
assert_contains "$state" 'STATUS=rolled_back'
openssh_pid=$(sed -n '1p' "$case_ok/device/var/run/sshd.pid")
kill -0 "$openssh_pid" 2>/dev/null || fail 'rollback did not start OpenSSH'
assert_contains "$case_ok/rollback.out" 'Original OpenSSH restored on port 22'

printf 'INSTALLER_TESTS_OK\n'
