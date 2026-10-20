#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

CONFIRMED_TEST=0
for option in "$@"; do
    case "$option" in
        --confirmed-test) CONFIRMED_TEST=1 ;;
        --help)
            printf 'Usage: %s --confirmed-test\n' "$0"
            exit 0
            ;;
        *) die "unknown option: $option" ;;
    esac
done

require_root
require_commands awk chmod cmp cp grep kill mkdir mv rm sed sha256sum sleep tr

current_status=$(state_value STATUS 2>/dev/null || true)
if [ "$current_status" = active ]; then
    current_prod_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
    valid_pid "$current_prod_pid" || die 'installer state says active, but managed Dropbear is not healthy on port 22'
    active_test_port=$(state_value TEST_PORT 2>/dev/null || true)
    active_test_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$active_test_port" 2>/dev/null || true)
    if valid_pid "$active_test_pid"; then
        stop_verified_pid "$active_test_pid" "$DROPBEAR_BIN" || die "stale managed test listener PID $active_test_pid did not stop"
        rm -f "$TEST_PIDFILE" "$TEST_LAUNCH_PIDFILE"
        active_hash=$(state_value BUILD_SHA256)
        active_original_pid=$(state_value ORIGINAL_PID 2>/dev/null || true)
        write_state active "$active_hash" "$active_test_port" '' "$current_prod_pid" "$active_original_pid"
    fi
    say "This exact managed installation is already active on port 22 (PID $current_prod_pid)."
    say 'A reboot is not performed or implied by this command.'
    exit 0
fi

[ "$CONFIRMED_TEST" = 1 ] || die 'phase 2 requires --confirmed-test after a real interactive login and remote-command test on the phase-1 port'
[ "$current_status" = prepared ] || die 'phase 1 is not in the prepared state'

build_hash=$(state_value BUILD_SHA256)
test_port=$(state_value TEST_PORT)
original_pid_recorded=$(state_value ORIGINAL_PID 2>/dev/null || true)
case "$build_hash" in ''|*[!0-9a-f]*) die 'invalid build hash in installer state' ;; esac
[ "${#build_hash}" -eq 64 ] || die 'invalid build hash length in installer state'
[ "$(sha256_file "$DROPBEAR_BIN")" = "$build_hash" ] || die 'installed Dropbear differs from the build tested in phase 1'

test_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$test_port" 2>/dev/null || true)
valid_pid "$test_pid" || die 'the verified phase-1 test listener is not running; port 22 was not changed'
require_regular_nonsymlink "$BACKUP_INIT"
require_regular_nonsymlink "$MANAGED_INIT"
require_regular_nonsymlink "$INSTALL_DIR/lib/common.sh"
sh -n "$MANAGED_INIT" || die 'managed service script failed syntax validation'

port22_owner=$(listener_pid 22 2>/dev/null || true)
valid_pid "$port22_owner" || die 'cannot identify the current port-22 listener; test listener remains available'
verified_openssh_pid "$port22_owner" >/dev/null 2>&1 || die "port 22 is not owned by the expected vendor OpenSSH listener (PID $port22_owner)"
if valid_pid "$original_pid_recorded" && [ "$port22_owner" != "$original_pid_recorded" ]; then
    warn "OpenSSH listener PID changed from $original_pid_recorded to $port22_owner; the current verified listener will be used"
fi

say "Stopping only the verified OpenSSH listener PID $port22_owner; existing session children are not targeted."
stop_verified_pid "$port22_owner" "$OPENSSH_BIN" || die "OpenSSH listener PID $port22_owner did not stop; test listener remains available"
rm -f "$OPENSSH_PIDFILE"

if ! "$MANAGED_INIT" start; then
    fallback_pid=$(start_original_openssh 2>/dev/null || true)
    write_state prepared "$build_hash" "$test_port" "$test_pid" '' "$fallback_pid"
    die 'Dropbear activation failed; vendor OpenSSH was requested on port 22 and the test listener was retained'
fi
prod_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
if ! valid_pid "$prod_pid"; then
    fallback_owner=$(listener_pid 22 2>/dev/null || true)
    if ! valid_pid "$fallback_owner" || ! verified_openssh_pid "$fallback_owner" >/dev/null 2>&1; then
        fallback_owner=$(start_original_openssh 2>/dev/null || true)
    fi
    write_state prepared "$build_hash" "$test_port" "$test_pid" '' "$fallback_owner"
    die 'managed Dropbear was not verified on port 22; vendor OpenSSH fallback was requested and the test listener was retained'
fi

say "Managed Dropbear is provisionally listening on port 22 (PID $prod_pid)."
say 'From a separate local client terminal, open a NEW connection to port 22 and verify an interactive shell and a remote command.'
say 'Return here only after that succeeds. Type exactly: PORT-22-LOGIN-OK'
printf '> '
confirmation=
IFS= read -r confirmation || confirmation=
if [ "$confirmation" != PORT-22-LOGIN-OK ]; then
    provisional_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
    if valid_pid "$provisional_pid"; then
        stop_verified_pid "$provisional_pid" "$DROPBEAR_BIN" || die "port-22 confirmation was not received, but provisional Dropbear PID $provisional_pid did not stop; the test listener remains available and rollback is required"
        rm -f "$PROD_PIDFILE" "$PROD_LAUNCH_PIDFILE"
    fi
    fallback_pid=$(start_original_openssh 2>/dev/null || true)
    valid_pid "$fallback_pid" || die 'port-22 confirmation was not received; provisional Dropbear stopped, but vendor OpenSSH could not be verified; the test listener remains available'
    write_state prepared "$build_hash" "$test_port" "$test_pid" '' "$fallback_pid"
    die 'port-22 confirmation was not received; provisional activation was reverted and the test listener was retained'
fi

atomic_copy "$MANAGED_INIT" "$INIT_SCRIPT" 0700
write_state active "$build_hash" "$test_port" "$test_pid" "$prod_pid" "$port22_owner"

verified_test_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$test_port" 2>/dev/null || true)
if valid_pid "$verified_test_pid"; then
    stop_verified_pid "$verified_test_pid" "$DROPBEAR_BIN" || die "activation succeeded, but test listener PID $verified_test_pid could not be stopped; rerun phase 2 to clean it up"
    rm -f "$TEST_PIDFILE" "$TEST_LAUNCH_PIDFILE"
fi
write_state active "$build_hash" "$test_port" '' "$prod_pid" "$port22_owner"

say 'Activation confirmed: managed Dropbear owns port 22 and the phase-1 test listener is removed.'
say "Original init script backup: $BACKUP_INIT"
say "Rollback command: $SCRIPT_DIR/rollback.sh"
say 'A reboot has not been tested or performed. Schedule a separate manual reboot only when its operational impact is acceptable.'
