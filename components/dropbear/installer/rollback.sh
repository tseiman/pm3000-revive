#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

case "${1:-}" in
    --help)
        printf 'Usage: %s\n' "$0"
        exit 0
        ;;
    '') ;;
    *) die "unknown option: $1" ;;
esac

require_root
require_commands awk chmod cmp cp grep kill mkdir mv rm sed sha256sum sleep tr
require_regular_nonsymlink "$BACKUP_INIT"

previous_status=$(state_value STATUS 2>/dev/null || true)
build_hash=$(state_value BUILD_SHA256 2>/dev/null || true)
test_port=$(state_value TEST_PORT 2>/dev/null || true)
test_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$test_port" 2>/dev/null || true)
prod_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
pending_test_pid=$(pending_dropbear_pid "$TEST_LAUNCH_PIDFILE" "$TEST_PIDFILE" "$test_port" 2>/dev/null || true)
pending_prod_pid=$(pending_dropbear_pid "$PROD_LAUNCH_PIDFILE" "$PROD_PIDFILE" 22 2>/dev/null || true)

port22_owner=$(listener_pid 22 2>/dev/null || true)
if valid_pid "$port22_owner" && ! verified_openssh_pid "$port22_owner" >/dev/null 2>&1; then
    if { ! valid_pid "$prod_pid" || [ "$port22_owner" != "$prod_pid" ]; } && { ! valid_pid "$pending_prod_pid" || [ "$port22_owner" != "$pending_prod_pid" ]; }; then
        die "port 22 is owned by unrecognized PID $port22_owner; rollback made no changes"
    fi
fi

prod_stop_pid=$prod_pid
valid_pid "$prod_stop_pid" || prod_stop_pid=$pending_prod_pid
if valid_pid "$prod_stop_pid"; then
    say "Stopping only managed Dropbear process PID $prod_stop_pid."
    stop_verified_pid "$prod_stop_pid" "$DROPBEAR_BIN" || die "managed Dropbear process PID $prod_stop_pid did not stop; original service was not restored"
    rm -f "$PROD_PIDFILE" "$PROD_LAUNCH_PIDFILE"
fi

atomic_preserve_copy "$BACKUP_INIT" "$INIT_SCRIPT"
fallback_pid=$(start_original_openssh 2>/dev/null || true)
if ! valid_pid "$fallback_pid"; then
    warn 'vendor OpenSSH could not be verified on port 22; attempting to restore managed Dropbear availability'
    recovery_pid=
    if [ -x "$MANAGED_INIT" ]; then
        "$MANAGED_INIT" start >/dev/null 2>&1 || true
        recovery_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
    fi
    if valid_pid "$recovery_pid"; then
        write_state active "$build_hash" "$test_port" "$test_pid" "$recovery_pid" ''
        die 'rollback failed to start OpenSSH; managed Dropbear was restarted on port 22, but the original init script is restored and must be repaired before reboot'
    fi
    die 'rollback failed: neither vendor OpenSSH nor managed Dropbear could be verified on port 22; retain the current recovery session'
fi

test_stop_pid=$test_pid
valid_pid "$test_stop_pid" || test_stop_pid=$pending_test_pid
if valid_pid "$test_stop_pid"; then
    stop_verified_pid "$test_stop_pid" "$DROPBEAR_BIN" || die "OpenSSH is restored, but managed test process PID $test_stop_pid did not stop"
    rm -f "$TEST_PIDFILE" "$TEST_LAUNCH_PIDFILE"
fi
write_state rolled_back "$build_hash" "$test_port" '' '' "$fallback_pid"

say "Original OpenSSH restored on port 22 (PID $fallback_pid)."
say "Original init script restored from: $BACKUP_INIT"
say 'No reboot was performed. Existing session children were not targeted.'
case "$previous_status" in
    active|prepared|preparing|rolled_back) ;;
    *) warn "previous installer status was '${previous_status:-unknown}'" ;;
esac
