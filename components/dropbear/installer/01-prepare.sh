#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

TEST_PORT=2222
for option in "$@"; do
    case "$option" in
        --test-port=*) TEST_PORT=${option#--test-port=} ;;
        --help)
            printf 'Usage: %s [--test-port=PORT]\n' "$0"
            exit 0
            ;;
        *) die "unknown option: $option" ;;
    esac
done
case "$TEST_PORT" in ''|*[!0-9]*) die 'test port must be a decimal number' ;; esac
case "$TEST_PORT" in 0|0*) die 'test port must be canonical decimal without leading zeros' ;; esac
[ "$TEST_PORT" -ge 1 ] 2>/dev/null && [ "$TEST_PORT" -le 65535 ] 2>/dev/null || die 'test port must be between 1 and 65535'
[ "$TEST_PORT" != 22 ] || die 'phase 1 test port must not be 22'

require_root
require_commands awk chmod cmp cp df grep id kill ls mkdir mv readlink rm sed sha256sum sleep tr uname

require_regular_nonsymlink "$SCRIPT_DIR/PAYLOAD.sha256"
require_regular_nonsymlink "$SCRIPT_DIR/bin/dropbear"
require_regular_nonsymlink "$SCRIPT_DIR/bin/dropbearkey"
require_regular_nonsymlink "$SCRIPT_DIR/service/sshd"
require_regular_nonsymlink "$SCRIPT_DIR/common.sh"
require_regular_nonsymlink "$SCRIPT_DIR/01-prepare.sh"
require_regular_nonsymlink "$SCRIPT_DIR/02-activate.sh"
require_regular_nonsymlink "$SCRIPT_DIR/rollback.sh"
verified_manifest_hash=$(sha256_file "$SCRIPT_DIR/PAYLOAD.sha256")
(
    cd "$SCRIPT_DIR"
    sha256sum -c PAYLOAD.sha256
) || die 'package integrity verification failed; no changes were made'
[ "$(sha256_file "$SCRIPT_DIR/PAYLOAD.sha256")" = "$verified_manifest_hash" ] || die 'package manifest changed during verification; no changes were made'

machine=${PM3000_MACHINE:-$(uname -m)}
kernel=${PM3000_KERNEL:-$(uname -r)}
case "$machine" in ppc|powerpc|ppc32) ;; *) die "unsupported machine: $machine (expected 32-bit PowerPC)" ;; esac
case "$kernel" in 2.6.23*) ;; *) die "unsupported kernel: $kernel (expected Linux 2.6.23)" ;; esac

require_safe_existing_dir "$(root_path /mnt/hdUser)"
require_safe_existing_dir "$(root_path /etc)"
for existing_dir in \
    "$(root_path /mnt/hdUser/pm3000-revive)" \
    "$INSTALL_DIR" "$INSTALL_DIR/bin" "$INSTALL_DIR/hostkeys" "$INSTALL_DIR/state" \
    "$INSTALL_DIR/backup" "$INSTALL_DIR/service" "$INSTALL_DIR/lib" "$INSTALL_DIR/control" \
    "$RUN_DIR"; do
    if [ -e "$existing_dir" ] || is_symlink "$existing_dir"; then
        require_safe_existing_dir "$existing_dir"
    fi
done
if [ -e "$STATE_FILE" ]; then
    require_regular_nonsymlink "$STATE_FILE"
fi
require_regular_nonsymlink "$INIT_SCRIPT"
require_regular_nonsymlink "$OPENSSH_BIN"
[ -x "$(root_path /bin/bash)" ] || die 'required executable shell missing: /bin/bash'

if [ "${PM3000_INSTALLER_TESTING:-0}" != 1 ]; then
    grep -F ' /mnt/hdUser ' /proc/mounts >/dev/null 2>&1 || die '/mnt/hdUser is not mounted'
    free_kib=$(df -k "$(root_path /mnt/hdUser)" | awk 'NR == 2 {print $4}')
    case "$free_kib" in ''|*[!0-9]*) die 'cannot determine free space on /mnt/hdUser' ;; esac
    [ "$free_kib" -ge 1536 ] || die "insufficient free space on /mnt/hdUser: ${free_kib} KiB available, 1536 KiB required"
fi

existing_status=$(state_value STATUS 2>/dev/null || true)
package_hash=$(sha256_file "$SCRIPT_DIR/bin/dropbear")
if [ "$existing_status" = active ]; then
    installed_hash=$(sha256_file "$DROPBEAR_BIN" 2>/dev/null || true)
    existing_prod_pid=$(managed_dropbear_pid "$PROD_PIDFILE" 22 2>/dev/null || true)
    if [ "$installed_hash" = "$package_hash" ] && valid_pid "$existing_prod_pid"; then
        say 'This exact managed Dropbear build is already active on port 22; prepare is a no-op.'
        exit 0
    fi
    die 'installer state says active, but the managed service or build does not match; inspect before retrying'
fi
if [ "$existing_status" = prepared ]; then
    installed_hash=$(sha256_file "$DROPBEAR_BIN" 2>/dev/null || true)
    prepared_port=$(state_value TEST_PORT 2>/dev/null || true)
    prepared_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$prepared_port" 2>/dev/null || true)
    if [ "$installed_hash" = "$package_hash" ] && [ "$prepared_port" = "$TEST_PORT" ] && valid_pid "$prepared_pid"; then
        say "The exact build is already prepared and its single test listener is running on port $TEST_PORT (PID $prepared_pid)."
        say "Exactly one required client test remains: verify a remote command and an interactive shell, then run $INSTALL_DIR/control/02-activate.sh --confirmed-test."
        exit 0
    fi
    die 'an incomplete or mismatched prepared installation exists; inspect state and use rollback before retrying'
fi
if [ "$existing_status" = preparing ]; then
    preparing_hash=$(state_value BUILD_SHA256 2>/dev/null || true)
    preparing_port=$(state_value TEST_PORT 2>/dev/null || true)
    [ "$preparing_hash" = "$package_hash" ] || die 'interrupted preparation used a different build; run rollback before retrying'
    [ "$preparing_port" = "$TEST_PORT" ] || die "interrupted preparation used test port $preparing_port; rerun with --test-port=$preparing_port or use rollback"
    wait_for_managed_dropbear "$TEST_PIDFILE" "$preparing_port" >/dev/null 2>&1 || true
    preparing_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$preparing_port" 2>/dev/null || true)
    if valid_pid "$preparing_pid"; then
        preparing_original_pid=$(state_value ORIGINAL_PID 2>/dev/null || true)
        write_state prepared "$package_hash" "$preparing_port" "$preparing_pid" '' "$preparing_original_pid"
        say "Recovered interrupted preparation: the exact test listener is running on port $preparing_port (PID $preparing_pid)."
        say "After the required client tests, run $INSTALL_DIR/control/02-activate.sh --confirmed-test."
        exit 0
    fi
    die 'interrupted preparation has no verified listener; run rollback before retrying'
fi

port22_pid=$(listener_pid 22 2>/dev/null || true)
valid_pid "$port22_pid" || die 'cannot identify the current port-22 listener'
for known_dropbear in "$DROPBEAR_BIN" "$(root_path /mnt/hdUser/dropbear-test/dropbear-new)"; do
    if [ -f "$known_dropbear" ] && ! is_symlink "$known_dropbear" && [ "$(sha256_file "$known_dropbear")" = "$package_hash" ] && process_is_executable "$port22_pid" "$known_dropbear" && process_has_port_argument "$port22_pid" 22; then
        say "This exact Dropbear build is already active on port 22 from $known_dropbear; prepare is a no-op and does not migrate the working installation."
        exit 0
    fi
done
verified_openssh_pid "$port22_pid" >/dev/null 2>&1 || die 'port 22 is not owned by the expected vendor OpenSSH listener; refusing to alter an existing modernized or unknown installation'
occupied_test_pid=$(listener_pid "$TEST_PORT" 2>/dev/null || true)
[ -z "$occupied_test_pid" ] || die "test port $TEST_PORT is already owned by PID $occupied_test_pid; choose one explicit free port"

write_probe_hd=$(root_path /mnt/hdUser)/.pm3000-write-test.$$
write_probe_etc=$(root_path /etc)/.pm3000-write-test.$$
(umask 077; : >"$write_probe_hd") 2>/dev/null || die '/mnt/hdUser is not writable; no remount was attempted'
rm -f "$write_probe_hd"
(umask 077; : >"$write_probe_etc") 2>/dev/null || die '/etc is not writable; no remount was attempted'
rm -f "$write_probe_etc"

umask 077
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/hostkeys" "$INSTALL_DIR/state" "$INSTALL_DIR/backup" "$INSTALL_DIR/service" "$INSTALL_DIR/lib" "$INSTALL_DIR/control" "$RUN_DIR"
chmod 0700 "$INSTALL_DIR" "$INSTALL_DIR/bin" "$INSTALL_DIR/hostkeys" "$INSTALL_DIR/state" "$INSTALL_DIR/backup" "$INSTALL_DIR/service" "$INSTALL_DIR/lib" "$INSTALL_DIR/control" "$RUN_DIR"
for protected_dir in "$INSTALL_DIR" "$INSTALL_DIR/bin" "$INSTALL_DIR/hostkeys" "$INSTALL_DIR/state" "$INSTALL_DIR/backup" "$INSTALL_DIR/service" "$INSTALL_DIR/lib" "$INSTALL_DIR/control" "$RUN_DIR"; do
    require_safe_existing_dir "$protected_dir"
done

STAGE_DIR=$INSTALL_DIR/stage.$$
cleanup_stage() {
    if [ -n "${STAGE_DIR:-}" ] && [ -d "$STAGE_DIR" ] && ! is_symlink "$STAGE_DIR"; then
        rm -rf "$STAGE_DIR"
    fi
}
trap 'cleanup_stage' 0
trap 'cleanup_stage; exit 1' 1 2 15
mkdir "$STAGE_DIR" "$STAGE_DIR/bin" "$STAGE_DIR/service"
chmod 0700 "$STAGE_DIR" "$STAGE_DIR/bin" "$STAGE_DIR/service"
cp "$SCRIPT_DIR/PAYLOAD.sha256" "$STAGE_DIR/PAYLOAD.sha256"
cp "$SCRIPT_DIR/01-prepare.sh" "$SCRIPT_DIR/02-activate.sh" "$SCRIPT_DIR/rollback.sh" "$SCRIPT_DIR/common.sh" "$STAGE_DIR/"
cp "$SCRIPT_DIR/bin/dropbear" "$SCRIPT_DIR/bin/dropbearkey" "$STAGE_DIR/bin/"
cp "$SCRIPT_DIR/service/sshd" "$STAGE_DIR/service/sshd"
[ "$(sha256_file "$STAGE_DIR/PAYLOAD.sha256")" = "$verified_manifest_hash" ] || { rm -rf "$STAGE_DIR"; die 'staged package manifest differs from the verified manifest'; }
(cd "$STAGE_DIR" && sha256sum -c PAYLOAD.sha256) || { rm -rf "$STAGE_DIR"; die 'root-owned staged payload differs from the verified package'; }
package_hash=$(sha256_file "$STAGE_DIR/bin/dropbear")

if [ -e "$BACKUP_INIT" ]; then
    require_regular_nonsymlink "$BACKUP_INIT"
else
    atomic_preserve_copy "$INIT_SCRIPT" "$BACKUP_INIT"
fi
atomic_copy "$STAGE_DIR/bin/dropbear" "$DROPBEAR_BIN" 0700
atomic_copy "$STAGE_DIR/bin/dropbearkey" "$DROPBEARKEY_BIN" 0700
atomic_copy "$STAGE_DIR/service/sshd" "$MANAGED_INIT" 0700
atomic_copy "$STAGE_DIR/common.sh" "$INSTALL_DIR/lib/common.sh" 0600
atomic_copy "$STAGE_DIR/01-prepare.sh" "$INSTALL_DIR/control/01-prepare.sh" 0700
atomic_copy "$STAGE_DIR/02-activate.sh" "$INSTALL_DIR/control/02-activate.sh" 0700
atomic_copy "$STAGE_DIR/rollback.sh" "$INSTALL_DIR/control/rollback.sh" 0700
atomic_copy "$STAGE_DIR/common.sh" "$INSTALL_DIR/control/common.sh" 0600
rm -rf "$STAGE_DIR"
STAGE_DIR=
[ "$(sha256_file "$DROPBEAR_BIN")" = "$package_hash" ] || die 'installed Dropbear hash differs from the verified package'

if [ -e "$HOST_KEY" ]; then
    require_regular_nonsymlink "$HOST_KEY"
    chmod 0600 "$HOST_KEY"
    "$DROPBEARKEY_BIN" -y -f "$HOST_KEY" >/dev/null 2>&1 || die 'existing host key is invalid; it was not replaced'
else
    "$DROPBEARKEY_BIN" -t ed25519 -f "$HOST_KEY" >/dev/null 2>&1 || die 'host-key generation failed'
    chmod 0600 "$HOST_KEY"
fi

launch_interrupted=0
trap 'launch_interrupted=1' 1 2 15
write_state preparing "$package_hash" "$TEST_PORT" '' '' "$port22_pid"
start_dropbear "$TEST_PORT" "$TEST_PIDFILE" "$TEST_LAUNCH_PIDFILE" || die "Dropbear did not become healthy on test port $TEST_PORT; vendor SSH on port 22 was not changed; rollback clears the recorded preparing state"
test_pid=$(managed_dropbear_pid "$TEST_PIDFILE" "$TEST_PORT") || die 'cannot verify the test listener after startup'
write_state prepared "$package_hash" "$TEST_PORT" "$test_pid" '' "$port22_pid"
trap 'cleanup_stage' 0
trap 'cleanup_stage; exit 1' 1 2 15
[ "$launch_interrupted" = 0 ] || die 'preparation was interrupted after the test listener became recoverable; run rollback.sh or rerun phase 1'

say "Prepared Dropbear build SHA-256: $package_hash"
say "Single test listener: port $TEST_PORT, PID $test_pid"
say 'Host-key public data and fingerprint:'
"$DROPBEARKEY_BIN" -y -f "$HOST_KEY"
say 'Vendor OpenSSH on port 22 remains unchanged.'
say 'Exactly one required client test: verify an interactive login and a remote command against this test port.'
say 'For a newly built artifact, also verify classic SCP with scp -O.'
say "After success, run: $INSTALL_DIR/control/02-activate.sh --confirmed-test"
