#!/bin/sh
# Shared PM3000 Dropbear installer functions. POSIX sh; no modern BusyBox options assumed.

PM3000_ROOT=${PM3000_ROOT:-}
INSTALL_REL=/mnt/hdUser/pm3000-revive/dropbear
RUN_REL=/dev/pm3000-ssh
INIT_REL=/etc/init.d/sshd
OPENSSH_REL=/usr/sbin/sshd
OPENSSH_PID_REL=/var/run/sshd.pid

root_path() {
    printf '%s%s\n' "$PM3000_ROOT" "$1"
}

INSTALL_DIR=$(root_path "$INSTALL_REL")
RUN_DIR=$(root_path "$RUN_REL")
INIT_SCRIPT=$(root_path "$INIT_REL")
OPENSSH_BIN=$(root_path "$OPENSSH_REL")
OPENSSH_PIDFILE=$(root_path "$OPENSSH_PID_REL")
STATE_FILE=$INSTALL_DIR/state/installer.state
BACKUP_INIT=$INSTALL_DIR/backup/sshd.openssh-original
MANAGED_INIT=$INSTALL_DIR/service/sshd
DROPBEAR_BIN=$INSTALL_DIR/bin/dropbear
DROPBEARKEY_BIN=$INSTALL_DIR/bin/dropbearkey
HOST_KEY=$INSTALL_DIR/hostkeys/dropbear_ed25519_host_key
TEST_PIDFILE=$RUN_DIR/dropbear-test.pid
PROD_PIDFILE=$RUN_DIR/dropbear.pid
TEST_LAUNCH_PIDFILE=$RUN_DIR/dropbear-test.launch.pid
PROD_LAUNCH_PIDFILE=$RUN_DIR/dropbear.launch.pid

say() {
    printf '%s\n' "$*"
}

warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [ "${PM3000_INSTALLER_TESTING:-0}" = 1 ]; then
        return 0
    fi
    [ "$(id -u)" = 0 ] || die 'run this installer as root'
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_commands() {
    for command_name in "$@"; do
        require_command "$command_name"
    done
}

is_symlink() {
    [ -L "$1" ]
}

require_regular_nonsymlink() {
    [ -f "$1" ] || die "required regular file missing: $1"
    ! is_symlink "$1" || die "refusing symlink: $1"
}

require_safe_existing_dir() {
    dir_to_check=$1
    [ -d "$dir_to_check" ] || die "required directory missing: $dir_to_check"
    ! is_symlink "$dir_to_check" || die "refusing symlink directory: $dir_to_check"
    if [ "${PM3000_INSTALLER_TESTING:-0}" != 1 ]; then
        dir_listing=$(ls -ldn "$dir_to_check")
        dir_owner=$(printf '%s\n' "$dir_listing" | awk '{print $3}')
        [ "$dir_owner" = 0 ] || die "directory is not owned by root: $dir_to_check"
        printf '%s\n' "$dir_listing" | awk '{ mode = $1; if (substr(mode, 6, 1) == "w" || substr(mode, 9, 1) == "w") exit 1 }' || die "directory is group/world-writable: $dir_to_check"
    fi
}

atomic_copy() {
    source_file=$1
    destination_file=$2
    destination_mode=$3
    destination_dir=${destination_file%/*}
    temporary_file=$destination_dir/.pm3000-install.$$
    cp "$source_file" "$temporary_file" || die "cannot stage $destination_file"
    chmod "$destination_mode" "$temporary_file" || { rm -f "$temporary_file"; die "cannot protect $destination_file"; }
    cmp "$source_file" "$temporary_file" >/dev/null 2>&1 || { rm -f "$temporary_file"; die "staged copy differs: $destination_file"; }
    mv -f "$temporary_file" "$destination_file" || { rm -f "$temporary_file"; die "cannot publish $destination_file"; }
}

atomic_preserve_copy() {
    source_file=$1
    destination_file=$2
    destination_dir=${destination_file%/*}
    temporary_file=$destination_dir/.pm3000-preserve.$$
    cp -p "$source_file" "$temporary_file" || die "cannot stage $destination_file"
    cmp "$source_file" "$temporary_file" >/dev/null 2>&1 || { rm -f "$temporary_file"; die "staged copy differs: $destination_file"; }
    mv -f "$temporary_file" "$destination_file" || { rm -f "$temporary_file"; die "cannot publish $destination_file"; }
}

valid_pid() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -gt 1 ] 2>/dev/null
}

read_pid() {
    pid_file_to_read=$1
    [ -s "$pid_file_to_read" ] || return 1
    pid_value=$(sed -n '1p' "$pid_file_to_read" 2>/dev/null) || return 1
    valid_pid "$pid_value" || return 1
    printf '%s\n' "$pid_value"
}

process_alive() {
    valid_pid "$1" || return 1
    kill -0 "$1" 2>/dev/null
}

process_cmdline() {
    process_pid=$1
    [ -r "/proc/$process_pid/cmdline" ] || return 1
    tr '\000' ' ' <"/proc/$process_pid/cmdline"
}

process_is_executable() {
    process_pid=$1
    expected_executable=$2
    process_alive "$process_pid" || return 1
    if [ "${PM3000_INSTALLER_TESTING:-0}" = 1 ]; then
        process_cmdline "$process_pid" | grep -F "$expected_executable" >/dev/null 2>&1
        return $?
    fi
    [ -e "/proc/$process_pid/exe" ] || return 1
    [ "/proc/$process_pid/exe" -ef "$expected_executable" ]
}

process_has_argument() {
    process_pid=$1
    expected_argument=$2
    [ -r "/proc/$process_pid/cmdline" ] || return 1
    tr '\000' '\n' <"/proc/$process_pid/cmdline" | awk -v expected="$expected_argument" '$0 == expected { found = 1 } END { exit found ? 0 : 1 }'
}

process_has_port_argument() {
    process_pid=$1
    expected_port=$2
    [ -r "/proc/$process_pid/cmdline" ] || return 1
    tr '\000' '\n' <"/proc/$process_pid/cmdline" | awk -v port="$expected_port" '
        $0 == port { found = 1 }
        length($0) > length(port) && substr($0, length($0) - length(port), 1) == ":" && substr($0, length($0) - length(port) + 1) == port { found = 1 }
        END { exit found ? 0 : 1 }
    '
}

managed_dropbear_pid() {
    managed_pidfile=$1
    managed_port=$2
    managed_pid=$(read_pid "$managed_pidfile") || return 1
    process_is_executable "$managed_pid" "$DROPBEAR_BIN" || return 1
    process_has_argument "$managed_pid" "$managed_pidfile" || return 1
    process_has_port_argument "$managed_pid" "$managed_port" || return 1
    managed_owner=$(listener_pid "$managed_port" 2>/dev/null) || return 1
    [ "$managed_owner" = "$managed_pid" ] || return 1
    printf '%s\n' "$managed_pid"
}

pending_dropbear_pid() {
    pending_launch_pidfile=$1
    pending_managed_pidfile=$2
    pending_port=$3
    pending_pid=$(read_pid "$pending_launch_pidfile") || return 1
    process_is_executable "$pending_pid" "$DROPBEAR_BIN" || return 1
    process_has_argument "$pending_pid" "$pending_managed_pidfile" || return 1
    process_has_port_argument "$pending_pid" "$pending_port" || return 1
    printf '%s\n' "$pending_pid"
}

verified_openssh_pid() {
    candidate_pid=$1
    process_is_executable "$candidate_pid" "$OPENSSH_BIN" || return 1
    openssh_owner=$(listener_pid 22 2>/dev/null) || return 1
    [ "$openssh_owner" = "$candidate_pid" ] || return 1
    printf '%s\n' "$candidate_pid"
}

listener_pid() {
    listener_port=$1
    if [ "${PM3000_INSTALLER_TESTING:-0}" = 1 ]; then
        if [ "$listener_port" = 22 ]; then
            candidate_pid=$(read_pid "$OPENSSH_PIDFILE" 2>/dev/null || true)
            if valid_pid "$candidate_pid" && process_alive "$candidate_pid" && process_cmdline "$candidate_pid" | grep -F "$PM3000_ROOT" >/dev/null 2>&1; then
                printf '%s\n' "$candidate_pid"
                return 0
            fi
        fi
        for process_dir in /proc/[0-9]*; do
            candidate_pid=${process_dir#/proc/}
            valid_pid "$candidate_pid" || continue
            process_alive "$candidate_pid" || continue
            process_cmdline "$candidate_pid" | grep -F "$PM3000_ROOT" >/dev/null 2>&1 || continue
            process_has_port_argument "$candidate_pid" "$listener_port" || continue
            printf '%s\n' "$candidate_pid"
            return 0
        done
        return 1
    fi

    listener_hex=$(printf '%04X' "$listener_port") || return 1
    listener_inodes=
    for socket_table in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$socket_table" ] || continue
        table_inodes=$(awk -v port="$listener_hex" '
            NR > 1 {
                split($2, address, ":")
                if (address[2] == port && $4 == "0A" && $10 ~ /^[0-9]+$/) print $10
            }
        ' "$socket_table")
        if [ -n "$table_inodes" ]; then
            listener_inodes="$listener_inodes $table_inodes"
        fi
    done
    [ -n "$listener_inodes" ] || return 1

    unique_pid=
    for listener_inode in $listener_inodes; do
        for socket_fd in /proc/[0-9]*/fd/*; do
            [ -L "$socket_fd" ] || continue
            socket_target=$(readlink "$socket_fd" 2>/dev/null) || continue
            [ "$socket_target" = "socket:[$listener_inode]" ] || continue
            socket_pid=${socket_fd#/proc/}
            socket_pid=${socket_pid%%/*}
            valid_pid "$socket_pid" || continue
            process_alive "$socket_pid" || continue
            if [ -n "$unique_pid" ] && [ "$socket_pid" != "$unique_pid" ]; then
                return 1
            fi
            unique_pid=$socket_pid
        done
    done
    valid_pid "$unique_pid" || return 1
    printf '%s\n' "$unique_pid"
}

wait_for_managed_dropbear() {
    waited_pidfile=$1
    waited_port=$2
    waited_count=0
    while [ "$waited_count" -lt 10 ]; do
        waited_pid=$(managed_dropbear_pid "$waited_pidfile" "$waited_port" 2>/dev/null) && {
            owner_pid=$(listener_pid "$waited_port" 2>/dev/null) || owner_pid=
            [ "$owner_pid" = "$waited_pid" ] && { printf '%s\n' "$waited_pid"; return 0; }
        }
        waited_count=$((waited_count + 1))
        sleep 1
    done
    return 1
}

wait_until_stopped() {
    stopped_pid=$1
    stopped_count=0
    while [ "$stopped_count" -lt 10 ]; do
        process_alive "$stopped_pid" || return 0
        stopped_count=$((stopped_count + 1))
        sleep 1
    done
    return 1
}

stop_verified_pid() {
    stopped_pid=$1
    stopped_executable=$2
    process_is_executable "$stopped_pid" "$stopped_executable" || return 1
    kill "$stopped_pid" 2>/dev/null || return 1
    wait_until_stopped "$stopped_pid"
}

write_pid_file() {
    pid_destination=$1
    pid_to_write=$2
    pid_directory=${pid_destination%/*}
    pid_temporary=$pid_directory/.pm3000-pid.$$
    (umask 077; printf '%s\n' "$pid_to_write" >"$pid_temporary") || return 1
    chmod 0600 "$pid_temporary" || { rm -f "$pid_temporary"; return 1; }
    mv -f "$pid_temporary" "$pid_destination" || { rm -f "$pid_temporary"; return 1; }
}

start_dropbear() {
    start_port=$1
    start_pidfile=$2
    start_launch_pidfile=$3
    [ -x "$DROPBEAR_BIN" ] || return 1
    [ -x "$(root_path /bin/bash)" ] || return 1
    require_regular_nonsymlink "$HOST_KEY"
    mkdir -p "$RUN_DIR" || return 1
    chmod 0700 "$RUN_DIR" || return 1
    rm -f "$start_pidfile" "$start_launch_pidfile"
    "$DROPBEAR_BIN" -F -p "0.0.0.0:$start_port" -r "$HOST_KEY" -P "$start_pidfile" -K 30 --login-shell "$(root_path /bin/bash)" >/dev/null 2>&1 &
    launched_pid=$!
    write_pid_file "$start_launch_pidfile" "$launched_pid" || { kill "$launched_pid" 2>/dev/null || true; return 1; }
    wait_for_managed_dropbear "$start_pidfile" "$start_port" >/dev/null 2>&1
}

state_value() {
    state_key=$1
    [ -f "$STATE_FILE" ] || return 1
    sed -n "s/^$state_key=//p" "$STATE_FILE" | sed -n '1p'
}

write_state() {
    state_status=$1
    state_build_hash=$2
    state_test_port=$3
    state_test_pid=$4
    state_prod_pid=$5
    state_original_pid=$6
    state_dir=${STATE_FILE%/*}
    state_tmp=$state_dir/.installer.state.$$
    umask 077
    {
        printf 'FORMAT=1\n'
        printf 'STATUS=%s\n' "$state_status"
        printf 'BUILD_SHA256=%s\n' "$state_build_hash"
        printf 'HOST_KEY=%s\n' "$HOST_KEY"
        printf 'TEST_PORT=%s\n' "$state_test_port"
        printf 'TEST_PID=%s\n' "$state_test_pid"
        printf 'PROD_PID=%s\n' "$state_prod_pid"
        printf 'ORIGINAL_PID=%s\n' "$state_original_pid"
    } >"$state_tmp" || { rm -f "$state_tmp"; die 'cannot write installer state'; }
    chmod 0600 "$state_tmp" || { rm -f "$state_tmp"; die 'cannot protect installer state'; }
    mv -f "$state_tmp" "$STATE_FILE" || { rm -f "$state_tmp"; die 'cannot publish installer state'; }
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

start_original_openssh() {
    [ -x "$BACKUP_INIT" ] || return 1
    existing_openssh_pid=$(listener_pid 22 2>/dev/null || true)
    if valid_pid "$existing_openssh_pid" && verified_openssh_pid "$existing_openssh_pid" >/dev/null 2>&1; then
        printf '%s\n' "$existing_openssh_pid"
        return 0
    fi
    if cmp "$INIT_SCRIPT" "$BACKUP_INIT" >/dev/null 2>&1; then
        "$INIT_SCRIPT" start >/dev/null 2>&1 || return 1
    else
        ( set -- start; . "$BACKUP_INIT" ) >/dev/null 2>&1 || return 1
    fi
    openssh_wait=0
    while [ "$openssh_wait" -lt 10 ]; do
        openssh_owner=$(listener_pid 22 2>/dev/null) || openssh_owner=
        if valid_pid "$openssh_owner" && verified_openssh_pid "$openssh_owner" >/dev/null 2>&1; then
            printf '%s\n' "$openssh_owner"
            return 0
        fi
        openssh_wait=$((openssh_wait + 1))
        sleep 1
    done
    return 1
}
