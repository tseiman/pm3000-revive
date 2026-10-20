#!/bin/sh
# Stage 7 read-only PM3000 device preflight. Output is written only to stdout.
set -u
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

if [ "$#" -ne 0 ]; then
    printf '%s\n' 'usage: device-preflight.sh' >&2
    exit 2
fi

clean_value()
{
    printf '%s' "$1" | tr '\n\r\t =' '_____' | tr -cd 'A-Za-z0-9_./,:+@%()-'
}

emit()
{
    _emit_key=$1
    _emit_value=$(clean_value "$2")
    [ -n "$_emit_value" ] || _emit_value=empty
    printf '%s=%s\n' "$_emit_key" "$_emit_value"
}

capture()
{
    _capture_key=$1
    shift
    _capture_output=$("$@" 2>&1)
    _capture_status=$?
    emit "$_capture_key.status" "$_capture_status"
    emit "$_capture_key.output" "$_capture_output"
}

printf '%s\n' 'pm3000_preflight.format=1'
printf '%s\n' 'safety.mode=read-only'
printf '%s\n' 'safety.device_changes=none'
printf '%s\n' 'safety.output=stdout_only'

emit system.kernel "$(uname -s 2>&1)"
emit system.release "$(uname -r 2>&1)"
emit system.machine "$(uname -m 2>&1)"
emit identity.uid "$(id -u 2>&1)"
emit identity.gid "$(id -g 2>&1)"

if command -v busybox >/dev/null 2>&1; then
    emit busybox.path "$(command -v busybox)"
    emit busybox.version "$(busybox 2>&1 | sed -n '1p')"
else
    emit busybox.path missing
    emit busybox.version unavailable
fi

old_ifs=$IFS
IFS=:
tools='sh:tar:sha256sum:cat:wc:cut:cp:cmp:sed:id:readlink:ln:chmod:mkdir:mktemp:dirname:pwd:rm:sync:stat:df:grep:httpd:wget:curl'
for tool in $tools; do
    if command -v "$tool" >/dev/null 2>&1; then
        emit "tool.$tool" "$(command -v "$tool")"
    else
        emit "tool.$tool" missing
    fi
done
IFS=$old_ifs

for path in / /etc /etc/apache2 /etc/apache2/conf.d /var /tmp /mnt /mnt/hdUser /mnt/hdUser/pm3000-revive; do
    path_key=$(printf '%s' "$path" | sed 's,^/$,root,; s,^/,,; s,/,_,g')
    if [ -e "$path" ] || [ -L "$path" ]; then
        emit "path.$path_key.exists" yes
        if [ -L "$path" ]; then
            emit "path.$path_key.type" symlink
            emit "path.$path_key.target" "$(readlink "$path" 2>&1)"
        elif [ -d "$path" ]; then
            emit "path.$path_key.type" directory
        elif [ -f "$path" ]; then
            emit "path.$path_key.type" file
        else
            emit "path.$path_key.type" other
        fi
        if command -v stat >/dev/null 2>&1; then
            metadata=$(stat -c '%a:%u:%g:%h' "$path" 2>&1)
            emit "path.$path_key.mode_uid_gid_links" "$metadata"
        else
            emit "path.$path_key.mode_uid_gid_links" stat_missing
        fi
        if [ -d "$path" ]; then
            usage=$(df -k "$path" 2>&1 | sed -n '2p')
            emit "filesystem.$path_key.df_k" "$usage"
        fi
    else
        emit "path.$path_key.exists" no
    fi
done

if [ -r /proc/mounts ]; then
    while read -r mount_source mount_point mount_type mount_options mount_rest; do
        case "$mount_point" in
            /|/etc|/var|/tmp|/mnt|/mnt/hdUser)
                mount_key=$(printf '%s' "$mount_point" | sed 's,^/$,root,; s,^/,,; s,/,_,g')
                emit "mount.$mount_key.type" "$mount_type"
                emit "mount.$mount_key.options" "$mount_options"
                ;;
        esac
    done </proc/mounts
else
    emit mounts.status proc_mounts_unreadable
fi

apache=/usr/sbin/httpd
apache_config=/etc/apache2/httpd.conf
if [ -x "$apache" ]; then
    emit apache.binary "$apache"
    capture apache.version "$apache" -v
    capture apache.compiled_modules "$apache" -l
else
    emit apache.binary missing
fi

if [ -r "$apache_config" ]; then
    emit apache.config.readable yes
    for directive in Include LoadModule ScriptAlias Alias AcceptPathInfo SetEnvIf RequestHeader; do
        count=$(grep -i -c "^[[:space:]]*$directive[[:space:]]" "$apache_config" 2>&1)
        status=$?
        case "$status" in
            0|1) emit "apache.directive.$directive.count" "$count" ;;
            *) emit "apache.directive.$directive.count" grep_error ;;
        esac
    done
    if [ -x "$apache" ]; then
        capture apache.syntax "$apache" -t -D SSL -f "$apache_config"
    else
        emit apache.syntax.status not_run_httpd_missing
    fi
else
    emit apache.config.readable no
    emit apache.syntax.status not_run_config_unreadable
fi

config_count=0
for candidate in /etc/apache2/conf.d/*; do
    [ -e "$candidate" ] || continue
    config_count=$((config_count + 1))
done
emit apache.conf_d.entries "$config_count"

if [ -S /dev/avtrans_socket ]; then
    emit backend.avtrans_socket.type socket
elif [ -e /dev/avtrans_socket ]; then
    emit backend.avtrans_socket.type non_socket
else
    emit backend.avtrans_socket.type missing
fi
if [ -e /dev/avtrans_socket ] && command -v stat >/dev/null 2>&1; then
    emit backend.avtrans_socket.mode_uid_gid "$(stat -c '%a:%u:%g' /dev/avtrans_socket 2>&1)"
fi

printf '%s\n' 'probe.authorization_forwarding=not_tested_requires_pilot'
printf '%s\n' 'probe.cgi_path_info=not_tested_requires_pilot'
printf '%s\n' 'probe.static_ppc_helper=not_tested_requires_transfer'
printf '%s\n' 'probe.directory_fsync=not_tested_requires_write_probe'
printf '%s\n' 'probe.scp_transport=not_tested_by_device_script'
printf '%s\n' 'pm3000_preflight.complete=yes'
