#!/bin/sh
# Fixed-purpose Stage 7 pilot primitive. Invoke only after the host BACKUP_COMPLETE gate.
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

sha256_file()
{
    _sha_output=$(openssl dgst -sha256 "$1") || return 1
    _sha_digest=${_sha_output##*= }
    case "$_sha_digest" in *[!0-9a-f]*|'') return 1;; esac
    [ "${#_sha_digest}" -eq 64 ] || return 1
    printf '%s\n' "$_sha_digest"
}

verify_release_sums()
{
    _sum_root=$1
    _sum_list=$2
    _sum_count=0
    while IFS= read -r _sum_line; do
        _sum_expected=${_sum_line%%  *}
        _sum_path=${_sum_line#*  }
        [ "$_sum_line" = "$_sum_expected  $_sum_path" ] || return 1
        case "$_sum_expected" in *[!0-9a-f]*|'') return 1;; esac
        [ "${#_sum_expected}" -eq 64 ] || return 1
        case "$_sum_path" in
            apache/pm3000-revive.conf|bin/pm3000-atomic-publish|bin/pm3000-gsp-session-helper|bin/pm3000-rest|web/app.js|web/index.html|web/styles.css) :;;
            *) return 1;;
        esac
        [ -f "$_sum_root/$_sum_path" ] && [ ! -L "$_sum_root/$_sum_path" ] || return 1
        _sum_actual=$(sha256_file "$_sum_root/$_sum_path") || return 1
        [ "$_sum_actual" = "$_sum_expected" ] || return 1
        _sum_count=$((_sum_count + 1))
    done <"$_sum_list"
    [ "$_sum_count" -eq 7 ]
}

# BEGIN DISK PREFLIGHT TEST FUNCTIONS
check_release_capacity()
{
    _capacity_archive=$1
    _capacity_filesystem=$2
    _capacity_scratch=$3
    _capacity_wc_output=$_capacity_scratch/archive-size
    _capacity_df_output=$_capacity_scratch/filesystem-capacity

    if wc -c <"$_capacity_archive" >"$_capacity_wc_output"; then
        :
    else
        echo "release archive size unavailable" >&2
        return 1
    fi
    _capacity_wc_line=$(tail -n 1 "$_capacity_wc_output") || {
        echo "release archive size unavailable" >&2
        return 1
    }
    package_bytes=
    _capacity_wc_extra=
    read -r package_bytes _capacity_wc_extra <<EOF_WC_SIZE
$_capacity_wc_line
EOF_WC_SIZE
    case "$package_bytes" in
        ''|*[!0-9]*|??????????*)
            echo "invalid release archive size" >&2
            return 1
            ;;
    esac
    [ -z "$_capacity_wc_extra" ] || {
        echo "invalid release archive size" >&2
        return 1
    }
    package_kib=$((package_bytes / 1024))
    if [ $((package_bytes % 1024)) -ne 0 ]; then
        package_kib=$((package_kib + 1))
    fi
    required_kib=$((package_kib + 256))

    if df -k "$_capacity_filesystem" >"$_capacity_df_output"; then
        :
    else
        echo "release filesystem capacity unavailable" >&2
        return 1
    fi
    _capacity_df_line=$(tail -n 1 "$_capacity_df_output") || {
        echo "release filesystem capacity unavailable" >&2
        return 1
    }
    _capacity_df_filesystem=
    _capacity_df_blocks=
    _capacity_df_used=
    available_kib=
    _capacity_df_percent=
    _capacity_df_mount=
    _capacity_df_extra=
    read -r _capacity_df_filesystem _capacity_df_blocks _capacity_df_used \
        available_kib _capacity_df_percent _capacity_df_mount _capacity_df_extra <<EOF_DF_LINE
$_capacity_df_line
EOF_DF_LINE
    case "$_capacity_df_blocks:$_capacity_df_used:$available_kib" in
        *[!0-9:]*|:*|*::*|*:) echo "invalid release filesystem capacity" >&2; return 1;;
    esac
    case "$available_kib" in ??????????*) echo "invalid release filesystem capacity" >&2; return 1;; esac
    [ -n "$_capacity_df_filesystem" ] && [ -n "$_capacity_df_percent" ] &&
        [ -n "$_capacity_df_mount" ] && [ -z "$_capacity_df_extra" ] || {
        echo "invalid release filesystem capacity" >&2
        return 1
    }
    [ "$available_kib" -ge "$required_kib" ] || {
        echo "insufficient release filesystem space: required_kib=$required_kib available_kib=$available_kib" >&2
        return 1
    }
}

extract_release_archive()
{
    _extract_archive=$1
    _extract_root=$2
    if ! (cd "$_extract_root" && tar xf "$_extract_archive"); then
        echo "release archive extraction failed" >&2
        return 1
    fi
    for extracted_member in RELEASE_MANIFEST.json RELEASE_SHA256SUMS apache/pm3000-revive.conf \
        bin/pm3000-atomic-publish bin/pm3000-rest bin/pm3000-gsp-session-helper \
        web/app.js web/index.html web/styles.css; do
        [ -f "$_extract_root/$extracted_member" ] && [ ! -L "$_extract_root/$extracted_member" ] || {
            echo "release archive extraction incomplete: $extracted_member" >&2
            return 1
        }
    done
}
# END DISK PREFLIGHT TEST FUNCTIONS

[ "$#" -eq 4 ] || {
    echo "usage: device-install.sh RELEASE.tar PACKAGE_SHA256 RELEASE_ID BACKUP_COMPLETE" >&2
    exit 2
}
package=$1
expected=$2
release_id=$3
backup_complete=$4
[ "$(id -u)" = 0 ] || { echo "installer must run as root" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl missing" >&2; exit 1; }
for required_command in df tail tar wc; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "$required_command missing" >&2
        exit 1
    }
done
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac
[ -f "$package" ] && [ ! -L "$package" ] || { echo "unsafe package" >&2; exit 1; }
[ -f "$backup_complete" ] && [ ! -L "$backup_complete" ] || { echo "BACKUP_COMPLETE missing or unsafe" >&2; exit 1; }
{
    IFS= read -r backup_archive_hash
    IFS= read -r backup_manifest_hash
    if IFS= read -r extra; then exit 1; fi
} <"$backup_complete" || { echo "invalid BACKUP_COMPLETE" >&2; exit 1; }
for digest in "$backup_archive_hash" "$backup_manifest_hash" "$expected"; do
    case "$digest" in *[!0-9a-f]*|'') echo "invalid digest" >&2; exit 1;; esac
    [ "${#digest}" -eq 64 ] || { echo "invalid digest length" >&2; exit 1; }
done
root=/mnt/hdUser/pm3000-revive
base=$root/webui
releases=$base/releases
release=$releases/$release_id
tmp=$releases/.$release_id.stage6-tmp
config_dir=/etc/apache2/conf.d
config=$config_dir/pm3000-revive.conf
work=/tmp/stage6-install-$$
for parent in /mnt /mnt/hdUser "$root" "$base" "$releases" /etc /etc/apache2 "$config_dir"; do
    [ ! -L "$parent" ] || { echo "unsafe parent symlink: $parent" >&2; exit 1; }
done
[ ! -e "$tmp" ] && [ ! -L "$tmp" ] || { echo "transaction temporary exists" >&2; exit 1; }
[ ! -L "$config" ] || { echo "unsafe Apache config symlink" >&2; exit 1; }
if [ -e "$base/current" ] && [ ! -L "$base/current" ]; then
    echo "unsafe non-symlink current pointer" >&2
    exit 1
fi
if [ -L "$release" ]; then echo "unsafe release symlink" >&2; exit 1; fi
mkdir -m 700 "$work"
package_snapshot=$work/release.tar
cp "$package" "$package_snapshot"
chmod 600 "$package_snapshot"
actual=$(sha256_file "$package_snapshot")
[ "$actual" = "$expected" ] || { echo "package digest mismatch" >&2; rm -rf "$work"; exit 1; }
members=$work/archive-members
expected_members=$work/expected-members
tar tf "$package_snapshot" >"$members"
cat >"$expected_members" <<'EOF_MEMBERS'
RELEASE_MANIFEST.json
RELEASE_SHA256SUMS
apache/pm3000-revive.conf
bin/pm3000-atomic-publish
bin/pm3000-gsp-session-helper
bin/pm3000-rest
web/app.js
web/index.html
web/styles.css
EOF_MEMBERS
cmp "$members" "$expected_members" >/dev/null 2>&1 || { echo "release archive allowlist mismatch" >&2; rm -rf "$work"; exit 1; }

old_current=absent
if [ -L "$base/current" ]; then
    old_current=$(readlink "$base/current")
    old_release_id=${old_current#releases/}
    case "$old_current:$old_release_id" in
        releases/*:*/*|releases/*:*[!A-Za-z0-9._-]*|releases/*:.|releases/*:..) echo "unsafe current target" >&2; rm -rf "$work"; exit 1;;
        releases/*:*) :;;
        *) echo "unsafe current target" >&2; rm -rf "$work"; exit 1;;
    esac
fi
old_config=absent
if [ -f "$config" ]; then cp -p "$config" "$work/old-config"; old_config=file; fi
created_release=no
committed=no
publish_ambiguous=no
rollback_failed_install()
{
    [ "$committed" = yes ] || return 0
    if [ "$old_config" = file ]; then
        cp -p "$work/old-config" "$config_dir/.pm3000-revive.conf.stage6-tmp"
        "$atomic_helper" "$config_dir" .pm3000-revive.conf.stage6-tmp pm3000-revive.conf regular || return 1
    else
        rm -f "$config"
    fi
    if [ "$old_current" = absent ]; then
        rm -f "$base/current"
    else
        rm -f "$base/.current.stage6-tmp"
        ln -s "$old_current" "$base/.current.stage6-tmp"
        "$atomic_helper" "$base" .current.stage6-tmp current symlink || return 1
    fi
    if [ "$created_release" = yes ] && [ -d "$release" ] && [ ! -L "$release" ]; then rm -rf "$release"; fi
    /usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf >/dev/null 2>&1 &&
        /etc/init.d/apache2 reload >/dev/null 2>&1 || return 1
}
cleanup()
{
    status=$?
    trap - 0 1 2 15
    if [ "$status" -ne 0 ]; then
        if ! rollback_failed_install || [ "$publish_ambiguous" = yes ]; then
            echo "automatic rollback incomplete; retain the management session and inspect $release" >&2
        fi
    fi
    rm -rf "$work"
    if [ -d "$tmp" ] && [ ! -L "$tmp" ]; then rm -rf "$tmp"; fi
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

check_release_capacity "$package_snapshot" /mnt/hdUser "$work"
mkdir -p "$releases"
chmod 755 "$root" "$base" "$releases"
mkdir -m 700 "$tmp"
extract_release_archive "$package_snapshot" "$tmp"
packaged_helper=$tmp/bin/pm3000-atomic-publish
[ -f "$packaged_helper" ] && [ ! -L "$packaged_helper" ] || { echo "unsafe packaged atomic helper" >&2; exit 1; }
atomic_helper=$work/pm3000-atomic-publish
cp "$packaged_helper" "$atomic_helper"
chmod 700 "$atomic_helper"
"$atomic_helper" --verify-regular "$atomic_helper" || { echo "unsafe private atomic helper" >&2; exit 1; }
daemon_uid=$(id -u daemon)
case "$daemon_uid" in ''|*[!0-9]*) echo "invalid Apache daemon account" >&2; exit 1;; esac
daemon_gid=$(id -g daemon)
case "$daemon_gid" in ''|*[!0-9]*) echo "invalid Apache daemon group" >&2; exit 1;; esac
verify_private_directory()
{
    "$atomic_helper" --verify-private-directory "$1" 2>/dev/null ||
        "$atomic_helper" --verify-private-directory-owner "$1" "$daemon_uid"
}
verify_private_regular()
{
    "$atomic_helper" --verify-private-regular "$1" 2>/dev/null ||
        "$atomic_helper" --verify-private-regular-owner "$1" "$daemon_uid"
}
initialize_private_directory()
{
    _private_directory=$1
    [ ! -L "$_private_directory" ] || return 1
    if [ ! -e "$_private_directory" ]; then
        mkdir -m 700 "$_private_directory" || return 1
    fi
    verify_private_directory "$_private_directory"
}
initialize_private_regular()
{
    _private_path=$1
    [ ! -L "$_private_path" ] || return 1
    if [ ! -e "$_private_path" ]; then
        if [ "$#" -eq 2 ]; then
            (umask 077; set -C; printf '%s\n' "$2" >"$_private_path") || return 1
        else
            (umask 077; set -C; : >"$_private_path") || return 1
        fi
    fi
    verify_private_regular "$_private_path"
}
initialize_private_directory "$root/rest" || { echo "unsafe REST private directory" >&2; exit 1; }
initialize_private_regular "$root/rest/tokens.json" '{"generation":1,"schemaVersion":1,"tokens":[]}' || {
    echo "unsafe token store" >&2; exit 1;
}
initialize_private_regular "$root/rest/tokens.json.lock" || {
    echo "unsafe token-store lock" >&2; exit 1;
}
for private_file in "$root/rest/tokens.json" "$root/rest/tokens.json.lock"; do
    "$atomic_helper" --set-private-regular-owner "$private_file" "$daemon_uid" "$daemon_gid"
done
for private_directory in "$root/rest"; do
    "$atomic_helper" --set-private-directory-owner "$private_directory" "$daemon_uid" "$daemon_gid"
done
"$atomic_helper" --verify-private-directory-owner "$root/rest" "$daemon_uid"
for prerequisite in "$root/rest/tokens.json" "$root/rest/tokens.json.lock"; do
    "$atomic_helper" --verify-private-regular-owner "$prerequisite" "$daemon_uid"
done
for member in RELEASE_MANIFEST.json RELEASE_SHA256SUMS apache/pm3000-revive.conf \
    bin/pm3000-atomic-publish bin/pm3000-rest bin/pm3000-gsp-session-helper \
    web/app.js web/index.html web/styles.css; do
    "$atomic_helper" --verify-regular "$tmp/$member" || {
        echo "unsafe extracted release member: $member" >&2
        exit 1
    }
done
verify_release_sums "$tmp" "$tmp/RELEASE_SHA256SUMS"
approved_manifest=$work/RELEASE_MANIFEST.json
approved_sums=$work/RELEASE_SHA256SUMS
cp "$tmp/RELEASE_MANIFEST.json" "$approved_manifest"
cp "$tmp/RELEASE_SHA256SUMS" "$approved_sums"
chmod 600 "$approved_manifest" "$approved_sums"
"$atomic_helper" --verify-regular "$approved_manifest" || exit 1
"$atomic_helper" --verify-regular "$approved_sums" || exit 1
chmod 755 "$tmp" "$tmp/apache" "$tmp/bin" "$tmp/web"
chmod 755 "$tmp/bin/pm3000-atomic-publish" "$tmp/bin/pm3000-rest"
chown 0:"$daemon_gid" "$tmp/bin/pm3000-gsp-session-helper"
chmod 4750 "$tmp/bin/pm3000-gsp-session-helper"
chmod 600 "$tmp/RELEASE_MANIFEST.json" "$tmp/RELEASE_SHA256SUMS"
chmod 644 "$tmp/web/index.html" "$tmp/web/styles.css" "$tmp/web/app.js" "$tmp/apache/pm3000-revive.conf"
"$atomic_helper" --verify-release "$tmp" "$daemon_gid" || { echo "unsafe staged release tree" >&2; exit 1; }
if [ ! -e "$release" ]; then
    if "$atomic_helper" "$releases" ".$release_id.stage6-tmp" "$release_id" directory; then
        created_release=yes
    else
        publish_status=$?
        # renameat() may have succeeded even when the helper reports a later
        # parent-fsync failure. Classify that outcome only from the exact,
        # package-bound destination; never delete an ambiguous destination.
        if [ ! -e "$tmp" ] && [ ! -L "$tmp" ] && [ -d "$release" ] && [ ! -L "$release" ] &&
            "$atomic_helper" --verify-release "$release" "$daemon_gid" &&
            cmp "$approved_manifest" "$release/RELEASE_MANIFEST.json" >/dev/null 2>&1 &&
            cmp "$approved_sums" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1 &&
            verify_release_sums "$release" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1; then
            created_release=yes
            committed=yes
        elif [ ! -e "$tmp" ]; then
            publish_ambiguous=yes
        fi
        exit "$publish_status"
    fi
else
    [ -d "$release" ] && [ ! -L "$release" ] || { echo "unsafe existing release" >&2; exit 1; }
    "$atomic_helper" --verify-release "$release" "$daemon_gid" || { echo "unsafe existing release tree" >&2; exit 1; }
    cmp "$tmp/RELEASE_MANIFEST.json" "$release/RELEASE_MANIFEST.json" >/dev/null 2>&1 || { echo "release id collision" >&2; exit 1; }
    cmp "$tmp/RELEASE_SHA256SUMS" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1 || { echo "release checksum-list collision" >&2; exit 1; }
    verify_release_sums "$release" "$release/RELEASE_SHA256SUMS"
    rm -rf "$tmp"
fi
committed=yes
ln -s "releases/$release_id" "$base/.current.stage6-tmp"
"$atomic_helper" "$base" .current.stage6-tmp current symlink
cp "$release/apache/pm3000-revive.conf" "$config_dir/.pm3000-revive.conf.stage6-tmp"
chmod 644 "$config_dir/.pm3000-revive.conf.stage6-tmp"
"$atomic_helper" "$config_dir" .pm3000-revive.conf.stage6-tmp pm3000-revive.conf regular
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
/etc/init.d/apache2 reload
committed=no
