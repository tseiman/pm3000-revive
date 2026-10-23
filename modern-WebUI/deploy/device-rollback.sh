#!/bin/sh
# Fixed-purpose Stage 7 rollback primitive for host-verified, pre-staged state.
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

[ "$#" -eq 4 ] || {
    echo "usage: device-rollback.sh RESTORE_DIR RELEASE_ID RELEASE.tar PACKAGE_SHA256" >&2
    exit 2
}
restore_dir=$1
release_id=$2
package=$3
expected=$4
[ "$(id -u)" = 0 ] || { echo "rollback must run as root" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl missing" >&2; exit 1; }
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac
case "$restore_dir" in /tmp/stage6-restore-*) :;; *) echo "unsafe restore directory" >&2; exit 2;; esac
case "$expected" in *[!0-9a-f]*|'') echo "invalid package digest" >&2; exit 2;; esac
[ "${#expected}" -eq 64 ] || { echo "invalid package digest length" >&2; exit 2; }
[ -d "$restore_dir" ] && [ ! -L "$restore_dir" ] || { echo "restore directory missing or unsafe" >&2; exit 1; }
[ -f "$package" ] && [ ! -L "$package" ] || { echo "unsafe package" >&2; exit 1; }

base=/mnt/hdUser/pm3000-revive/webui
release=$base/releases/$release_id
config_dir=/etc/apache2/conf.d
config=$config_dir/pm3000-revive.conf
work=/tmp/stage6-rollback-$$
for parent in /mnt /mnt/hdUser /mnt/hdUser/pm3000-revive "$base" "$base/releases" /etc /etc/apache2 "$config_dir"; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || { echo "unsafe rollback parent: $parent" >&2; exit 1; }
done
mkdir -m 700 "$work"
cleanup()
{
    status=$?
    trap - 0 1 2 15
    rm -rf "$work"
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

package_snapshot=$work/release.tar
cp "$package" "$package_snapshot"
chmod 600 "$package_snapshot"
actual=$(sha256_file "$package_snapshot")
[ "$actual" = "$expected" ] || { echo "package digest mismatch" >&2; exit 1; }
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
cmp "$members" "$expected_members" >/dev/null 2>&1 || { echo "release archive allowlist mismatch" >&2; exit 1; }
package_tree=$work/package
mkdir -m 700 "$package_tree"
(cd "$package_tree" && tar xf "$package_snapshot")
packaged_helper=$package_tree/bin/pm3000-atomic-publish
[ -f "$packaged_helper" ] && [ ! -L "$packaged_helper" ] || { echo "unsafe packaged atomic helper" >&2; exit 1; }
atomic_helper=$work/pm3000-atomic-publish
cp "$packaged_helper" "$atomic_helper"
chmod 700 "$atomic_helper"
"$atomic_helper" --verify-regular "$atomic_helper" || { echo "unsafe private atomic helper" >&2; exit 1; }
for member in RELEASE_MANIFEST.json RELEASE_SHA256SUMS apache/pm3000-revive.conf \
    bin/pm3000-atomic-publish bin/pm3000-gsp-session-helper bin/pm3000-rest \
    web/app.js web/index.html web/styles.css; do
    "$atomic_helper" --verify-regular "$package_tree/$member" || {
        echo "unsafe packaged release member: $member" >&2
        exit 1
    }
done
verify_release_sums "$package_tree" "$package_tree/RELEASE_SHA256SUMS"
daemon_gid=$(id -g daemon)
case "$daemon_gid" in ''|*[!0-9]*) echo "invalid Apache daemon group" >&2; exit 1;; esac

"$atomic_helper" --verify-release "$release" "$daemon_gid" || { echo "unsafe active release tree" >&2; exit 1; }
cmp "$package_tree/RELEASE_MANIFEST.json" "$release/RELEASE_MANIFEST.json" >/dev/null 2>&1 || { echo "active release manifest mismatch" >&2; exit 1; }
cmp "$package_tree/RELEASE_SHA256SUMS" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1 || { echo "active release checksum list mismatch" >&2; exit 1; }
verify_release_sums "$release" "$release/RELEASE_SHA256SUMS"

"$atomic_helper" --verify-private-directory "$restore_dir" || { echo "unsafe restore directory ownership or mode" >&2; exit 1; }
[ -f "$restore_dir/config.state" ] && [ ! -L "$restore_dir/config.state" ] || { echo "config state missing" >&2; exit 1; }
[ -f "$restore_dir/current.state" ] && [ ! -L "$restore_dir/current.state" ] || { echo "current state missing" >&2; exit 1; }
"$atomic_helper" --verify-regular "$restore_dir/config.state" || exit 1
"$atomic_helper" --verify-regular "$restore_dir/current.state" || exit 1
[ "$(wc -l <"$restore_dir/config.state")" -eq 1 ] || { echo "invalid config state" >&2; exit 1; }
[ "$(wc -l <"$restore_dir/current.state")" -eq 1 ] || { echo "invalid current state" >&2; exit 1; }
config_state=$(sed -n '1p' "$restore_dir/config.state")
current_state=$(sed -n '1p' "$restore_dir/current.state")
case "$config_state" in
    absent) : ;;
    file)
        [ -f "$restore_dir/pm3000-revive.conf" ] && [ ! -L "$restore_dir/pm3000-revive.conf" ] || {
            echo "restored config missing or unsafe" >&2; exit 1
        }
        "$atomic_helper" --verify-regular "$restore_dir/pm3000-revive.conf" || exit 1
        cp "$restore_dir/pm3000-revive.conf" "$config_dir/.pm3000-revive.conf.stage6-tmp"
        chmod 644 "$config_dir/.pm3000-revive.conf.stage6-tmp"
        ;;
    *) echo "unsafe config state" >&2; exit 1 ;;
esac
case "$current_state" in
    absent) : ;;
    releases/*)
        old_release_id=${current_state#releases/}
        case "$old_release_id" in ''|*/*|*[!A-Za-z0-9._-]*|.|..) echo "unsafe current state" >&2; exit 1;; esac
        ln -s "$current_state" "$base/.current.stage6-tmp"
        ;;
    *) echo "unsafe current state" >&2; exit 1 ;;
esac
# The host must already have verified that live managed paths equal the selected
# transaction post-state. Publish only the pre-staged fixed destinations here.
if [ "$config_state" = file ]; then
    "$atomic_helper" "$config_dir" .pm3000-revive.conf.stage6-tmp pm3000-revive.conf regular
else
    rm -f "$config"
fi
if [ "$current_state" = absent ]; then
    rm -f "$base/current"
else
    "$atomic_helper" "$base" .current.stage6-tmp current symlink
fi
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
/etc/init.d/apache2 reload
# Release deletion is intentionally host-mediated after hash/drift verification.
