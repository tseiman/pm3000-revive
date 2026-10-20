#!/bin/sh
# Fixed-purpose Stage 7 pilot primitive. Invoke only after the host BACKUP_COMPLETE gate.
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

[ "$#" -eq 4 ] || {
    echo "usage: device-install.sh RELEASE.tar PACKAGE_SHA256 RELEASE_ID BACKUP_COMPLETE" >&2
    exit 2
}
package=$1
expected=$2
release_id=$3
backup_complete=$4
[ "$(id -u)" = 0 ] || { echo "installer must run as root" >&2; exit 1; }
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac
case "$package" in /*) :;; *) echo "package path must be absolute" >&2; exit 2;; esac
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
base=/mnt/hdUser/pm3000-revive/webui
releases=$base/releases
release=$releases/$release_id
tmp=$releases/.$release_id.stage6-tmp
config_dir=/etc/apache2/conf.d
config=$config_dir/pm3000-revive.conf
work=/tmp/stage6-install-$$
for parent in /mnt /mnt/hdUser /mnt/hdUser/pm3000-revive "$base" "$releases" /etc /etc/apache2 "$config_dir"; do
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
actual=$(sha256sum "$package_snapshot" | cut -d ' ' -f 1)
[ "$actual" = "$expected" ] || { echo "package digest mismatch" >&2; rm -rf "$work"; exit 1; }
members=$work/archive-members
expected_members=$work/expected-members
tar tf "$package_snapshot" >"$members"
cat >"$expected_members" <<'EOF_MEMBERS'
RELEASE_MANIFEST.json
RELEASE_SHA256SUMS
apache/pm3000-revive.conf
bin/pm3000-atomic-publish
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

mkdir -p "$releases"
chmod 755 "$base" "$releases"
mkdir -m 700 "$tmp"
(cd "$tmp" && tar xf "$package_snapshot")
packaged_helper=$tmp/bin/pm3000-atomic-publish
[ -f "$packaged_helper" ] && [ ! -L "$packaged_helper" ] || { echo "unsafe packaged atomic helper" >&2; exit 1; }
atomic_helper=$work/pm3000-atomic-publish
cp "$packaged_helper" "$atomic_helper"
chmod 700 "$atomic_helper"
"$atomic_helper" --verify-regular "$atomic_helper" || { echo "unsafe private atomic helper" >&2; exit 1; }
for member in RELEASE_MANIFEST.json RELEASE_SHA256SUMS apache/pm3000-revive.conf \
    bin/pm3000-atomic-publish bin/pm3000-rest web/app.js web/index.html web/styles.css; do
    "$atomic_helper" --verify-regular "$tmp/$member" || {
        echo "unsafe extracted release member: $member" >&2
        exit 1
    }
done
(cd "$tmp" && sha256sum -c RELEASE_SHA256SUMS)
approved_manifest=$work/RELEASE_MANIFEST.json
approved_sums=$work/RELEASE_SHA256SUMS
cp "$tmp/RELEASE_MANIFEST.json" "$approved_manifest"
cp "$tmp/RELEASE_SHA256SUMS" "$approved_sums"
chmod 600 "$approved_manifest" "$approved_sums"
"$atomic_helper" --verify-regular "$approved_manifest" || exit 1
"$atomic_helper" --verify-regular "$approved_sums" || exit 1
chmod 755 "$tmp" "$tmp/apache" "$tmp/bin" "$tmp/web"
chmod 755 "$tmp/bin/pm3000-atomic-publish" "$tmp/bin/pm3000-rest"
chmod 600 "$tmp/RELEASE_MANIFEST.json" "$tmp/RELEASE_SHA256SUMS"
chmod 644 "$tmp/web/index.html" "$tmp/web/styles.css" "$tmp/web/app.js" "$tmp/apache/pm3000-revive.conf"
"$atomic_helper" --verify-release "$tmp" || { echo "unsafe staged release tree" >&2; exit 1; }
if [ ! -e "$release" ]; then
    if "$atomic_helper" "$releases" ".$release_id.stage6-tmp" "$release_id" directory; then
        created_release=yes
    else
        publish_status=$?
        # renameat() may have succeeded even when the helper reports a later
        # parent-fsync failure. Classify that outcome only from the exact,
        # package-bound destination; never delete an ambiguous destination.
        if [ ! -e "$tmp" ] && [ ! -L "$tmp" ] && [ -d "$release" ] && [ ! -L "$release" ] &&
            "$atomic_helper" --verify-release "$release" &&
            cmp "$approved_manifest" "$release/RELEASE_MANIFEST.json" >/dev/null 2>&1 &&
            cmp "$approved_sums" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1 &&
            (cd "$release" && sha256sum -c RELEASE_SHA256SUMS >/dev/null 2>&1); then
            created_release=yes
            committed=yes
        elif [ ! -e "$tmp" ]; then
            publish_ambiguous=yes
        fi
        exit "$publish_status"
    fi
else
    [ -d "$release" ] && [ ! -L "$release" ] || { echo "unsafe existing release" >&2; exit 1; }
    "$atomic_helper" --verify-release "$release" || { echo "unsafe existing release tree" >&2; exit 1; }
    cmp "$tmp/RELEASE_MANIFEST.json" "$release/RELEASE_MANIFEST.json" >/dev/null 2>&1 || { echo "release id collision" >&2; exit 1; }
    cmp "$tmp/RELEASE_SHA256SUMS" "$release/RELEASE_SHA256SUMS" >/dev/null 2>&1 || { echo "release checksum-list collision" >&2; exit 1; }
    (cd "$release" && sha256sum -c RELEASE_SHA256SUMS)
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
