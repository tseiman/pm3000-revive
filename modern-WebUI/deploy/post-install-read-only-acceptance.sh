#!/bin/sh
set -eu

usage()
{
    echo "usage: $0 SSH_TARGET RELEASE_ID HTTPS_BASE_URL COOKIE_JAR" >&2
    exit 2
}

[ "$#" -eq 4 ] || usage
target=$1
release_id=$2
base_url=${3%/}
cookie_jar=$4
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac
case "$base_url" in https://*) :;; *) echo "HTTPS base URL required" >&2; exit 2;; esac
[ -f "$cookie_jar" ] && [ ! -L "$cookie_jar" ] || { echo "cookie jar missing or unsafe" >&2; exit 1; }
for command_name in ssh curl python3 mktemp; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name missing" >&2; exit 1; }
done

local_tmp=$(mktemp "${TMPDIR:-/tmp}/pm3000-post-install.XXXXXX")
chmod 600 "$local_tmp"
cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    rm -f "$local_tmp"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

# Device phase is read-only and creates no remote temporary object.
ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no "$target" sh -s "$release_id" <<'REMOTE'
set -eu
release_id=$1
base=/mnt/hdUser/pm3000-revive/webui
release=$base/releases/$release_id
temporary=/tmp/pm3000-acme-post-install-acceptance

[ ! -e "$temporary" ] && [ ! -L "$temporary" ] || {
    echo "acceptance temporary path unexpectedly exists: $temporary" >&2
    exit 1
}
[ -L "$base/current" ] || { echo "active release pointer is not a symlink" >&2; exit 1; }
active=$(readlink "$base/current")
[ "$active" = "releases/$release_id" ] || {
    echo "active release mismatch: $active" >&2
    exit 1
}
[ -d "$release" ] && [ ! -L "$release" ] || { echo "active release directory is unsafe" >&2; exit 1; }

daemon_gid=$(id -g daemon)
"$release/bin/pm3000-atomic-publish" --verify-release "$release" "$daemon_gid"
for helper in pm3000-acme-admin pm3000-gsp-session-helper; do
    set -- $(ls -ldn "$release/bin/$helper")
    [ "$1" = "-rwsr-x---" ] || { echo "helper mode mismatch: $helper $1" >&2; exit 1; }
    [ "$3" = 0 ] || { echo "helper owner mismatch: $helper $3" >&2; exit 1; }
    [ "$4" = "$daemon_gid" ] || { echo "helper group mismatch: $helper $4" >&2; exit 1; }
    printf 'helper=%s mode=4750 owner=0 group=%s\n' "$helper" "$daemon_gid"
done

set +e
LD_BIND_NOW=1 "$release/bin/pm3000-acme" status >/dev/null
status_code=$?
set -e
[ "$status_code" -eq 0 ] || { echo "pm3000-acme status exit=$status_code" >&2; exit 1; }
[ ! -e "$temporary" ] && [ ! -L "$temporary" ] || {
    echo "acceptance temporary cleanup failed: $temporary" >&2
    exit 1
}
printf 'active_release=%s\npm3000_acme_status_exit=0\n' "$release_id"
echo 'remote_temporary_cleanup=complete'
REMOTE

# HTTPS phase proves the authenticated WebUI route projects a closed safe state.
http_status=$(curl --silent --show-error --cookie "$cookie_jar" \
    --output "$local_tmp" --write-out '%{http_code}' \
    "$base_url/api/v1/settings/acme")
[ "$http_status" = 200 ] || { echo "ACME settings HTTP status=$http_status" >&2; exit 1; }
projection=$(python3 - "$local_tmp" <<'PY'
import json
from pathlib import Path
import re
import sys
try:
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, ValueError) as exc:
    raise SystemExit(f"invalid ACME settings response: {exc}")
if not isinstance(value, dict):
    raise SystemExit("invalid ACME settings response type")

if set(value) == {"configured", "caInstalled", "renewal"}:
    if value["configured"] is not False or not isinstance(value["caInstalled"], bool):
        raise SystemExit("invalid ACME unconfigured projection")
    if value["renewal"] != {"state": "never_run"}:
        raise SystemExit("invalid ACME unconfigured renewal state")
    print("unconfigured")
    raise SystemExit(0)

if set(value) != {"enabled", "directoryUrl", "caFile", "dnsNames", "revision", "renewal"}:
    raise SystemExit("invalid ACME configured projection fields")
if not isinstance(value["enabled"], bool):
    raise SystemExit("invalid ACME enabled field")
directory = value["directoryUrl"]
if (not isinstance(directory, str) or len(directory.encode("utf-8")) > 1291 or
        re.fullmatch(r"https://[^\x00-\x20\x7f]+", directory) is None):
    raise SystemExit("invalid ACME directory URL")
if value["caFile"] != "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem":
    raise SystemExit("invalid ACME managed CA path")
dns_names = value["dnsNames"]
dns_pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
if (not isinstance(dns_names, list) or not 1 <= len(dns_names) <= 16 or
        any(not isinstance(name, str) or len(name.encode("utf-8")) > 253 or
            dns_pattern.fullmatch(name) is None for name in dns_names) or
        len(set(dns_names)) != len(dns_names)):
    raise SystemExit("invalid ACME DNS names")
revision = value["revision"]
if not isinstance(revision, str) or re.fullmatch(r'"[0-9a-f]{64}"', revision) is None:
    raise SystemExit("invalid ACME strong revision")
renewal = value["renewal"]
states = {"never_run", "starting", "running", "succeeded", "failed", "durability_uncertain", "unknown"}
phases = {"directory", "nonce", "account", "order", "authorization", "challenge_publication", "challenge_acceptance", "challenge_poll", "finalize", "certificate_download", "certificate_validation", "certificate_publication"}
reasons = {"tls", "http", "parse", "io", "rejected", "timeout", "validation", "publication"}
if not isinstance(renewal, dict) or renewal.get("state") not in states:
    raise SystemExit("invalid ACME renewal state")
if set(renewal) == {"state"}:
    pass
elif (set(renewal) == {"state", "phase", "reason"} and renewal["state"] == "failed" and
      renewal["phase"] in phases and renewal["reason"] in reasons):
    pass
else:
    raise SystemExit("invalid ACME renewal diagnostics")
print("configured")
PY
)
rm -f "$local_tmp"
printf 'acme_http_status=200\nacme_http_projection=%s\n%s\n%s\n' \
    "$projection" \
    'local_temporary_cleanup=complete' \
    'post_install_read_only_acceptance.complete=yes'
