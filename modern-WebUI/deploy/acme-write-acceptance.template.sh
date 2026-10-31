#!/bin/sh
# WRITE-CAPABLE: bootstraps ACME state and performs one real renewal.
set -eu

usage()
{
    echo "usage: ACME_WRITE_ACCEPTANCE=YES ACME_DIRECTORY_URL=https://... ACME_DNS_NAMES_FILE=... ACME_CA_PEM=... $0 SSH_TARGET RELEASE_ID" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
[ "${ACME_WRITE_ACCEPTANCE:-}" = YES ] || { echo "set ACME_WRITE_ACCEPTANCE=YES to acknowledge device writes" >&2; exit 2; }
: "${ACME_DIRECTORY_URL:?ACME_DIRECTORY_URL is required}"
: "${ACME_DNS_NAMES_FILE:?ACME_DNS_NAMES_FILE is required}"
: "${ACME_CA_PEM:?ACME_CA_PEM is required}"
target=$1
release_id=$2
case "$target" in ''|-*) echo "unsafe SSH target" >&2; exit 2;; esac
case "$release_id" in ''|*[!A-Za-z0-9._-]*|.|..) echo "unsafe release id" >&2; exit 2;; esac
[ -f "$ACME_DNS_NAMES_FILE" ] && [ ! -L "$ACME_DNS_NAMES_FILE" ] || { echo "DNS names file must be a regular non-symlink file" >&2; exit 2; }
[ -f "$ACME_CA_PEM" ] && [ ! -L "$ACME_CA_PEM" ] || { echo "CA PEM must be a regular non-symlink file" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 missing" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl missing" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/pm3000-acme-acceptance.XXXXXX")
remote_config=/tmp/pm3000-acme-acceptance-config.json
remote_ca=/tmp/pm3000-acme-acceptance-ca.pem
remote_cert=/mnt/hdUser/pm3000-revive/acme/certificate.pem
remote_cleanup_needed=yes
cleanup()
{
    status=$?
    trap - 0 1 2 15
    if [ "$remote_cleanup_needed" = yes ]; then
        ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no "$target" \
            "rm -f '$remote_config' '$remote_ca'; test ! -e '$remote_config' -a ! -L '$remote_config' -a ! -e '$remote_ca' -a ! -L '$remote_ca'" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

ACME_CONFIG_OUT=$work/config.json ACME_DNS_OUT=$work/dns-normalized.txt \
python3 - "$ACME_DIRECTORY_URL" "$ACME_DNS_NAMES_FILE" "$ACME_CA_PEM" <<'PY'
import json, os, pathlib, re, sys
url, names_path, ca_path = sys.argv[1:]
if not re.fullmatch(r"https://[^\x00-\x20\x7f]+", url) or len(url.encode()) > 1291:
    raise SystemExit("invalid ACME HTTPS directory URL")
raw = pathlib.Path(names_path).read_text(encoding="ascii").splitlines()
names = [line.strip().lower() for line in raw if line.strip()]
pattern = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
if not 1 <= len(names) <= 16 or len(set(names)) != len(names) or any(len(n.encode()) > 253 or not pattern.fullmatch(n) for n in names):
    raise SystemExit("invalid or duplicate DNS names")
ca = pathlib.Path(ca_path).read_bytes()
if not 0 < len(ca) <= 65536 or b"-----BEGIN CERTIFICATE-----" not in ca or b"PRIVATE KEY" in ca:
    raise SystemExit("CA PEM must be a non-empty certificate bundle without private keys (max 64 KiB)")
config = {"enabled": True, "directory_url": url,
          "ca_file": "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem",
          "dns_names": names}
pathlib.Path(os.environ["ACME_CONFIG_OUT"]).write_text(json.dumps(config, separators=(",", ":")) + "\n", encoding="ascii")
pathlib.Path(os.environ["ACME_DNS_OUT"]).write_text("\n".join(names) + "\n", encoding="ascii")
PY
openssl crl2pkcs7 -nocrl -certfile "$ACME_CA_PEM" | openssl pkcs7 -print_certs -noout >/dev/null

# Classic SCP is required by the appliance's old SSH server.
scp -O "$work/config.json" "$target:$remote_config"
scp -O "$ACME_CA_PEM" "$target:$remote_ca"

ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no "$target" sh -s "$release_id" <<'REMOTE'
set -eu
release_id=$1
release=/mnt/hdUser/pm3000-revive/webui/releases/$release_id
acme=$release/bin/pm3000-acme
state=/mnt/hdUser/pm3000-revive/acme
challenge=/mnt/hdUser/pm3000-revive/acme-http-01
config=/tmp/pm3000-acme-acceptance-config.json
ca=/tmp/pm3000-acme-acceptance-ca.pem
cleanup()
{
    status=$?
    trap - 0 1 2 15
    rm -f "$config" "$ca"
    if [ -e "$config" ] || [ -L "$config" ] || [ -e "$ca" ] || [ -L "$ca" ]; then
        echo 'acme_write_acceptance.temporary_cleanup=failed' >&2
        exit 1
    fi
    echo 'acme_write_acceptance.temporary_cleanup=complete'
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

[ -x "$acme" ] || { echo "installed ACME CLI missing" >&2; exit 1; }
actual=$(openssl dgst -sha256 "$acme") || { echo "installed ACME CLI hash unavailable" >&2; exit 1; }
actual=${actual##*= }
[ "$actual" = 0aa205b837fa357cf3d7d0eb8a67c3df10fd929d9a8dc5c3a41c0383416832c0 ] || { echo "installed ACME CLI hash mismatch" >&2; exit 1; }
[ -f "$config" ] && [ ! -L "$config" ] && [ -f "$ca" ] && [ ! -L "$ca" ] || { echo "acceptance input staging is unsafe" >&2; exit 1; }
if "$acme" config show >/dev/null 2>&1; then
    echo "ACME config already exists; bootstrap acceptance refuses to overwrite it" >&2
    exit 1
fi
[ "$(LD_BIND_NOW=1 "$acme" status)" = '{"state":"never_run"}' ] || { echo "pre-bootstrap status is not never_run" >&2; exit 1; }
"$acme" config replace --stdin <"$config"
"$acme" ca install --stdin <"$ca"
"$acme" config show >/dev/null
"$acme" renew --foreground
[ "$("$acme" status)" = '{"state":"succeeded"}' ] || { echo "renewal did not succeed" >&2; exit 1; }
[ -f "$state/certificate.pem" ] && [ ! -L "$state/certificate.pem" ] || { echo "certificate missing or unsafe" >&2; exit 1; }
set -- $(ls -ldn "$state" "$state/config.json" "$state/status.json" "$state/certificate.pem" "$state/account-key.pem" "$state/certificate-key.pem" "$state/trust" "$state/trust/managed-ca.pem")
# The production CLI validates the private tree and exact certificate SAN set before publication.
"$release/bin/pm3000-atomic-publish" --verify-private-tree "$state"
entries=$(ls -a "$challenge" | grep -v '^\.$' | grep -v '^\.\.$' || true)
[ -z "$entries" ] || { echo "HTTP-01 challenge files remain" >&2; exit 1; }
echo 'acme_write_acceptance.renewal=succeeded'
echo 'acme_write_acceptance.http01_cleanup=complete'
echo 'acme_write_acceptance.private_tree=verified'
REMOTE
remote_cleanup_needed=no

scp -O "$target:$remote_cert" "$work/certificate.pem"
openssl x509 -in "$work/certificate.pem" -noout -checkend 0 >/dev/null
openssl x509 -in "$work/certificate.pem" -noout -ext subjectAltName >"$work/sans.txt"
python3 - "$work/dns-normalized.txt" "$work/sans.txt" <<'PY'
import pathlib, re, sys
expected = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
actual = re.findall(r"DNS:([^,\s]+)", text)
if sorted(actual) != sorted(expected) or len(actual) != len(expected):
    raise SystemExit(f"certificate SAN mismatch: expected {expected!r}, got {actual!r}")
print("acme_write_acceptance.sans=verified")
PY
echo 'acme_write_acceptance.complete=yes'
