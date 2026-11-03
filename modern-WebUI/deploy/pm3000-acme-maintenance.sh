#!/bin/sh
# Fixed-purpose PM3000 ACME renewal and certificate activation helper.
# Diagnostics go to stderr; stdout is one closed JSON result.
set -u

MANAGED_ROOT=/etc/CA/pm3000-acme
ISSUED_ROOT=/mnt/hdUser/pm3000-revive/acme
ISSUED_CERT=$ISSUED_ROOT/certificate.pem
ISSUED_KEY=$ISSUED_ROOT/certificate-key.pem
MANAGED_CA=$ISSUED_ROOT/trust/managed-ca.pem
ACTIVATION_STATUS=$ISSUED_ROOT/activation-status-v1
APACHE_CONFIG=/etc/apache2/extra/httpd-ssl.conf
OPENSSL=/usr/bin/openssl
ACME=/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme
ATOMIC=/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-atomic-publish
HTTPD=/usr/sbin/httpd
APACHE_RELOAD=/etc/init.d/apache2
SLEEP=/bin/sleep
POLL_SLEEP=/bin/sleep
S_CLIENT_TIMEOUT=5
S_CLIENT_ATTEMPTS=10
ORIGINAL_CONFIG_SHA=9c693be2e5e2bf7ea5f35a3b8578754fcbd6a941d222c4c6a0074ca510cc1f19

usage() { echo "usage: pm3000-acme-maintenance scheduled|force [--broker-startup-notify]|activate" >&2; exit 2; }
result() { printf '{"mode":"%s","result":"%s","changed":%s,"reloaded":%s}\n' "$1" "$2" "$3" "$4"; }
transaction=0
reload_attempted=no
active_s_client_pid=
stage=
rollback=

sha256_file() {
    _digest=$($OPENSSL dgst -sha256 "$1" 2>/dev/null) || return 1
    _digest=${_digest##* }
    [ "${#_digest}" -eq 64 ] || return 1
    case "$_digest" in *[!0-9a-f]*) return 1;; esac
    printf '%s\n' "$_digest"
}

process_state() {
    _proc_line=
    read _proc_line <"/proc/$1/stat" || return 1
    set -- $_proc_line
    [ "$#" -ge 3 ] || return 1
    printf '%s\n' "$3"
}

cleanup_active_s_client() {
    _cleanup_pid=$active_s_client_pid
    [ -n "$_cleanup_pid" ] || return 0
    active_s_client_pid=
    kill -KILL "$_cleanup_pid" 2>/dev/null
    wait "$_cleanup_pid" 2>/dev/null
    return 0
}

kill_and_reap_s_client() {
    _reap_pid=$1
    kill -KILL "$_reap_pid" 2>/dev/null
    wait "$_reap_pid" 2>/dev/null
    [ "$active_s_client_pid" != "$_reap_pid" ] || active_s_client_pid=
    return 1
}

run_s_client_bounded() {
    _sclient_output=$1
    "$OPENSSL" s_client -connect 127.0.0.1:443 -showcerts </dev/null >"$_sclient_output" 2>/dev/null &
    _sclient_pid=$!
    active_s_client_pid=$_sclient_pid
    _sclient_elapsed=0
    while [ "$_sclient_elapsed" -lt "$S_CLIENT_TIMEOUT" ]; do
        _sclient_state=$(process_state "$_sclient_pid" 2>/dev/null) || {
            wait "$_sclient_pid"
            _sclient_rc=$?
            [ "$active_s_client_pid" != "$_sclient_pid" ] || active_s_client_pid=
            return "$_sclient_rc"
        }
        if [ "$_sclient_state" = Z ]; then
            wait "$_sclient_pid"
            _sclient_rc=$?
            [ "$active_s_client_pid" != "$_sclient_pid" ] || active_s_client_pid=
            return "$_sclient_rc"
        fi
        "$POLL_SLEEP" 1 || {
            kill_and_reap_s_client "$_sclient_pid"
            return 1
        }
        _sclient_elapsed=$(($_sclient_elapsed + 1))
    done
    kill_and_reap_s_client "$_sclient_pid"
    return 1
}

wait_for_tls_liveness() {
    _liveness_output=$1
    _liveness_attempt=1
    while [ "$_liveness_attempt" -le "$S_CLIENT_ATTEMPTS" ]; do
        run_s_client_bounded "$_liveness_output" && return 0
        [ "$_liveness_attempt" -eq "$S_CLIENT_ATTEMPTS" ] && break
        "$SLEEP" 1 || return 1
        _liveness_attempt=$(($_liveness_attempt + 1))
    done
    return 1
}

wait_for_served_certificate() {
    _wait_expected=$1
    _wait_output=$2
    _wait_attempt=1
    _wait_expected_fp=$($OPENSSL x509 -in "$_wait_expected" -noout -fingerprint -sha256 2>/dev/null) || return 1
    while [ "$_wait_attempt" -le "$S_CLIENT_ATTEMPTS" ]; do
        if run_s_client_bounded "$_wait_output"; then
            _wait_served_fp=$($OPENSSL x509 -in "$_wait_output" -noout -fingerprint -sha256 2>/dev/null) || _wait_served_fp=
            [ "$_wait_served_fp" = "$_wait_expected_fp" ] && return 0
        fi
        [ "$_wait_attempt" -eq "$S_CLIENT_ATTEMPTS" ] && break
        "$SLEEP" 1 || return 1
        _wait_attempt=$(($_wait_attempt + 1))
    done
    return 1
}

status_payload() {
    case "$1" in
        running) printf '%s\n' '{"state":"running"}' ;;
        succeeded) printf '%s\n' '{"state":"succeeded"}' ;;
        failed) printf '%s\n' '{"state":"failed","phase":"certificate_publication","reason":"publication"}' ;;
        *) return 1 ;;
    esac
}

publish_activation_status() {
    _status=$1
    _status_tmp=$ISSUED_ROOT/.activation-status.$$
    status_payload "$_status" >"$_status_tmp" || return 1
    chmod 600 "$_status_tmp" || { rm -f "$_status_tmp"; return 1; }
    "$ATOMIC" --verify-private-directory "$ISSUED_ROOT" >/dev/null 2>&1 || { rm -f "$_status_tmp"; return 1; }
    "$ATOMIC" "$ISSUED_ROOT" ".activation-status.$$" activation-status-v1 regular >/dev/null 2>&1 || {
        rm -f "$_status_tmp"
        "$ATOMIC" --verify-private-regular "$ACTIVATION_STATUS" >/dev/null 2>&1 || return 1
        _expected=$(status_payload "$_status") || return 1
        _actual=$(cat "$ACTIVATION_STATUS" 2>/dev/null) || return 1
        [ "$_actual" = "$_expected" ] || return 1
    }
    "$ATOMIC" --verify-private-regular "$ACTIVATION_STATUS" >/dev/null 2>&1
}

show_combined_status() {
    if [ -e "$ACTIVATION_STATUS" ] || [ -L "$ACTIVATION_STATUS" ]; then
        "$ATOMIC" --verify-private-regular "$ACTIVATION_STATUS" >/dev/null 2>&1 || {
            echo "unsafe activation status" >&2; return 1;
        }
        _status=$(cat "$ACTIVATION_STATUS" 2>/dev/null) || return 1
        case "$_status" in
            '{"state":"running"}'|'{"state":"succeeded"}'|'{"state":"failed","phase":"certificate_publication","reason":"publication"}')
                printf '%s\n' "$_status"; return 0;;
            *) echo "invalid activation status" >&2; return 1;;
        esac
    fi
    exec "$ACME" status
}

restore_previous() {
    _restore_ok=yes
    echo "activation failed; restoring previous certificate/config state" >&2
    if [ -f "$rollback/config" ]; then
        cp -p "$rollback/config" "$APACHE_CONFIG" || _restore_ok=no
        cmp -s "$rollback/config" "$APACHE_CONFIG" || _restore_ok=no
        "$ATOMIC" --verify-same-metadata "$rollback/config" "$APACHE_CONFIG" >/dev/null 2>&1 || _restore_ok=no
    else
        _restore_ok=no
    fi
    for _name in certificate.pem private-key.pem chain.pem config.sha256; do
        if [ -f "$rollback/$_name" ]; then
            cp -p "$rollback/$_name" "$MANAGED_ROOT/$_name" || _restore_ok=no
            cmp -s "$rollback/$_name" "$MANAGED_ROOT/$_name" || _restore_ok=no
            "$ATOMIC" --verify-same-metadata "$rollback/$_name" "$MANAGED_ROOT/$_name" >/dev/null 2>&1 || _restore_ok=no
            "$ATOMIC" --verify-private-regular "$MANAGED_ROOT/$_name" >/dev/null 2>&1 || _restore_ok=no
        elif [ -f "$rollback/.absent.$_name" ]; then
            rm -f "$MANAGED_ROOT/$_name" || _restore_ok=no
            [ ! -e "$MANAGED_ROOT/$_name" ] && [ ! -L "$MANAGED_ROOT/$_name" ] || _restore_ok=no
        else
            _restore_ok=no
        fi
    done
    "$HTTPD" -t -D SSL -f /etc/apache2/httpd.conf >/dev/null 2>&1 || _restore_ok=no
    if [ "$reload_attempted" = yes ]; then
        "$APACHE_RELOAD" reload >/dev/null 2>&1 || _restore_ok=no
        if [ -f "$rollback/certificate.pem" ]; then
            wait_for_served_certificate "$rollback/certificate.pem" "$stage/restored-served.pem" || _restore_ok=no
        elif [ -f "$rollback/.absent.certificate.pem" ]; then
            wait_for_tls_liveness "$stage/restored-served.pem" || _restore_ok=no
        else
            _restore_ok=no
        fi
    fi
    [ "$_restore_ok" = yes ] || return 1
    transaction=0
    rm -rf "$stage" "$rollback" || return 1
    return 0
}

abort_during_failure() {
    trap - 1 2 3 15
    cleanup_active_s_client
    if [ "$transaction" -ne 0 ]; then
        echo "rollback interrupted; preserving activation snapshots" >&2
        result "$mode" rollback_uncertain false false
    else
        result "$mode" failed false false
    fi
    exit 1
}

handle_activation_signal() {
    trap 'abort_during_failure' 1 2 3 15
    cleanup_active_s_client
    fail "activation interrupted"
}

fail() {
    trap 'abort_during_failure' 1 2 3 15
    cleanup_active_s_client
    echo "$1" >&2
    publish_activation_status failed || echo "cannot publish terminal activation failure status" >&2
    if [ "$transaction" -ne 0 ]; then
        if restore_previous; then
            trap - 1 2 3 15
            result "$mode" failed false false
        else
            echo "rollback verification failed; preserved snapshots at $rollback" >&2
            transaction=0
            trap - 1 2 3 15
            result "$mode" rollback_uncertain false false
        fi
    else
        [ -z "$stage" ] || rm -rf "$stage"
        [ -z "$rollback" ] || rm -rf "$rollback"
        result "$mode" failed false false
    fi
    exit 1
}

[ "$#" -ge 1 ] || usage
if [ "$1" = status ] && [ "$#" -eq 1 ]; then show_combined_status; exit $?; fi
case "$1" in
    config|ca|bootstrap) exec "$ACME" "$@";;
esac
mode=$1; shift; notify=no
case "$mode:$#" in
    scheduled:0|force:0|activate:0) : ;;
    force:1) [ "$1" = "--broker-startup-notify" ] || usage; notify=yes ;;
    *) usage ;;
esac
if [ "$mode" = scheduled ] && [ -f "$MANAGED_ROOT/certificate.pem" ] && [ ! -L "$MANAGED_ROOT/certificate.pem" ] &&
   "$OPENSSL" x509 -in "$MANAGED_ROOT/certificate.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
    result scheduled not_due false false; exit 0
fi

publish_activation_status running || { result "$mode" failed false false; exit 1; }
# pm3000-acme validates the exact configured SAN set, key match and complete
# chain against managed-ca.pem before atomically publishing these fixed inputs.
# "activate" reuses only those already-published inputs after an activation-only failure.
if [ "$mode" != activate ]; then
    if [ "$notify" = yes ]; then "$ACME" renew --foreground --broker-startup-notify || fail "ACME renewal failed"
    else "$ACME" renew --foreground || fail "ACME renewal failed"; fi
fi

[ -d "$MANAGED_ROOT" ] || { mkdir "$MANAGED_ROOT" || fail "cannot create managed certificate directory"; }
[ ! -L "$MANAGED_ROOT" ] || fail "managed certificate directory is a symlink"
chmod 700 "$MANAGED_ROOT" || fail "cannot protect managed certificate directory"
"$ATOMIC" --verify-private-directory "$MANAGED_ROOT" >/dev/null || fail "unsafe managed certificate directory"
"$ATOMIC" --verify-private-regular "$ISSUED_CERT" >/dev/null || fail "unsafe issued certificate"
"$ATOMIC" --verify-private-regular "$ISSUED_KEY" >/dev/null || fail "unsafe issued private key"
"$ATOMIC" --verify-private-regular "$MANAGED_CA" >/dev/null || fail "unsafe managed CA"
for _name in certificate.pem private-key.pem chain.pem config.sha256; do
    if [ -e "$MANAGED_ROOT/$_name" ] || [ -L "$MANAGED_ROOT/$_name" ]; then
        "$ATOMIC" --verify-private-regular "$MANAGED_ROOT/$_name" >/dev/null || fail "unsafe active managed file"
    fi
done
stage=$MANAGED_ROOT/.stage.$$
rollback=$MANAGED_ROOT/.rollback.$$
umask 077
mkdir "$stage" "$rollback" || fail "cannot create private activation staging"
trap 'handle_activation_signal' 1 2 3 15

awk '
BEGIN { n=0; inside=0; bad=0 }
/^-----BEGIN CERTIFICATE-----$/ { if (inside) bad=1; inside=1; n++; file=(n==1 ? leaf : chain) }
{ if (inside) print $0 > file; else if ($0 !~ /^[ \t\r]*$/) bad=1 }
/^-----END CERTIFICATE-----$/ { if (!inside) bad=1; inside=0 }
END { if (inside || bad || n < 2) exit 1; print n > count }
' leaf="$stage/certificate.pem" chain="$stage/chain.pem" count="$stage/count" "$ISSUED_CERT" || fail "issued fullchain is not one leaf plus a nonempty chain"
set -- $(cat "$stage/count" 2>/dev/null)
[ "$#" -eq 1 ] && [ "$1" -ge 2 ] 2>/dev/null || fail "invalid certificate object count"
leaf_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$stage/certificate.pem" 2>/dev/null)
chain_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$stage/chain.pem" 2>/dev/null)
[ "$leaf_count" -eq 1 ] && [ "$chain_count" -eq $(($1 - 1)) ] || fail "unexpected certificate object count"
cp "$ISSUED_KEY" "$stage/private-key.pem" || fail "cannot stage private key"
chmod 600 "$stage/certificate.pem" "$stage/private-key.pem" "$stage/chain.pem" || fail "cannot protect staged credentials"
awk '
/^-----BEGIN (RSA )?PRIVATE KEY-----$/ { begins++; inside=1; next }
/^-----END (RSA )?PRIVATE KEY-----$/ { ends++; inside=0; next }
/^-----BEGIN / || /^-----END / { bad=1 }
END { if (begins != 1 || ends != 1 || inside || bad) exit 1 }
' "$stage/private-key.pem" || fail "unexpected private-key PEM object count"
"$OPENSSL" x509 -in "$stage/certificate.pem" -noout >/dev/null 2>&1 || fail "invalid leaf certificate"
"$OPENSSL" verify -CAfile "$MANAGED_CA" -untrusted "$stage/chain.pem" "$stage/certificate.pem" >/dev/null 2>&1 || fail "certificate chain validation failed"
cert_mod=$($OPENSSL x509 -in "$stage/certificate.pem" -noout -modulus 2>/dev/null) || fail "cannot inspect certificate public key"
key_mod=$($OPENSSL rsa -in "$stage/private-key.pem" -noout -modulus 2>/dev/null) || fail "cannot inspect private key"
[ "$cert_mod" = "$key_mod" ] || fail "leaf and private key do not match"

config_sha=$(sha256_file "$APACHE_CONFIG") || fail "cannot hash Apache TLS configuration"
if [ -f "$MANAGED_ROOT/config.sha256" ]; then
    read recorded_sha <"$MANAGED_ROOT/config.sha256" || fail "cannot read managed Apache hash state"
    [ "$config_sha" = "$recorded_sha" ] || fail "Apache TLS configuration drift detected"
    config_migrated=yes
else
    [ "$config_sha" = "$ORIGINAL_CONFIG_SHA" ] || fail "unrecognized original Apache TLS configuration"
    config_migrated=no
fi
if [ "$config_migrated" = no ]; then
    sed -e 's|^SSLCertificateFile /etc/CA/pdu1\.tsei\.mdn\.pem$|SSLCertificateFile /etc/CA/pm3000-acme/certificate.pem|' \
        -e 's|^SSLCertificateKeyFile /etc/CA/pdu1\.tsei\.mdn\.key$|SSLCertificateKeyFile /etc/CA/pm3000-acme/private-key.pem|' \
        -e 's|^SSLCertificateChainFile /etc/CA/ca\.tsei\.mdn\.crt$|SSLCertificateChainFile /etc/CA/pm3000-acme/chain.pem|' \
        "$APACHE_CONFIG" >"$stage/httpd-ssl.conf" || fail "cannot stage Apache TLS configuration"
    [ "$(grep -c '^SSLCertificateFile /etc/CA/pm3000-acme/certificate.pem$' "$stage/httpd-ssl.conf")" -eq 1 ] || fail "server certificate directive migration failed"
    [ "$(grep -c '^SSLCertificateKeyFile /etc/CA/pm3000-acme/private-key.pem$' "$stage/httpd-ssl.conf")" -eq 1 ] || fail "server key directive migration failed"
    [ "$(grep -c '^SSLCertificateChainFile /etc/CA/pm3000-acme/chain.pem$' "$stage/httpd-ssl.conf")" -eq 1 ] || fail "server chain directive migration failed"
else cp "$APACHE_CONFIG" "$stage/httpd-ssl.conf" || fail "cannot stage Apache TLS configuration"; fi
managed_sha=$(sha256_file "$stage/httpd-ssl.conf") || fail "cannot hash managed Apache TLS configuration"
printf '%s\n' "$managed_sha" >"$stage/config.sha256" || fail "cannot stage managed Apache hash state"
chmod 600 "$stage/config.sha256" || fail "cannot protect managed Apache hash state"

unchanged=yes
for _name in certificate.pem private-key.pem chain.pem config.sha256; do
    [ -f "$MANAGED_ROOT/$_name" ] && cmp -s "$stage/$_name" "$MANAGED_ROOT/$_name" || unchanged=no
done
if [ "$unchanged" = yes ] && [ "$(sha256_file "$APACHE_CONFIG")" = "$managed_sha" ]; then
    "$OPENSSL" verify -CAfile "$MANAGED_CA" -untrusted "$MANAGED_ROOT/chain.pem" "$MANAGED_ROOT/certificate.pem" >/dev/null 2>&1 || unchanged=no
    active_cert_mod=$($OPENSSL x509 -in "$MANAGED_ROOT/certificate.pem" -noout -modulus 2>/dev/null) || unchanged=no
    active_key_mod=$($OPENSSL rsa -in "$MANAGED_ROOT/private-key.pem" -noout -modulus 2>/dev/null) || unchanged=no
    [ "${active_cert_mod-}" = "${active_key_mod-}" ] || unchanged=no
    if [ "$unchanged" = yes ]; then
        run_s_client_bounded "$stage/served.pem" || unchanged=no
        expected_fp=$($OPENSSL x509 -in "$MANAGED_ROOT/certificate.pem" -noout -fingerprint -sha256 2>/dev/null) || unchanged=no
        served_fp=$($OPENSSL x509 -in "$stage/served.pem" -noout -fingerprint -sha256 2>/dev/null) || unchanged=no
        [ "${served_fp-}" = "${expected_fp-}" ] || unchanged=no
    fi
fi
if [ "$unchanged" = yes ]; then
    transaction=0
    rm -rf "$stage" "$rollback"
    trap - 1 2 3 15
    publish_activation_status succeeded || { result "$mode" failed false false; exit 1; }
    result "$mode" unchanged false false; exit 0
fi

cp -p "$APACHE_CONFIG" "$rollback/config" || fail "cannot snapshot Apache TLS configuration"
for _name in certificate.pem private-key.pem chain.pem config.sha256; do
    if [ -f "$MANAGED_ROOT/$_name" ]; then cp -p "$MANAGED_ROOT/$_name" "$rollback/$_name" || fail "cannot snapshot managed state"
    else : >"$rollback/.absent.$_name" || fail "cannot snapshot absent managed state"; fi
done
transaction=1
for _name in certificate.pem private-key.pem chain.pem; do
    mv "$stage/$_name" "$MANAGED_ROOT/$_name" || fail "cannot publish managed certificate files"
done
if [ "$config_migrated" = no ]; then cp -p "$stage/httpd-ssl.conf" "$APACHE_CONFIG" || fail "cannot publish Apache TLS configuration"; fi
mv "$stage/config.sha256" "$MANAGED_ROOT/config.sha256" || fail "cannot publish managed Apache hash state"
chmod 600 "$MANAGED_ROOT/certificate.pem" "$MANAGED_ROOT/private-key.pem" "$MANAGED_ROOT/chain.pem" "$MANAGED_ROOT/config.sha256" || fail "cannot protect managed certificate files"
for _name in certificate.pem private-key.pem chain.pem config.sha256; do
    "$ATOMIC" --verify-private-regular "$MANAGED_ROOT/$_name" >/dev/null || fail "unsafe published managed file"
done
[ "$(sha256_file "$APACHE_CONFIG")" = "$managed_sha" ] || fail "published Apache TLS configuration hash mismatch"
"$HTTPD" -t -D SSL -f /etc/apache2/httpd.conf >/dev/null 2>&1 || fail "Apache syntax check failed"
reload_attempted=yes
"$APACHE_RELOAD" reload >/dev/null 2>&1 || fail "Apache reload failed"
wait_for_served_certificate "$MANAGED_ROOT/certificate.pem" "$stage/served.pem" || fail "Apache did not serve the activated certificate within the health-check window"
transaction=0
rm -rf "$stage" "$rollback"
trap - 1 2 3 15
publish_activation_status succeeded || { result "$mode" failed false true; exit 1; }
result "$mode" activated true true
exit 0
