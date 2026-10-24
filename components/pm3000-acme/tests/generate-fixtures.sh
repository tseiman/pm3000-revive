#!/bin/sh
set -eu

base=${1:-tests/fixtures}
tls=$base/tls
mkdir -p "$tls"

if [ ! -s "$base/account-test-key.pem" ]; then
    openssl genrsa -out "$base/account-test-key.pem" 2048 >/dev/null 2>&1
    chmod 600 "$base/account-test-key.pem"
fi

if [ ! -s "$tls/ca-key.pem" ] || [ ! -s "$tls/ca.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj '/CN=PM3000 ACME Test CA' \
        -keyout "$tls/ca-key.pem" -out "$tls/ca.pem" >/dev/null 2>&1
    chmod 600 "$tls/ca-key.pem"
fi

if [ ! -s "$tls/server-key.pem" ] || [ ! -s "$tls/server.pem" ]; then
    request=$tls/server.csr
    openssl req -new -newkey rsa:2048 -nodes \
        -config "$tls/server.cnf" \
        -keyout "$tls/server-key.pem" -out "$request" >/dev/null 2>&1
    openssl x509 -req -days 30 -sha256 -in "$request" \
        -CA "$tls/ca.pem" -CAkey "$tls/ca-key.pem" -CAcreateserial \
        -extfile "$tls/server.cnf" -extensions req_ext \
        -out "$tls/server.pem" >/dev/null 2>&1
    rm -f "$request" "$tls/ca.srl"
    chmod 600 "$tls/server-key.pem"
fi
