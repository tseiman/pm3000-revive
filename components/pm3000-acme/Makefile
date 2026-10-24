CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Werror -pedantic
CPPFLAGS ?= -Iinclude

.PHONY: test clean fixtures

fixtures:
	sh tests/generate-fixtures.sh

test: fixtures build/test_url build/test_base64url build/test_json build/test_directory build/test_protocol build/test_crypto build/test_jws build/test_csr build/test_tls build/test_http build/test_challenge build/test_client build/test_network_client build/test_store build/test_certificate
	./build/test_url
	./build/test_base64url
	./build/test_json
	./build/test_directory
	./build/test_protocol
	./build/test_crypto
	./build/test_jws
	./build/test_csr
	python3 tests/verify_csr.py
	python3 tests/run_tls_test.py
	./build/test_http
	./build/test_challenge
	./build/test_client
	python3 tests/run_network_client.py
	./build/test_store
	./build/test_certificate

build/test_url: tests/test_url.c src/url.c include/pm3000_acme_url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_url.c src/url.c

build/test_base64url: tests/test_base64url.c src/base64url.c include/pm3000_acme_base64url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_base64url.c src/base64url.c

build/test_json: tests/test_json.c src/json.c include/pm3000_acme_json.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_json.c src/json.c

build/test_directory: tests/test_directory.c src/protocol.c src/json.c src/url.c \
		include/pm3000_acme_protocol.h include/pm3000_acme_json.h include/pm3000_acme_url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_directory.c src/protocol.c src/json.c src/url.c

build/test_protocol: tests/test_protocol.c src/protocol.c src/json.c src/url.c \
		include/pm3000_acme_protocol.h include/pm3000_acme_json.h include/pm3000_acme_url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_protocol.c src/protocol.c src/json.c src/url.c

build/test_crypto: tests/test_crypto.c src/crypto.c src/base64url.c src/url.c \
		include/pm3000_acme_crypto.h include/pm3000_acme_base64url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_crypto.c src/crypto.c src/base64url.c src/url.c -lcrypto

build/test_jws: tests/test_jws.c src/jws.c src/crypto.c src/base64url.c src/json.c src/url.c \
		include/pm3000_acme_jws.h include/pm3000_acme_crypto.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_jws.c src/jws.c src/crypto.c src/base64url.c src/json.c src/url.c -lcrypto

build/test_csr: tests/test_csr.c src/crypto.c src/base64url.c src/url.c \
		include/pm3000_acme_crypto.h include/pm3000_acme_url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_csr.c src/crypto.c src/base64url.c src/url.c -lcrypto

build/test_tls: tests/test_tls.c src/tls.c src/url.c \
		include/pm3000_acme_tls.h src/openssl_ssl_compat.h
	mkdir -p build
	$(CC) $(CPPFLAGS) -Isrc $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_tls.c src/tls.c src/url.c -lssl -lcrypto

build/test_http: tests/test_http.c src/http.c src/url.c \
		include/pm3000_acme_http.h include/pm3000_acme_url.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_http.c src/http.c src/url.c

build/test_challenge: tests/test_challenge.c src/challenge.c \
		include/pm3000_acme_challenge.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_challenge.c src/challenge.c

build/test_client: tests/test_client.c src/client.c src/challenge.c src/protocol.c \
		src/json.c src/url.c src/jws.c src/crypto.c src/base64url.c \
		include/pm3000_acme_client.h
	mkdir -p build
	$(CC) $(CPPFLAGS) -Isrc $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_client.c src/client.c src/challenge.c src/protocol.c \
		src/json.c src/url.c src/jws.c src/crypto.c src/base64url.c -lcrypto

build/test_network_client: tests/test_network_client.c src/client.c src/transport.c \
		src/tls.c src/http.c src/challenge.c src/protocol.c src/json.c src/url.c \
		src/jws.c src/crypto.c src/base64url.c include/pm3000_acme_transport.h
	mkdir -p build
	$(CC) $(CPPFLAGS) -Isrc $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_network_client.c src/client.c src/transport.c src/tls.c src/http.c \
		src/challenge.c src/protocol.c src/json.c src/url.c src/jws.c \
		src/crypto.c src/base64url.c -lssl -lcrypto

build/test_store: tests/test_store.c src/store.c include/pm3000_acme_store.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_store.c src/store.c

build/test_certificate: tests/test_certificate.c src/certificate.c src/tls.c \
		src/crypto.c src/base64url.c src/url.c include/pm3000_acme_certificate.h
	mkdir -p build
	$(CC) $(CPPFLAGS) -Isrc $(CFLAGS) -DPM3000_OPENSSL3_HOST -o $@ \
		tests/test_certificate.c src/certificate.c src/tls.c src/crypto.c \
		src/base64url.c src/url.c -lssl -lcrypto

clean:
	rm -rf build
