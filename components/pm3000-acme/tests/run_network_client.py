#!/usr/bin/env python3
import http.server
import os
import pathlib
import ssl
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
WEBROOT = ROOT / "build" / "network-challenge"

class State:
    nonce = 0
    bad_nonce = False
    challenge = False
    auth_polls = 0
    finalized = False
    order_polls = 0

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def authority(self):
        return f"https://localhost:{self.server.server_port}"

    def reply(self, status, body=b"", location=None):
        State.nonce += 1
        self.send_response(status)
        self.send_header("Replay-Nonce", f"bm9uY2Ut{State.nonce}")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if location:
            self.send_header("Location", location)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path != "/directory":
            return self.reply(404, b"{}")
        a = self.authority()
        body = (f'{{"newNonce":"{a}/nonce","newAccount":"{a}/account",'
                f'"newOrder":"{a}/new-order"}}').encode()
        self.reply(200, body)

    def do_HEAD(self):
        self.reply(204)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if (not body.startswith(b"{") or
                self.headers.get("Content-Type") != "application/jose+json"):
            return self.reply(400, b"{}")
        a = self.authority()
        if self.path == "/account":
            return self.reply(201, b'{"status":"valid"}', f"{a}/account/1")
        if self.path == "/new-order":
            if not State.bad_nonce:
                State.bad_nonce = True
                return self.reply(400,
                    b'{"type":"urn:ietf:params:acme:error:badNonce"}')
            data = (f'{{"status":"pending","authorizations":["{a}/auth/1"],'
                    f'"finalize":"{a}/finalize/1"}}').encode()
            return self.reply(201, data, f"{a}/order/1")
        if self.path == "/challenge/1":
            token = WEBROOT / "dG9rZW4"
            if not token.is_file() or not token.read_text().startswith("dG9rZW4."):
                return self.reply(500, b"{}")
            State.challenge = True
            return self.reply(200, b'{"status":"pending"}')
        if self.path == "/auth/1":
            if not State.challenge:
                status, challenge_status = "pending", "pending"
            else:
                State.auth_polls += 1
                if State.auth_polls == 1:
                    status, challenge_status = "pending", "processing"
                else:
                    status, challenge_status = "valid", "valid"
            data = (f'{{"status":"{status}","identifier":{{"type":"dns",'
                    f'"value":"pdu1.tsei.mdn"}},"challenges":[{{"type":"http-01",'
                    f'"url":"{a}/challenge/1","status":"{challenge_status}",'
                    f'"token":"dG9rZW4"}}]}}').encode()
            return self.reply(200, data)
        if self.path == "/finalize/1":
            State.finalized = True
            data = (f'{{"status":"processing","authorizations":["{a}/auth/1"],'
                    f'"finalize":"{a}/finalize/1"}}').encode()
            return self.reply(200, data)
        if self.path == "/order/1":
            if not State.finalized:
                status = "ready"
                certificate = ""
            else:
                State.order_polls += 1
                status = "processing" if State.order_polls == 1 else "valid"
                certificate = f',"certificate":"{a}/cert/1"' if status == "valid" else ""
            data = (f'{{"status":"{status}","authorizations":["{a}/auth/1"],'
                    f'"finalize":"{a}/finalize/1"{certificate}}}').encode()
            return self.reply(200, data)
        if self.path == "/cert/1":
            return self.reply(200,
                b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
        self.reply(404, b"{}")


def main():
    WEBROOT.mkdir(parents=True, exist_ok=True)
    for entry in WEBROOT.iterdir():
        entry.unlink()
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / "tests/fixtures/tls/server.pem",
                            ROOT / "tests/fixtures/tls/server-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = subprocess.run(
            [str(ROOT / "build/test_network_client"),
             str(server.server_port), str(WEBROOT)],
            cwd=ROOT, text=True, capture_output=True, timeout=30)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        return completed.returncode
    if not (State.bad_nonce and State.challenge and
            State.auth_polls == 2 and State.order_polls == 2):
        print("network.mock.state.invalid", file=sys.stderr)
        return 1
    print("network.mock.complete=yes")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
