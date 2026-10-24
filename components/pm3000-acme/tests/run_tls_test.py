#!/usr/bin/env python3
import socket
import subprocess
import sys
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]

command = [
    "openssl", "s_server", "-accept", str(port),
    "-cert", "tests/fixtures/tls/server.pem",
    "-key", "tests/fixtures/tls/server-key.pem",
    "-www", "-tls1_2", "-quiet",
]
server = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
try:
    deadline = time.monotonic() + 5.0
    while True:
        if server.poll() is not None:
            raise SystemExit("openssl s_server exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise SystemExit("openssl s_server readiness timeout")
            time.sleep(0.05)
    result = subprocess.run(["./build/test_tls", str(port)])
    if result.returncode != 0:
        raise SystemExit(result.returncode)
finally:
    server.terminate()
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
print("tls.loopback.verify.complete=yes")
