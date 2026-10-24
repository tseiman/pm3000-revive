#!/usr/bin/env python3
import subprocess
import sys

path = "build/test-request.csr.der"
verify = subprocess.run(
    ["openssl", "req", "-inform", "DER", "-in", path, "-verify", "-noout"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
if verify.returncode != 0:
    print(verify.stdout, end="", file=sys.stderr)
    raise SystemExit("CSR signature verification failed")
text = subprocess.check_output(
    ["openssl", "req", "-inform", "DER", "-in", path, "-text", "-noout"],
    text=True,
)
required = (
    "Subject: CN = pdu1.tsei.mdn",
    "DNS:pdu1.tsei.mdn, DNS:usv3.tsei.mdn, DNS:usv3-24v.tsei.mdn",
    "Signature Algorithm: sha256WithRSAEncryption",
)
for expected in required:
    if expected not in text:
        raise SystemExit(f"CSR field missing: {expected}")
print("csr.openssl.verify.complete=yes")
