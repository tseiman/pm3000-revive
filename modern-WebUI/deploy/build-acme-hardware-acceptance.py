#!/usr/bin/env python3
"""Build a closed one-password PM3000 ACME hardware acceptance ZIP."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def add(archive, name, data, mode):
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((stat.S_IFREG | mode) << 16)
    archive.writestr(info, data)


def run_script(version, candidate_sha):
    return f'''#!/bin/sh
# WRITE-CAPABLE: runs exactly one real renewal with the {version} diagnostic candidate.
set -eu
[ "$#" -eq 1 ] || {{ echo "usage: $0 root@CERTIFICATE_VALID_HOST" >&2; exit 2; }}
target=$1
case "$target" in ''|-*) echo "unsafe SSH target" >&2; exit 2;; esac
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
candidate=$SCRIPT_DIR/pm3000-acme
expected={candidate_sha}
[ -f "$candidate" ] && [ ! -L "$candidate" ] || {{ echo "candidate missing or unsafe" >&2; exit 1; }}
actual=$(openssl dgst -sha256 "$candidate"); actual=${{actual##*= }}
[ "$actual" = "$expected" ] || {{ echo "candidate hash mismatch" >&2; exit 1; }}
work=$(mktemp -d "${{TMPDIR:-/tmp}}/pm3000-acme-{version}-host.XXXXXX")
cleanup() {{ status=$?; trap - 0 1 2 15; rm -rf "$work"; exit "$status"; }}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
runner=$work/remote-runner.sh
cat >"$runner" <<'REMOTE_RUNNER'
#!/bin/sh
set -eu
remote=$1
expected=$2
candidate=$remote/pm3000-acme
challenge=/mnt/hdUser/pm3000-revive/acme-http-01
[ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -x "$candidate" ] || {{ echo 'candidate staging unsafe' >&2; exit 1; }}
actual=$(openssl dgst -sha256 "$candidate"); actual=${{actual##*= }}
[ "$actual" = "$expected" ] || {{ echo 'remote candidate hash mismatch' >&2; exit 1; }}
set +e
"$candidate" renew --foreground --debug
renewal=$?
set -e
[ -d "$challenge" ] && [ ! -L "$challenge" ] || {{ echo 'challenge webroot missing or unsafe' >&2; exit 1; }}
entries=$(ls -a "$challenge" | grep -v '^\\.$' | grep -v '^\\.\\.$' || true)
[ -z "$entries" ] || {{ echo 'HTTP-01 challenge files remain' >&2; exit 1; }}
printf 'acme_hardware_acceptance.renewal_exit=%s\\n' "$renewal"
echo 'acme_hardware_acceptance.http01_cleanup=complete'
echo 'acme_hardware_acceptance.renewal_count=1'
exit "$renewal"
REMOTE_RUNNER
chmod 700 "$runner"
remote=/tmp/pm3000-acme-{version}-acceptance
echo "Opening one non-multiplexed SSH connection to $target (one password prompt expected)"
python3 - "$candidate" "$runner" <<'PY' | ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no "$target" "remote='$remote'; expected='$expected'; cleanup() {{ status=\$?; trap - 0 1 2 15; cd /; rm -rf \"\$remote\"; if [ -e \"\$remote\" ] || [ -L \"\$remote\" ]; then echo 'acme_hardware_acceptance.temporary_cleanup=failed' >&2; exit 1; fi; echo 'acme_hardware_acceptance.temporary_cleanup=complete'; exit \"\$status\"; }}; trap cleanup 0; trap 'exit 129' 1; trap 'exit 130' 2; trap 'exit 143' 15; [ ! -e \"\$remote\" ] && [ ! -L \"\$remote\" ] && umask 077 && mkdir \"\$remote\" && cd \"\$remote\" && tar xf - && chmod 700 ./pm3000-acme ./remote-runner.sh && /bin/sh ./remote-runner.sh \"\$remote\" \"\$expected\""
import sys, tarfile
from pathlib import Path
candidate, runner = map(Path, sys.argv[1:])
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
    for path, name in ((candidate, "pm3000-acme"), (runner, "remote-runner.sh")):
        info = archive.gettarinfo(str(path), arcname=name)
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        info.mode = 0o700
        with path.open("rb") as source:
            archive.addfile(info, source)
PY
'''.encode("ascii")


def verifier(version, expected, checksums):
    return f'''#!/usr/bin/env python3
import hashlib, os, pathlib, stat, sys
root = pathlib.Path(__file__).resolve().parent
expected_names = ["README.md", "SHA256SUMS", "verify.py", "run.sh", "pm3000-acme"]
if sorted(p.name for p in root.iterdir()) != sorted(expected_names):
    raise SystemExit("bundle member allowlist mismatch")
lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
expected = {checksums!r}
if lines != expected:
    raise SystemExit("checksum manifest mismatch")
for line in lines:
    value, name = line.split("  ", 1)
    path = root / name
    if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != value:
        raise SystemExit("bundle checksum mismatch: " + name)
for name in ("verify.py", "run.sh", "pm3000-acme"):
    if stat.S_IMODE((root / name).stat().st_mode) != 0o755:
        raise SystemExit("executable mode mismatch: " + name)
print("candidate_sha256={expected}")
print("bundle_version={version}")
print("bundle.verify.complete=yes")
'''.encode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"v[1-9][0-9]*", args.version) is None:
        parser.error("version must match vN")
    if not args.candidate.is_file() or args.candidate.is_symlink():
        parser.error("candidate must be a regular non-symlink file")
    if args.output.exists():
        parser.error("output already exists")
    candidate = args.candidate.read_bytes()
    candidate_sha = digest(candidate)
    run = run_script(args.version, candidate_sha)
    readme = f'''# PM3000 ACME {args.version} hardware acceptance\n\nVerify with `python3 ./verify.py`, then run exactly one write-capable renewal:\n\n```sh\n./run.sh root@CERTIFICATE_VALID_HOST\n```\n\nOpenSSH owns the single password prompt. The command uploads one POSIX USTAR over\none non-multiplexed SSH connection, runs the candidate from a fixed `/tmp` tree,\nprints only closed debug categories, and trap-removes and verifies that tree.\n'''.encode("ascii")
    checksum_lines = [
        f"{digest(readme)}  README.md",
        f"{digest(run)}  run.sh",
        f"{candidate_sha}  pm3000-acme",
    ]
    sums = ("\n".join(checksum_lines) + "\n").encode("ascii")
    verify = verifier(args.version, candidate_sha, checksum_lines)
    prefix = f"pm3000-acme-{args.version}-acceptance"
    ordered = [
        ("README.md", readme, 0o644),
        ("SHA256SUMS", sums, 0o644),
        ("verify.py", verify, 0o755),
        ("run.sh", run, 0o755),
        ("pm3000-acme", candidate, 0o755),
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for name, data, mode in ordered:
                add(archive, f"{prefix}/{name}", data, mode)
        os.replace(temporary, args.output)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(f"zip={args.output}")
    print(f"zip_sha256={digest(args.output.read_bytes())}")
    print(f"candidate_sha256={candidate_sha}")
    print("bundle.build.complete=yes")


if __name__ == "__main__":
    main()
