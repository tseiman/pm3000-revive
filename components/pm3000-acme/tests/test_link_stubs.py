#!/usr/bin/env python3
import subprocess
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
BUILDER = COMPONENT / "scripts" / "build-link-stubs.sh"
ROOT = COMPONENT / "build" / "link-stubs"
READELF = (
    COMPONENT.parent.parent
    / "components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-readelf"
)

subprocess.run([str(BUILDER)], check=True)
expected = {
    line.strip()
    for line in (COMPONENT / "abi-allowed-imports.txt").read_text(encoding="ascii").splitlines()
    if line.strip()
}
actual = set()
for relative, soname in (
    ("lib/libc-2.3.5.so", "libc.so.6"),
    ("usr/lib/libssl.so.1.0.0", "libssl.so.1.0.0"),
    ("usr/lib/libcrypto.so.1.0.0", "libcrypto.so.1.0.0"),
):
    library = ROOT / relative
    dynamic = subprocess.run(
        [str(READELF), "-d", str(library)], check=True,
        text=True, stdout=subprocess.PIPE,
    ).stdout
    if f"Library soname: [{soname}]" not in dynamic:
        raise SystemExit(f"wrong SONAME: {relative}")
    symbols = subprocess.run(
        [str(READELF), "--wide", "--dyn-syms", str(library)], check=True,
        text=True, stdout=subprocess.PIPE,
    ).stdout
    if soname == "libc.so.6" and " stderr@@GLIBC_2.0" not in symbols:
        raise SystemExit("libc link stub does not export stderr@GLIBC_2.0")
    for line in symbols.splitlines():
        fields = line.split()
        if (len(fields) >= 8 and fields[3] == "FUNC"
                and fields[6] != "UND" and fields[7] != ""):
            actual.add(fields[7].split("@", 1)[0])
if actual != expected:
    raise SystemExit(
        "stub symbol mismatch\nmissing=" + repr(sorted(expected - actual))
        + "\nextra=" + repr(sorted(actual - expected))
    )
print("link_stubs.tests.complete=yes")
