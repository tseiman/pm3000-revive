# 001: PM3000 firmware OpenSSL ABI

## Question

Given the existing PM3000 PPC32 big-endian firmware with glibc 2.3.5 and OpenSSL
1.0.1l, can a very small C99 executable built by the repository toolchain start
through `/lib/ld.so.1`, load the firmware `libssl.so.1.0.0` and
`libcrypto.so.1.0.0`, and call their public ABI without packaging either
library?

## Method

The probe uses the same source-only ABI-stub pattern as the existing GSP helper.
Generated stubs provide link metadata only and are never runtime dependencies or
release payload. QEMU runs the final stripped PPC binary against the extracted
firmware root filesystem.

## Acceptance

- ELF32, big-endian PowerPC executable with interpreter `/lib/ld.so.1`.
- Exact `DT_NEEDED`: `libc.so.6`, `libcrypto.so.1.0.0`, `libssl.so.1.0.0`.
- QEMU output reports `OpenSSL 1.0.1l 15 Jan 2015` and the success marker.
- The stripped binary size is measured.

## Verdict: PASS

### Validated locally

- The repository toolchain produces an ELF32 big-endian PowerPC executable with
  interpreter `/lib/ld.so.1`.
- The exact `DT_NEEDED` set is `libc.so.6`, `libcrypto.so.1.0.0`, and
  `libssl.so.1.0.0`.
- The exact direct imports are `SSL_library_init`, `SSL_load_error_strings`,
  `SSLeay_version`, and `write@GLIBC_2.0`.
- The stripped probe is 4,956 bytes with SHA-256
  `9ffc83481250d8578705f2af8a5279da6f91f3423fcae7130cc7becbf5c181ba`.

### Validated on the PM3000 target

The probe was copied temporarily to `/tmp`, its SHA-256 was verified, it was
executed in the foreground, and the shell trap removed it afterward. It made no
network request and changed no persistent state. The observed output was:

```text
openssl.version=OpenSSL 1.0.1l 15 Jan 2015
acme.openssl_abi.complete=yes
probe.exit=0
```

### QEMU limitation

QEMU 7.2 crashes in the firmware glibc 2.3.5 loader before application startup.
The unchanged firmware `wget.wget` fails at the same boundary, so QEMU is not
qualified for this dynamic firmware userspace. Static ELF/ABI gates and bounded
physical-target probes are authoritative instead.

### Decision

Proceed with a dedicated C99 ACME client using source-only link stubs and the
firmware's existing OpenSSL libraries. Do not package replacement TLS libraries.
