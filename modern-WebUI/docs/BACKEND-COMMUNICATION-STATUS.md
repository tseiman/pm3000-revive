# Backend Communication Status

This document records the live-device status of the Modern WebUI connection to the PM3000 controller backend as of 2026-10-22. It separates verified observations from hypotheses so that work can resume without repeating speculative releases.

## Communication path

```text
HTTPS client
  -> Apache 2.2.23 CGI
  -> pm3000-rest
  -> /dev/avtrans_socket (local Unix-domain socket)
  -> uicontrold
  -> GSP/CACPD
```

The relevant backend traffic exists only on `pdu1.tsei.mdn`. It does not cross a network interface, so workstation or gateway `tcpdump` captures cannot observe it.

## Verified live-device state

- Release `0.2-rest-control-rc4` is installed successfully.
- Legacy WebUI remains available.
- Bearer authentication and the token store work: the earlier `token_store_unavailable` response disappeared after correcting runtime ownership.
- `GET /api/v1/outlets` currently returns:

  ```json
  {"code":"backend_unavailable","message":"Read-only backend unavailable."}
  ```

  with HTTP 503.
- Browser login reaches the native backend path but reports `Controller login rejected.`
- A direct `uicontrold` trace of the RC4 login proves that the empty-SID login request is accepted, PAM/GSP and CACPD authentication succeed with `read write exec` permissions, and `uicontrold` returns a complete NUL-terminated `action=header` response with a 32-character SID.
- The same captured response is rejected by the RC4 native XML parser. Removing only the vendor's exact `xml-stylesheet` processing instruction makes that response pass. The current failure is therefore localized to response parsing, not controller authentication or Unix-socket transport.
- No Modern REST outlet action has been attempted and no outlet has been switched through the replacement adapter.
- Offline fake-controller and QEMU tests pass, but they do not prove communication with the real Linux 2.6.23 appliance backend.

## Implemented backend work

- Implemented the native C99 Avtrans client and bounded XML request templates.
- Implemented controller login, navigation, read-only inventory requests, logout, and separately gated write templates.
- Derived and checked the 59-byte Unix-socket metadata header against static analysis of vendor `mod_avtrans.so` and `uicontrold`:
  - byte 0: plugin flag;
  - byte 1: internal-mode flag;
  - byte 2: HTTPS flag;
  - bytes 3–42: client address;
  - bytes 43–58: accepted language.
- Corrected the client-address field from hard-coded `127.0.0.1` to validated CGI `REMOTE_ADDR` in RC3.
- Corrected private runtime ownership from `root` to the Apache `daemon` account in RC3.
- Replaced `SOCK_CLOEXEC` with `socket()` plus `fcntl(FD_CLOEXEC)` for Linux 2.6.23 compatibility in RC4.
- Added regression tests for the metadata address, runtime ownership, and old-kernel socket creation.

## Attempts that did not resolve the failure

- RC1 rejected Apache's inherited Basic Authorization header before browser login reached the controller.
- RC2 fixed that rejection, after which browser login failed as `Controller login rejected.`
- Correcting token-store ownership resolved `token_store_unavailable`, but exposed the current backend 503.
- RC3 corrected the Avtrans client address and runtime ownership; the backend 503 remained.
- RC4 removed the unsupported old-kernel `SOCK_CLOEXEC` dependency; the backend 503 still remained.

These changes corrected real defects, but neither the `REMOTE_ADDR` nor `SOCK_CLOEXEC` hypothesis was sufficient to establish live backend communication.

## Confirmed RC4 root cause

The real response starts with two processing instructions:

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="transformation.xsl"?>
```

RC4 accepts the XML declaration but rejects every subsequent processing instruction. Earlier sanitized fixtures did not retain the stylesheet instruction, so the fake-controller tests did not reproduce the real response. This causes login parsing to fail before navigation or topology is requested and is surfaced as `Controller login rejected.` or `backend_unavailable`.

## Next investigation

Do not publish another release based only on a new hypothesis. The next candidate should:

1. Add a regression test containing the exact safe vendor preamble before a sanitized successful login response.
2. Accept only the known static `xml-stylesheet` instruction before the root element; continue rejecting arbitrary processing instructions, external URLs, DTDs, and entities.
3. Verify the parser against the captured response locally without retaining credentials, private addresses, labels, or session values.
4. Keep stage-specific safe diagnostics so later transport and parser failures are distinguishable.
5. Run the complete host, sanitizer, QEMU/PPC, and deployment suites.
6. Validate browser login and `GET /api/v1/outlets` on the real device before considering any control-token or outlet-action test.

## Capture safety

Raw Avtrans traffic can contain usernames, passwords, session IDs, device identifiers, network configuration, and topology data.

- Keep raw traces outside Git and preferably on the appliance or a private workstation directory.
- Never commit raw syscall buffers, XML, HAR files, credentials, tokens, or session IDs.
- Stop Apache tracing immediately after the two controlled read-only requests.
- Sanitize any required XML with [`CAPTURE.md`](CAPTURE.md) and manually review it before sharing.
- Do not capture or replay `on`, `off`, or `cycle` actions during this investigation.

## Related documentation

- [`NATIVE-ADAPTER.md`](NATIVE-ADAPTER.md)
- [`PROTOCOL.md`](PROTOCOL.md)
- [`CAPTURE.md`](CAPTURE.md)
