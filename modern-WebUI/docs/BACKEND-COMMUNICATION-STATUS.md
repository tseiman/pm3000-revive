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
- No REST outlet action has been attempted and no outlet has been switched.
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

## Current uncertainty

The public error currently combines several different failure classes. It does not establish whether the failure occurs during:

1. Unix-socket creation or connection;
2. header or XML transmission;
3. response reception or framing;
4. controller authentication;
5. response parsing;
6. the subsequent read or logout request.

The remaining likely causes therefore include socket permissions or syscall behavior, a still-mismatched vendor framing detail, controller rejection, an unexpected real-firmware response, or an overly strict parser. No single cause is currently proven.

## Next investigation

Do not publish another release based only on a new hypothesis. First collect direct evidence on `pdu1.tsei.mdn`:

1. Check whether `strace` or `ltrace` is already present.
2. If available, trace the Apache/CGI processes for:
   - one successful read-only Legacy WebUI request;
   - the equivalent failed Modern REST read.
3. Compare only these syscall-level facts:
   - `socket`, `fcntl`, `connect`;
   - byte counts and return values from `send`/`write` and `recv`/`read`;
   - `errno`, close timing, and response termination.
4. If no tracer exists, build a narrow PPC diagnostic adapter that reports stage, syscall, `errno`, and message lengths without logging payload contents.
5. Only if syscall metadata is insufficient, capture the Unix-socket payload on the appliance and sanitize it before analysis.
6. Split the generic backend error into stable transport, controller-login-response, read-response, and logout phases before the next candidate release.
7. Validate `GET /api/v1/outlets` on the real device before considering any control-token or outlet-action test.

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
