# Modern Web UI

This directory contains the dependency-free PM3000 browser interface. Production assets are only `index.html`, `styles.css`, and `app.js`; there is no framework, CDN, package manager, font download, or runtime third-party dependency.

## Authentication and authorization

- Users sign in with an existing PM3000 username and password.
- The password is submitted once to `/api/v1/session`, cleared immediately, and never stored in browser storage.
- The native adapter keeps the resulting GSP SID in a short-lived server-side session file. The browser receives only a `Secure`, `HttpOnly`, `SameSite=Strict` cookie plus public identity, CSRF, and navigation data.
- Authorized navigation paths and power/token capabilities come from the server-returned PM3000 navigation response. The browser does not grant rights.
- Browser mutations require the session cookie and `X-CSRF-Token`.
- REST bearer tokens are exclusively for external API clients and are never used as the browser login.

## Features

- Rights-filtered PM3000 navigation, with `/` retained as the legacy fallback for settings not yet migrated.
- Fresh outlet inventory and status.
- Offline-implemented, rights-gated `on`, `off`, and `cycle` controls. Every action includes the current inventory revision; the server refreshes topology and resolves the device row identity before dispatch. No real power action has been executed or validated.
- Administrator-only REST-token list, create, enable, disable, and revoke operations.
- New bearer secrets are displayed once and cleared when the dialog closes.
- Self-service password change plus typed DSView and NIS settings.
- Revision-protected Help and Language and Data Buffering forms. Each form remains disabled until a successful GET, keeps its revision only in memory, and reloads after every save result.
- Typed system information, memory, flash, network-device, IPv4/IPv6 route, and serial-port views.
- API-controlled values use safe DOM text sinks rather than HTML parsing.

All other writable settings remain in the legacy UI until each form has a closed typed request/response contract. See [`../DEFERRED-IMPROVEMENTS.md`](../DEFERRED-IMPROVEMENTS.md).

## Verification

From the repository root:

```sh
python3 -m unittest modern-WebUI/tests/test_web_ui.py
python3 -m unittest modern-WebUI/tests/test_native_adapter.py
```

The production Web root contains no preview credentials or synthetic data. Offline native tests use a fake Unix-socket controller and never contact a PM3000 or execute a real power action.
