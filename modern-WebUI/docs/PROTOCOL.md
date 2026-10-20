# Avtrans Protocol Boundary

## Confirmed request envelope

The legacy client sends XML to `POST /appliance/avtrans` using the historical content type `application/x-www-form-urlencoded`:

```xml
<avtrans>
  <sid>SESSION_PLACEHOLDER</sid>
  <action>ACTION_PLACEHOLDER</action>
  <agents>
    <src>wmi</src>
    <dest>controller</dest>
  </agents>
  <paths>
    <path>PATH_PLACEHOLDER</path>
  </paths>
  <payload>...</payload>
</avtrans>
```

The payload is omitted for actions that do not require form/table data. Login uses a `section` with structure `login` and username/password parameters. Real credentials and session identifiers are never fixtures.

## Confirmed server flow

1. Apache maps `/appliance/avtrans` to `mod_avtrans.so`.
2. The module forwards the XML to `/dev/avtrans_socket`.
3. `uicontrold` parses the envelope and handles login, session resumption, navigation, payload parsing, GSP authorization, and CACPD transactions.
4. Power management ultimately uses the vendor power API and daemon.

Static symbols and strings confirm that `uicontrold` can create/resume GSP sessions, authenticate through PAM/GSP, connect and log in to CACPD, submit transactions, commit/revert, and produce Avtrans XML replies.

## Confirmed power semantics

Backend feature definitions distinguish:

- status and inventory reads;
- individual outlet `on`, `off`, and `cycle`;
- outlet operations such as `lock`, `unlock`, `ion`, and `ioff`;
- PDU-wide actions;
- configuration, reset, reboot, factory-default, and firmware operations.

The initial REST contract allows only status/inventory and individual `on`, `off`, and `cycle`. All other categories and operations are excluded. Backend authorization remains authoritative.

Concrete browser paths, action IDs, controls, dependencies, and confirmation metadata are supplied by the backend response. The original frontend does not provide a safe hard-coded power-path table. Display labels and numeric positions must not be treated as protocol identifiers.

## Rules for implementation

- Paths and actions come from fixed operation descriptors, never from HTTP input.
- REST is HTTPS-only; the adapter rejects execution through a cleartext listener even if routing is misconfigured.
- Outlet identifiers are resolved from current inventory; no arithmetic or guessed mapping.
- XML is constructed and parsed structurally with strict depth/size limits.
- Missing, duplicate, unexpected, or ambiguous fields fail closed.
- Unknown backend errors remain errors; they are not converted into success or empty values.
- State-changing requests are serialized or otherwise protected against overlap.
- `cycle` is never retried automatically.
- Session IDs, credentials, raw Authorization values, and full XML documents are not logged.

## Evidence required

Sanitized fixtures are still required for:

- login success/failure and session expiry;
- topology/navigation;
- PDU/outlet inventory;
- outlet status;
- authorization denial;
- exact individual `on`, `off`, and `cycle` request/response shapes;
- malformed and timeout behavior.

The framing between `mod_avtrans` and `/dev/avtrans_socket` must be proven before a CGI adapter connects directly. Alternatively, a same-origin call through the existing handler must be proven safe and non-deadlocking. Neither path is assumed yet.
