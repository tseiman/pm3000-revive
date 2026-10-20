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

## Observed firmware 2.0.1.23 flow

The reviewed fixtures in [`../fixtures/observed/`](../fixtures/observed/) confirm this read-only browser sequence:

1. `action=get`, `path=login` returns `action=login`, identity version `7`, and a login control whose post-login path is `units.topology`.
2. Login submits `action=login`, `path=units.topology`, and a `section structure="login"` containing `username` and `password` parameters.
3. Successful authentication returns `action=header`, `path=units`, and the Avtrans SID. The fixture redacts the SID and operator/appliance labels.
4. `action=navigation`, `path=units` returns the backend-described navigation and authorization metadata.
5. `action=get`, `path=units.topology` returns `action=content` with table `topologyTable`. It contains the appliance/PDU/outlet hierarchy, current status fields, and passive control descriptors.
6. `action=get`, `path=units.powermanagement.pdu_management` returns table `pdu_devices_table` with model, position, status, current, power, alarm, and threshold fields.
7. `action=logout`, `path=login` invalidates the browser session and returns the unauthenticated login model.

Only the read requests and logout were transmitted. Control descriptors such as `targPowerOn`, `targPowerOff`, `targCycle`, `on`, `off`, `cycle`, `rebootPDU`, `resetHW`, `factorydef`, and `upgradeFirmware` were observed in responses but never invoked. Their state-changing request payloads remain unknown.

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

## Remaining evidence

Observed sanitized fixtures now cover successful login/header, root navigation, topology, PDU/outlet inventory, read-only status, and logout. Evidence is still required for:

- login failure and session expiry;
- authorization denial;
- exact individual `on`, `off`, and `cycle` request/response shapes;
- malformed and timeout behavior.

The framing between `mod_avtrans` and `/dev/avtrans_socket` must be proven before a CGI adapter connects directly. Alternatively, a same-origin call through the existing handler must be proven safe and non-deadlocking. Neither path is assumed yet.

## Stage 1 evidence set

[`../fixtures/synthetic/`](../fixtures/synthetic/) contains only clean-room schema examples. Its manifest marks every XML file as `synthetic`; these files do not establish concrete device paths, action IDs, controls, row IDs, or complete responses.

[`../fixtures/observed/`](../fixtures/observed/) contains the manually reviewed `observed-sanitized` read-only evidence from firmware 2.0.1.23. Its manifest records the collection boundary. Response control definitions are evidence of available metadata, not evidence that any state-changing request was transmitted.

[`CAPTURE.md`](CAPTURE.md) defines the short operator-run procedure for obtaining request and response bodies without replaying requests. Raw captures remain outside Git. Only manually reviewed sanitizer output can be promoted to observed protocol evidence.

The sanitizer at `../tools/sanitize_avtrans.py`:

- requires an `<avtrans>` root;
- rejects DTD/entity declarations through the XML parser regardless of source encoding, input over 1 MiB, and XML deeper than 32 levels;
- redacts SID, login, credential, token, certificate, common network fields, operator-assigned `name`/`serialnumber` parameters, RFC1918 addresses, and private hostname suffixes across namespaced elements, attributes, and mixed content;
- supports explicit literal replacement for device labels or serials;
- opens raw input with no-follow and nonblocking semantics, then accepts only a regular file;
- writes a separate output atomically with mode `0600`.

A transport timeout is represented as the absence of a response, not as invented backend XML.
