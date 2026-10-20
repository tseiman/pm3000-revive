# REST API v1 Contract

This document defines the narrow Stage 2 contract for the PM3000 modern Web UI. The machine-readable source is [`../api/openapi-v1.json`](../api/openapi-v1.json).

Stage 2 is a contract only. It does not install an adapter, change appliance configuration, or enable outlet control.

## Active surface

Only these method/path pairs exist:

- `GET /api/v1/health`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
- `POST /api/v1/outlets/{outletId}/actions`

All other paths and methods are rejected. There is no generic backend path, XML passthrough, PDU-wide operation, configuration endpoint, reset endpoint, or update endpoint.

`GET /api/v1/health` is a local liveness check. It does not contact Avtrans and exposes no appliance identity or backend status. All other routes require bearer authentication; token persistence and scopes belong to Stage 3.

## Fixed backend reads

The two read routes are projections of one fixed, observed request:

```text
action=get
path=units.topology
```

- The collection route validates and projects every outlet row.
- The detail route performs the same fresh inventory read and then selects exactly one opaque outlet ID.
- HTTP input can never select or alter the Avtrans action, path, agents, payload, or table ID.
- An absent, duplicate, malformed, oversized, or ambiguous table/row/field produces `backend_protocol_error`; it is not silently ignored.
- Unknown backend state text maps to `unknown`. Only observed `ON` and `OFF` values map to `on` and `off`.

The adapter must construct XML structurally. It accepts at most 1 MiB of backend XML, at most 32 XML levels, one `<avtrans>` root, the expected action/path, and one `topologyTable`. DTDs and entities are rejected.

## Opaque IDs and fresh resolution

REST IDs never expose raw Avtrans row IDs, hostnames, labels, or numeric guesses.

For a validated UTF-8 backend row identity, the adapter derives the outlet ID as:

```text
base64url(SHA-256("pm3000-rest-v1\0outlet\0" || backendRowId))[0:22]
```

The PDU ID uses the separate domain string `pm3000-rest-v1\0pdu\0`. Base64 padding is omitted. IDs therefore match `^[A-Za-z0-9_-]{22}$`.

The adapter rejects duplicate backend identities and any digest-prefix collision. Outlet IDs are resolved only against the current validated inventory; labels and positions are never used as protocol identifiers.

`inventoryRevision` uses the separate `pm3000-rest-v1\0inventory\0` domain prefix. Backend outlet identities are encoded as UTF-8, sorted by unsigned byte value, and concatenated as a four-byte unsigned big-endian length followed by the identity bytes. SHA-256, base64url encoding without padding, and the same 22-character truncation are then applied. The OpenAPI contract contains exact domain-prefix hex values and synthetic fixed vectors for outlet, PDU, and inventory derivation.

The revision excludes display names and transient power state, so ordinary status changes do not invalidate identity mapping.

## Read response

The collection response has this closed shape:

```json
{
  "apiVersion": "v1",
  "inventoryRevision": "CCCCCCCCCCCCCCCCCCCCCC",
  "outlets": [
    {
      "id": "AAAAAAAAAAAAAAAAAAAAAA",
      "pduId": "BBBBBBBBBBBBBBBBBBBBBB",
      "position": 1,
      "name": "Example outlet",
      "state": "unknown",
      "availableActions": []
    }
  ]
}
```

Unknown JSON fields are not part of the contract. During Stages 2 through 7, `availableActions` is always empty.

Responses use `Content-Type: application/json`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`. Full backend XML, session IDs, credentials, bearer tokens, raw row IDs, and Authorization values are never logged.

## Reserved outlet-action shape

The action request is reserved now so that later security and UI work can target one closed interface:

```json
{
  "action": "on",
  "inventoryRevision": "CCCCCCCCCCCCCCCCCCCCCC"
}
```

Rules:

- `action` is exactly `on`, `off`, or `cycle`.
- Both fields are mandatory and no other field is accepted.
- The raw body is limited to 1,024 bytes of UTF-8 JSON.
- Duplicate object names, malformed JSON, non-object roots, content encoding, and media types other than `application/json` are rejected.
- The outlet ID must match the opaque-ID format.
- `inventoryRevision` must match the current validated identity mapping before any later action can be considered.

**Stage 2 behavior is always `503 action_disabled`. No Avtrans request is constructed or sent.** Exact backend templates and success responses cannot be added until Stage 8 has separately approved, sanitized hardware evidence for each action. A later timeout after dispatch must become `action_outcome_unknown`; `cycle` must never be retried automatically.

## Error behavior

Every error response is a closed JSON object containing only:

```json
{
  "code": "bad_request",
  "message": "Request rejected."
}
```

The fixed error-code vocabulary is defined in OpenAPI. Important transport behavior:

- unknown route: `404 not_found`
- known route with wrong method: `405 method_not_allowed`
- unacceptable response media type: `406 not_acceptable`
- malformed/duplicate-field JSON: `400 bad_request`
- wrong request media type: `415 unsupported_media_type`
- body over 1,024 bytes: `413 payload_too_large`
- unknown current outlet ID: `404 not_found`
- stale inventory identity mapping: `409 inventory_stale`
- invalid or unavailable backend response: `502 backend_protocol_error` or `503 backend_unavailable`
- Stage 2 action request: `503 action_disabled`

Errors do not include backend XML, internal paths, session state, credentials, tokens, or appliance identifiers.

## Stage 2 completion gate

The contract is complete only while automated tests prove:

- the exact route/method allowlist;
- bearer authentication on every non-health route;
- closed object schemas and action enum;
- fixed read templates with no HTTP-controlled backend path;
- Stage 2 action rejection without a backend template;
- opaque ID formats and bounded input;
- absence of generic or PDU-wide management operations.

Stage 4 may implement only the health and read portions of this contract. Stage 8 is the first stage permitted to change action behavior, and only after explicit hardware approval.
