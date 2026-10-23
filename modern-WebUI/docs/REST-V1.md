# PM3000 REST API v1

This guide focuses on the common use case: reading outlets and switching one outlet by its configured name or opaque ID.

For the complete machine-readable contract, see [`../api/openapi-v1.json`](../api/openapi-v1.json).

## Quick start

```sh
BASE_URL='https://pdu1.tsei.mdn'
TOKEN='***'
```

Use a bearer token with at least:

- `read` for inventory reads;
- `control` for outlet actions;
- `admin` for token administration.

## List outlets

```sh
curl --silent --show-error \
  --header "Authorization: Bearer ${TOKEN}" \
  "${BASE_URL}/api/v1/outlets" | jq .
```

The response contains each outlet's configured `name`, opaque `id`, current state, and the current `inventoryRevision`.

## Switch an outlet by name

> **WARNING:** This request performs a real power action on the selected outlet.

```sh
OUTLET='Exact configured outlet name'
ACTION='on' # on, off, or cycle

jq -n \
  --arg outlet "${OUTLET}" \
  --arg action "${ACTION}" \
  '{outlet: $outlet, action: $action}' |
curl --silent --show-error \
  --request POST \
  --header "Authorization: Bearer ${TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  --write-out '\nHTTP %{http_code}\n' \
  "${BASE_URL}/api/v1/outlets/actions"
```

Names are matched exactly and case-sensitively against fresh controller topology:

- no match returns `404 not_found`;
- duplicate names return `409 outlet_name_ambiguous`;
- the server never selects the first duplicate;
- authorization is checked against the resolved canonical outlet ID.

Using unique outlet names is strongly recommended.

## Switch an outlet by ID

The same simple endpoint also accepts an opaque ID:

> **WARNING:** This request performs a real power action on the selected outlet.

```sh
OUTLET='P-S7acky22zPPlk8ZcHLYP'
ACTION='on'

jq -n \
  --arg outlet "${OUTLET}" \
  --arg action "${ACTION}" \
  '{outlet: $outlet, action: $action}' |
curl --silent --show-error \
  --request POST \
  --header "Authorization: Bearer ${TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  --write-out '\nHTTP %{http_code}\n' \
  "${BASE_URL}/api/v1/outlets/actions"
```

The existing ID-in-path endpoint remains supported for compatibility:

```http
POST /api/v1/outlets/{outletId}/actions
```

## Optional inventory revision

Simple outlet actions do not require `inventoryRevision`.

To request optimistic concurrency checking, add the revision returned by the latest inventory read:

> **WARNING:** This request performs a real power action on the selected outlet.

```sh
REVISION='58rBFGeIs5tfugCUdsDhsY'

jq -n \
  --arg outlet "${OUTLET}" \
  --arg action "${ACTION}" \
  --arg revision "${REVISION}" \
  '{outlet: $outlet, action: $action, inventoryRevision: $revision}' |
curl --silent --show-error \
  --request POST \
  --header "Authorization: Bearer ${TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  --write-out '\nHTTP %{http_code}\n' \
  "${BASE_URL}/api/v1/outlets/actions"
```

A stale supplied revision returns `409 inventory_changed`. PDU-wide actions remain revision-protected and still require `inventoryRevision`.

## Important action result

If an action returns:

```text
503 action_outcome_unknown
```

the action may already have reached the controller. **Never retry it automatically.** Refresh the outlet inventory and verify the current state first.

## Other supported endpoints

Only a short overview is provided here; use OpenAPI for full schemas and response details.

- Health: `GET /api/v1/health`
- Outlet reads: `GET /api/v1/outlets`, `GET /api/v1/outlets/{outletId}`
- PDU inventory/action: `GET /api/v1/pdus`, `POST /api/v1/pdus/{pduId}/actions`
- Token administration: `/api/v1/tokens` and `/api/v1/tokens/{tokenId}`
- Browser session/password: `/api/v1/session`, `/api/v1/session/password`
- Appliance settings: `/api/v1/settings/*`
- System information and monitoring: `/api/v1/system/*`, `/api/v1/monitoring/*`

Bearer tokens are intended for external API clients. Browser-only operations use a secure session cookie and CSRF token; the built-in WebUI handles these automatically.

## Common errors

- `400 bad_request`: malformed or unsupported JSON
- `401 unauthorized`: missing or rejected authentication
- `403 forbidden`: missing scope, permission, CSRF token, or canonical outlet-ID authorization
- `404 not_found`: outlet ID/name not found
- `409 inventory_changed`: supplied revision is stale
- `409 outlet_name_ambiguous`: name is not unique
- `503 controller_service_user_unavailable`: local `pm3000-rest` controller account is unavailable
- `503 backend_unavailable`: controller operation did not complete
- `503 action_outcome_unknown`: action may have been dispatched; never retry automatically

## API version

No new API major version is required. The name-or-ID action route is additive, and existing `/api/v1` clients remain compatible. OpenAPI contract version `1.7.0` documents this extension.

## Not provided

The REST API intentionally does not provide arbitrary controller commands, generic XML/form passthrough, shell execution, firmware update, reboot, factory reset, or batch power actions.
