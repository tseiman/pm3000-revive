# REST API v1 contract

The machine-readable source is [`../api/openapi-v1.json`](../api/openapi-v1.json). It is authoritative for closed request/response schemas, limits, and errors.

## Routes

- `GET /api/v1/health`
- `POST|GET|DELETE /api/v1/session`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
- `POST /api/v1/outlets/{outletId}/actions`
- `GET|POST /api/v1/tokens`
- `POST /api/v1/tokens/{tokenId}/disable`
- `POST /api/v1/tokens/{tokenId}/enable`
- `DELETE /api/v1/tokens/{tokenId}`

There is no generic backend path, XML passthrough, token recovery, PDU-wide operation, reset, reboot, factory-default, or firmware-update route.

## Authentication boundaries

`GET /health` is unauthenticated local liveness and never contacts Avtrans.

Browser users create a server-side session with an existing PM3000 username and password. The adapter logs in through the observed GSP flow, reads rights-filtered navigation and topology controls, stores the GSP SID only in a mode-`0600` session file below a mode-`0700` directory, and returns a `Secure`, `HttpOnly`, `SameSite=Strict` cookie. Sessions expire after 15 idle minutes. Browser mutations require the matching `X-CSRF-Token`. Logout removes local state even when backend logout cannot be confirmed.

External API clients authenticate with `Authorization: Bearer`. Tokens have `read`, `control`, or `admin` scope and an optional outlet allowlist. Browser login never accepts a bearer token.

## Fixed outlet reads and opaque IDs

Outlet reads use only:

```text
action=get
path=units.topology
```

Raw controller row IDs are never exposed. For a validated UTF-8 backend identity, the adapter derives the outlet ID as:

```text
base64url(SHA-256("pm3000-rest-v1\0outlet\0" || backendRowId))[0:22]
```

PDU and inventory revisions use separate domain prefixes. Every detail lookup and action resolves the opaque ID against a fresh, validated topology. Duplicate, missing, malformed, oversized, ambiguous, or colliding identities fail closed.

## Outlet actions

Backend dispatch is currently disabled. The route retains its closed input, authentication, authorization, and CSRF boundary, but every otherwise valid request returns `503 action_contract_unverified` before opening the Avtrans socket.

The only request shape is:

```json
{
  "action": "on",
  "inventoryRevision": "CCCCCCCCCCCCCCCCCCCCCC"
}
```

Rules:

- `action` is exactly `on`, `off`, or `cycle`;
- both fields are required; unknown and duplicate fields are rejected;
- body limit is 1,024 bytes of UTF-8 JSON;
- bearer callers require `control` scope and allowlist membership;
- browser callers require a valid session, PM3000-derived power capability, and CSRF;
- no controller request is sent;
- observed topology controls use `targPowerOn`, `targPowerOff`, and `targCycle`, while plain `on`, `off`, and `cycle` belong to PDU/outlet detail tables;
- a sanitized browser-generated action request plus success/error responses must resolve path, table, action, row identity, and confirmation semantics before dispatch can be implemented;
- future actions must never be retried automatically, especially `cycle`.

## Token administration

Token list/create/enable/disable/revoke is local to the token store and never contacts Avtrans. Bearer callers require `admin`; browser callers require a PM3000 session whose returned navigation contains the conservative local-account-administration path plus CSRF for mutations.

- At most 128 records and 256 unique outlet IDs per allowlist.
- Omitted outlet list means unrestricted; an empty list denies every outlet.
- Only a new token's plaintext is returned, exactly once.
- Lists contain metadata only, never digest or plaintext.
- Disable retains the digest and metadata; revoke removes the record.
- The final enabled administrator cannot be disabled or revoked.
- Production persistence remains `/mnt/hdUser/pm3000-revive/rest/tokens.json` and is excluded from release installation and normal restore.

## Response and error behavior

All responses disable caching and content sniffing. Errors use a closed JSON object with `code` and `message` and never contain backend XML, GSP SIDs, cookies, credentials, bearer values, raw row IDs, or internal paths.

Important failures include malformed input, unsupported media type, oversized body, authentication/authorization denial, missing outlet, stale inventory, backend protocol/unavailability, unknown action outcome, final-administrator protection, token limit, and unavailable token storage. Exact status codes and the complete vocabulary are in OpenAPI.

## Writable settings

No generic settings route exists. A setting is added only after a sanitized real `get` response and matching `save` request prove the complete closed form, including server-generated and conditional fields. The known Network Settings form is deliberately deferred because its checkbox payload includes additional unobserved parameters; sending a partial form could remove state or make the appliance unreachable.
