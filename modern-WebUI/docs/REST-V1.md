# REST API v1 contract

The machine-readable source is [`../api/openapi-v1.json`](../api/openapi-v1.json). It is authoritative for closed request/response schemas, limits, and errors.

## Routes

- `GET /api/v1/health`
- `POST|GET|DELETE /api/v1/session`
- `POST /api/v1/session/password`
- `GET|PUT /api/v1/settings/security/dsview`
- `GET|PUT /api/v1/settings/authentication/nis`
- `GET|PUT /api/v1/settings/help-language`
- `GET|PUT /api/v1/settings/data-buffering`
- `GET|PUT /api/v1/settings/appliance-logging`
- `GET|PUT /api/v1/settings/time-zone`
- `GET /api/v1/system/information`
- `GET /api/v1/system/usage/memory`
- `GET /api/v1/system/usage/flash`
- `GET /api/v1/monitoring/network/devices`
- `GET /api/v1/monitoring/network/routes/ipv4`
- `GET /api/v1/monitoring/network/routes/ipv6`
- `GET /api/v1/monitoring/serial-ports`
- `GET /api/v1/outlets`
- `GET /api/v1/outlets/{outletId}`
- `POST /api/v1/outlets/{outletId}/actions`
- `GET /api/v1/pdus`
- `POST /api/v1/pdus/{pduId}/actions`
- `GET|POST /api/v1/tokens`
- `POST /api/v1/tokens/{tokenId}/disable`
- `POST /api/v1/tokens/{tokenId}/enable`
- `DELETE /api/v1/tokens/{tokenId}`

There is no generic backend path, XML passthrough, token recovery, reset, reboot, factory-default, or firmware-update route.

## Authentication boundaries

`GET /api/v1/health` is unauthenticated local liveness and never contacts Avtrans.

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

## Outlet and PDU actions

Outlet actions map public `on`, `off`, and `cycle` to firmware controls `targPowerOn`, `targPowerOff`, and `targCycle` at `units.topology` / `topologyTable`. PDU actions use firmware controls `on`, `off`, and `cycle` at `units.powermanagement.pdu_management` / `pdu_devices_table`.

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
- outlet bearer callers require `control` scope and allowlist membership;
- PDU bearer callers require `control` scope and an unrestricted outlet policy;
- browser callers require a valid session, PM3000-derived power capability, and CSRF;
- the supplied opaque ID is resolved against a fresh validated inventory; raw controller row IDs are never accepted;
- the revision supplied by the client must match the fresh inventory;
- `on` and `off` succeed only when a validated operation-specific inventory response reports the targeted outlet or PDU in the requested state;
- `cycle` has no stable read-back state and therefore returns `action_outcome_unknown` after dispatch; clients must not retry it automatically;
- any malformed, unrelated, mismatching, or failed response after dispatch likewise returns `action_outcome_unknown` and is never retried automatically.

## Password change

`POST /api/v1/session/password` accepts only the closed object `oldPassword`, `newPassword`, and `confirmation`. It is available only to a browser PM3000 session with the concrete `units.change_password` navigation right and matching CSRF token; bearer authentication is rejected. Confirmation mismatch is rejected before backend contact. Success requires the exact firmware-derived `changedPassword` / `infoForm` / title / notice hierarchy; an unrelated or empty payload is an unknown outcome. Password values are not logged or stored and are cleared from browser buffers and through non-optimizable native wiping after use.

## Typed settings

`/api/v1/settings/security/dsview` is a complete boolean resource with the sole field `allowDSView`. `/api/v1/settings/authentication/nis` is a complete two-field resource with required `domainName` and `address` printable-ASCII strings of at most 99 bytes. `/api/v1/settings/help-language` completely replaces `applianceLanguage` and `url`; the language must be one of the freshly validated backend choices. `/api/v1/settings/data-buffering` completely replaces all seven local, NFS, and syslog fields and restricts the facility to `LOG_LOCAL0` through `LOG_LOCAL5`.

`/api/v1/settings/appliance-logging` is a closed conditional replacement. A disabled request contains only `sessionLoggingEnabled: false`. An enabled request also contains `destination`, `timestampEnabled`, and `alertsEnabled`; exactly ten alert strings are required only while alerts are enabled. The destination is one of `local`, `nfs`, `syslog`, or `dsview`, and each alert string is at most 64 UTF-8 bytes. Inactive descendants are omitted from the firmware save and their freshly read values must remain unchanged in the typed post-save response. The setting affects newly opened sessions; a successful response confirms the stored configuration, not behavior of already active sessions. Unknown, duplicate, missing, oversized, incorrectly typed, or conditionally forbidden members are rejected before Avtrans.

`/api/v1/settings/time-zone` is a closed conditional replacement. Predefined mode submits one zone selected from the freshly validated, firmware-supplied list. Custom mode submits the name, standard acronym, GMT offset, and an explicit DST object; DST transition fields are required only when DST is enabled. Inactive values are omitted from the firmware save but must remain unchanged in the exact typed read-back. A successful backend read confirms configuration values only; it does not prove `/etc/localtime`, `dotz.sh`, service-hook, scheduler, certificate, log-timestamp, or runtime-clock effects.

These settings endpoints are browser-session-only: they reject an Authorization header, require their exact PM3000 navigation path and CSRF for PUT, and never map a REST bearer scope onto a PM3000 configuration right. DSView and NIS GETs validate their required response path, form, and unique parameter values. The revisioned Help and Language, Data Buffering, Appliance Logging, and Time Zone GETs additionally validate the complete fixed-form document grammar, controls, parameter declarations, hierarchy, choices, and unique values. Those revisioned resources return a quoted strong revision in the response and `ETag`; PUT requires the same value in `If-Match` and refreshes the backend state before dispatch. Writes use a private nonblocking cross-process lock; unsafe lock metadata or contention returns `503 backend_unavailable` before backend access. PUT emits fixed `save` requests in firmware field order and returns success only after exact typed read-back of active submitted fields and any preserved inactive state; any mismatch, missing value, duplicate, or dispatch uncertainty returns `action_outcome_unknown` and is never retried automatically.

## Session-only system and monitoring reads

The seven system and monitoring routes are cookie-session-only and reject bearer authentication before backend access. They require the matching PM3000 navigation capability and project only closed, bounded fields. They never expose GSP SIDs, backend paths or IDs, raw XML, mutation controls, hidden parameters, or the appliance serial number. Transport failures return `backend_unavailable`; malformed or ambiguous controller responses return `backend_protocol_error`.

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

## Further writable settings

No generic settings route exists. Offline firmware analysis identified fixed and dynamic form families. Each additional fixed operation must become a typed or compile-time-allowlisted route with exact path, action, form structure, validation, permission, and response semantics. Dynamic row/form families remain deferred until a fresh GET can unambiguously select and preserve every required value.
