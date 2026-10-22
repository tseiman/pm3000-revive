# Bearer-Token Store

This document defines the Stage 3 bearer-token model, persistent format, and host-side administration workflow. The machine-readable HTTP contract remains [`../api/openapi-v1.json`](../api/openapi-v1.json).

Stage 3 does **not** install software on a PM3000. `tools/token_store.py` is a host-tested reference implementation and persistence writer. `tools/token_admin.py` provisions and administers a store on a trusted host. The Stage 4 native adapter must reproduce these validation and authorization semantics before it may consume the store on the appliance.

## Persistent location and permissions

The planned appliance path is:

```text
/mnt/hdUser/pm3000-revive/rest/tokens.json
```

Required filesystem properties:

- the `rest` directory is a real, caller-owned directory with mode `0700` and is opened once with no-follow directory semantics;
- lock, store, temporary-file, replace, cleanup, and `fsync` operations remain relative to that verified directory descriptor;
- the configured path's ancestors must be trusted and must not be writable by an untrusted principal;
- `tokens.json` is a single-link regular, caller-owned file with mode `0600`;
- `tokens.json.lock` is a single-link regular, caller-owned file opened with `O_NOFOLLOW` and mode `0600`;
- a symlink, non-regular file, wrong owner, permissive mode, malformed document, unsupported schema version, or oversized document is rejected;
- the JSON document is limited to 128 KiB and 128 token records.

These limits are security boundaries, not tuning defaults.

## Token and identifier generation

A bearer token is:

```text
pm3_ + base64url-without-padding(32 random bytes)
```

The random portion therefore contains 256 bits of entropy and the complete token is exactly 47 ASCII characters. A token-record ID uses 16 independent random bytes and has the form:

```text
tok_ + base64url-without-padding(16 random bytes)
```

Bearer-token plaintext is never persisted. For a host command, the fully validated candidate credential is written and flushed exactly once to the caller's output channel before publication; only exit status `0` confirms normal publication, while exit status `3` means committed publication with uncertain directory durability. List operations never return plaintext, and plaintext must never appear in logs, command arguments, environment variables, URLs, captures, or repository files.

Authentication hashes the presented token and compares fixed-length hexadecimal digests with `hmac.compare_digest`. Opaque record IDs and digests are not credentials and do not grant authority by themselves.

## Closed persistent schema

The canonical document contains exactly:

```json
{
  "schemaVersion": 1,
  "generation": 1,
  "tokens": [
    {
      "id": "tok_AAAAAAAAAAAAAAAAAAAAAA",
      "label": "Initial administrator",
      "createdAt": "2026-10-20T12:00:00Z",
      "digest": "0000000000000000000000000000000000000000000000000000000000000000",
      "enabled": true,
      "scope": "admin",
      "outlets": null
    }
  ]
}
```

The digest above is a format illustration, not a usable credential. Unknown or duplicate JSON members are rejected. IDs and digests must be unique, and outlet IDs must be unique and sorted. An empty `tokens` array is valid: browser administration is authorized by the private PM3000 session rather than by a bearer token. Labels are immutable after creation, contain 1–64 visible characters, and are limited to 128 UTF-8 bytes.

`generation` increments on every committed mutation, is limited to the positive signed 64-bit range `1..2^63-1`, and fails closed before replacement on overflow. It is an internal persistence generation and is unrelated to the outlet `inventoryRevision`.

## Scope and outlet semantics

Scopes form this hierarchy:

- `read`: health-independent inventory and status reads;
- `control`: reserved authorization for individual-outlet actions; dispatch remains disabled until the controller contract is observed;
- `admin`: `control` plus token list/create/enable/disable/revoke operations.

`outlets` applies to every outlet-scoped read or action:

- `null`: unrestricted outlet set;
- `[]`: no outlet is authorized;
- a sorted array of opaque outlet IDs: only those outlets are authorized.

For collection reads, the adapter first authenticates `read` scope and then filters the returned collection to the token's allowlist; an empty list therefore returns no outlets. Detail reads and future actions require the requested opaque outlet ID to be a member. The core API deliberately separates `authorize_global()` from `authorize_outlet()` so a detail/action caller cannot omit this check.

An `admin` scope does not bypass its outlet allowlist. Token-administration routes require an enabled `admin` token but are not tied to an outlet.

## Disable, enable, and revoke

- Disable retains metadata and the digest but immediately denies authorization.
- Enable restores authorization using the existing digest.
- Revoke atomically removes both metadata and digest.
- An authenticated PM3000 browser administrator may disable or revoke every bearer token, including the final enabled bearer administrator.
- Bearer-authenticated administration retains final-administrator protection because a bearer client has no independent recovery identity.
- A disabled administrator cannot perform administration.

The runtime must reload or otherwise invalidate authorization state on each committed generation so disable and revoke take effect immediately.

## Atomic update protocol

Every mutation performs the following sequence while holding an exclusive advisory lock:

1. open and validate the private directory and lock file with no-follow semantics;
2. retain that directory descriptor for the complete transaction;
3. load and fully validate the existing store;
4. apply one closed mutation in memory and validate the complete candidate;
5. for a credential-issuing CLI operation, write and flush the one-time credential through the supplied delivery callback while the lock is still held;
6. create a mode-`0600`, single-link temporary regular file in the same directory;
7. write all bytes and `fsync` the temporary file;
8. atomically replace `tokens.json` relative to the retained directory descriptor;
9. `fsync` that directory descriptor.

The verified parent directory is also `fsync`ed before each transaction, covering both initial directory creation and a retry after an earlier parent-sync failure.

A delivery failure occurs before replacement and therefore leaves the previous store byte-for-byte intact; no unknown enabled credential is published. If delivery succeeds but a later pre-replacement persistence step fails, the command exits nonzero and the already displayed token is not valid and must be discarded. A failure after replacement means the new generation is visible, but crash durability could not be confirmed. For bootstrap/create this is reported as `IssuedTokenDurabilityError`; other mutations use `CommittedDurabilityError`. Callers must inspect the exit status and must not blindly retry.

## Host-side command

All paths are explicit and absolute. Bootstrap is an optional host-side way to create the first bearer credential when no store object exists; the browser WebUI does not require it:

```bash
python3 modern-WebUI/tools/token_admin.py bootstrap \
  --store /absolute/staging/path/tokens.json \
  --label 'Initial administrator'
```

The command writes and flushes one compact JSON object containing the initial plaintext token before publishing its digest. Transfer that value directly into an approved secret manager; do not redirect it into repository or deployment files. Exit `0` confirms normal publication. Exit `3` means the digest was committed but directory durability is uncertain; the token has already been emitted once, a token-free warning is written to standard error, and the operator must preserve the credential, inspect the store, and not blindly retry. Any other nonzero exit means the displayed candidate was not published and must be discarded. If stdout itself fails, no credential record is published.

Subsequent commands are:

```text
create  --store PATH --label LABEL --scope read|control|admin [--outlet OUTLET_ID ...]
list    --store PATH
disable --store PATH --id TOKEN_RECORD_ID
enable  --store PATH --id TOKEN_RECORD_ID
revoke  --store PATH --id TOKEN_RECORD_ID
```

They read the administrator bearer token from a hidden TTY prompt. For controlled non-interactive use they read exactly one line from standard input. The bearer token is deliberately unavailable as a command-line option or environment-variable interface.

Omitting every `--outlet` grants an unrestricted outlet set. The HTTP API can represent an explicit empty allowlist; the host command intentionally does not provide an accidental shorthand for that unusual case.

## HTTP administration boundary

The Stage 3 contract adds only:

```text
GET    /api/v1/tokens
POST   /api/v1/tokens
POST   /api/v1/tokens/{tokenId}/disable
POST   /api/v1/tokens/{tokenId}/enable
DELETE /api/v1/tokens/{tokenId}
```

Every operation requires either an enabled bearer `admin` or a private PM3000 browser session with the server-derived token-management right. Token administration uses the token store only and must never construct an Avtrans request. There is no HTTP bootstrap route, generic token patch, digest export, plaintext-token list, or token recovery route. A permitted browser session can create a new bearer token from an empty store.
