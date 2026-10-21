# Deferred improvements

This file records deliberately deferred work that is not required for the compact, safe core release.

## Requires controlled PM3000 fixtures

- **Writable Network Settings page:** firmware evidence proves the `save` action, path `units.network.networkSettings`, and primary fields (`hostname`, `primarydns`, `secondarydns`, `domain`, `enableIpv6`, `dhcpv6-dns`, `dhcpv6-domain`). A sanitized real `get` response and matching browser `save` request are still required because checkbox sections contain additional server-generated parameters. Do not issue a partial save: it may remove hidden state or make the appliance unreachable.
- **Additional writable settings:** capture one sanitized `get`/`save` pair per page before implementing a closed serializer. Never add a generic Avtrans proxy.
- **Power action confirmation:** offline fixtures prove the path, table, row resolution, actions, CSRF and rights gates. Confirm `on`, `off`, and `cycle` one at a time on a designated test outlet before production use.
- **Navigation capability comparison:** compare the modern fixed allowlist with at least one administrator and one restricted PM3000 account.

## Non-critical UI improvements

- Add localized labels after the appliance-language contract is observed.
- Add modern read/write forms for settings only after their closed contracts are captured.
- Replace the legacy fallback links incrementally; keep `/` available throughout migration.
- Improve compact/mobile navigation for accounts with many authorized legacy pages.

## Explicitly out of scope

- Firmware upload or upgrade.
- Automatic rollback.
- Browser login with REST bearer tokens.
- A second user or role database.
