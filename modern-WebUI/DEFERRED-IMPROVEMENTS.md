# Deferred improvements

This file records work intentionally left outside the currently implemented, narrow contracts.

## Statically classified but not yet implemented

- The full offline mutation inventory is summarized in `docs/MENU-CAPABILITY-CROSSCHECK.md`. Of the 20 fixed `COMPLETE_STATIC` settings contracts, DSView security, NIS, Help and Language, and Data Buffering are now implemented; the other 16 fixed settings and 10 fixed create/save flows remain.
- Implement each fixed contract as a separate typed REST operation or a compile-time allowlisted schema entry. Never expose a client-selected Avtrans path, action, form ID, parameter structure, or raw XML body.
- Settings that preserve hidden, conditional, or server-generated state must begin with a fresh GET and carry forward only fields allowed by the exact firmware contract. Reject ambiguous variants rather than submitting a partial form.

## Requires runtime object/form resolution

The following families have dynamic row IDs, drilldown `pathvar` values, memberships, or model-specific forms. They remain blocked until a fresh GET can unambiguously select the concrete contract and preserve all required state:

- PDU model-specific configuration and thresholds.
- Outlet-group membership and group CRUD.
- Device-detail, route, host, firewall-rule, SNMP-entry, user, group, event, and active-session mutations.
- Any edit/delete action whose target depends on a selected runtime table row.

A generic Avtrans write proxy is prohibited.

## Requires controlled PM3000 response fixtures

- Outlet and PDU request contracts are implemented from closed static maps. `on`/`off` require operation-specific state confirmation; `cycle` remains an unknown outcome after dispatch because no stable read-back state exists. Password change requires the exact statically derived success-form hierarchy. Before Stage 10 cutover or any device-validated product release, capture sanitized successful, validation-error, authorization-error, pending-warning, and cycle responses during an explicitly approved device test to validate these response semantics empirically.
- Compare modern navigation and action availability with at least one administrator and one restricted PM3000 account.

## Non-critical UI improvements

- Add localized labels after the appliance-language behavior is validated on a real device.
- Replace legacy fallback pages incrementally as typed settings endpoints become available.
- Improve compact/mobile navigation for accounts with many authorized legacy pages.

## Explicitly out of scope

- Setup wizard.
- Firmware upload or upgrade.
- Reboot, shutdown, hardware reset, factory default, and automatic configuration restore.
- Automatic rollback.
- Browser login with REST bearer tokens.
- A second user or role database.
