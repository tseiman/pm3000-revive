# Legacy menu capability cross-check

## Scope and evidence

This document compares the firmware 2.0.1.23 navigation model with the compact modern WebUI. It is based only on offline evidence:

- the sanitized observed navigation response;
- sanitized topology and PDU inventory responses;
- the extracted static `avrel.xml`, legacy XSL/JavaScript serializer, and `nav-cardId.properties`;
- the extracted CACPD feature-module contracts;
- the current REST API, native adapter, and browser client.

No appliance or legacy WebUI request was made while producing this cross-check. No firmware binary was executed.

The observed navigation contains 58 `units.*` paths: 15 grouping nodes and 43 actionable leaf pages visible in the supplied screenshot. The modern client renders every authorized allowlisted path using hard-coded labels. Only `units.topology` has a corresponding native capability: read-only outlet inventory. `units.powermanagement.pdu_management` is temporarily aliased to that outlet view but has no PDU API, projector, or native page and is therefore not implemented. Every other visible legacy leaf opens a local placeholder. The legacy UI remains separately available at `/`.

## Classification

- **Implemented**: modern UI and native REST behavior exist.
- **Read candidate**: fixed `get` path and static response schema are available; a strict, field-specific projector can be implemented offline. Real-device validation would still be required before release.
- **Write candidate after fixture**: static evidence proves the action and field family, but a sanitized real `get` plus matching mutation is required to preserve runtime-generated, hidden, conditional, or row-identity state.
- **Structurally bounded write candidate**: static evidence bounds a possible serializer, but observed request and success/error response fixtures are still mandatory before dispatch can be enabled.
- **Excluded**: intentionally outside project scope.

A known CACPD `set`, `admin`, `add`, or `del` verb is not by itself permission to expose a write API. The browser contract must also have a closed action, path, complete payload, validation, authorization gate, and unambiguous response parser.

## Menu matrix

### Access and power management

- **Access** — `units.topology`
  - **Current:** Implemented read view. `on`, `off`, and `cycle` request input is validated, but browser controls and backend dispatch are disabled.
  - **Evidence:** the observed topology response proves row identities and controls, but its action IDs are `targPowerOn`, `targPowerOff`, and `targCycle`. Plain `on`, `off`, and `cycle` occur on the observed PDU page and firmware-defined detail tables, so they cannot be inferred as the topology outlet-action contract. No action request or response was observed.
  - **Not implemented:** serial viewer and outlet `lock`/`unlock`.
  - **Decision:** keep `lock`/`unlock` deferred until explicitly requested and captured; serial viewer is not suitable for the compact REST UI without a separately designed streaming boundary.

- **System Tools** — `units.overview`
  - **Current:** Placeholder.
  - **Static contract:** reboot, shutdown, factory default, configuration save/restore, viewer launch, and firmware workflow.
  - **Decision:** firmware is excluded. Reboot, shutdown, factory default, restore, and viewer launch remain deferred because they are destructive, stateful, or require dynamic multi-step/session contracts. A configuration-download function may be considered separately after a sanitized request/response fixture.

- **PDUs** — `units.powermanagement.pdu_management`
  - **Current:** Not implemented. The menu is temporarily aliased to the implemented Access/outlet inventory view; there is no `/api/v1/pdus` route, PDU-response projector, or native PDU page.
  - **Not implemented:** PDU rename, PDU-wide power, reset, factory default, PDU firmware, detailed current/voltage/phase/circuit/environment pages, or threshold settings.
  - **Decision:** the observed sanitized PDU GET request/response makes model/status/current/power/alarm the safest next implementation. Do not expose the hidden `thresholds` value or backend row ID. Every mutation requires runtime path/row and response fixtures. Firmware remains excluded.

- **Power Settings** — `units.powermanagement.powerprofile_login`
  - **Current:** Placeholder.
  - **Static schema:** polling, chain, login, and data-logging settings plus hidden state fields.
  - **Decision:** read candidate; writes require a sanitized complete form pair.

- **Outlet Groups** — `units.powermanagement.outlet_groups`
  - **Current:** Placeholder.
  - **Static schema:** group name, status, outlets, and power consumption; add/details paths exist.
  - **Decision:** list is a read candidate. Group CRUD and group power require runtime row/membership fixtures.

- **Data Logging** — `units.powermanagement.data_logging`
  - **Current:** Placeholder.
  - **Static schema:** export type and last-store status; clear and export actions exist.
  - **Decision:** status is a read candidate. Clear/export remain deferred until complete action/response fixtures exist.

### System

- **Security Profile** — `units.applianceSettings.security.SecurityProfileNav`
  - **Current:** Placeholder.
  - **Static schema:** session timeout, services, outlet authorization, BOOTP, profile and hidden state fields.
  - **Decision:** read candidate with sensitive-field filtering; writes require a complete form pair because service/profile choices can alter remote access.

- **DSView** — `units.applianceSettings.security.SecurityDSView`
  - **Current:** Placeholder.
  - **Static schema:** DSView control form.
  - **Decision:** read candidate; write requires a complete form pair and explicit remote-management risk review.

- **Date and Time** — `units.applianceSettings.date_and_time.date_time`
  - **Current:** Placeholder.
  - **Static contract:** time read plus manual/date-source administration.
  - **Decision:** read candidate. Setting time can affect logs, certificates, sessions, and authentication; capture a complete form/action pair before write support.

- **Time Zone** — `units.applianceSettings.date_and_time.time_zone`
  - **Current:** Placeholder.
  - **Static contract:** timezone list/custom timezone and save behavior.
  - **Decision:** read candidate; write requires a complete form pair.

- **Help and Language** — `units.applianceSettings.help`
  - **Current:** Placeholder.
  - **Static schema:** appliance language and help URL.
  - **Decision:** read candidate. Language is a plausible narrow write candidate after one sanitized save fixture.

- **Boot Configuration** — `units.applianceSettings.bootconfiguration`
  - **Current:** Placeholder.
  - **Static schema:** boot configuration, watchdog, baud rate, Ethernet mode, and notice fields.
  - **Decision:** read candidate only for now. Writes can impair boot or management access and require a complete form pair.

- **Information** — `units.applianceSettings.information`
  - **Current:** Placeholder.
  - **Static schema:** identity, firmware version, and CPU information.
  - **Decision:** high-priority read candidate.

- **Memory** — `units.applianceSettings.usage.memory`
  - **Current:** Placeholder.
  - **Static schema:** read-only memory table.
  - **Decision:** high-priority read candidate.

- **Flash Usage** — `units.applianceSettings.usage.flashUsage`
  - **Current:** Placeholder.
  - **Static schema:** read-only flash-usage table.
  - **Decision:** high-priority read candidate.

### Network

- **Network Settings** — `units.network.networkSettings`
  - **Current:** Placeholder.
  - **Static contract:** `save`; hostname, primary/secondary DNS, domain, IPv6 enablement, DHCPv6 DNS/domain and nested/hidden state.
  - **Decision:** read candidate. Do not construct a partial write: it could erase omitted state or make the appliance unreachable. A sanitized complete `get`/`save` pair is mandatory.

- **Network Devices** — `units.network.devices`
  - **Current:** Placeholder.
  - **Static schema:** device/status list and dynamic device-details pages.
  - **Decision:** device list is a high-priority read candidate. Device writes require detail-path and full-form fixtures.

- **IPv4 Static Routes** — `units.network.ipv4_st_routes`
  - **Current:** Placeholder.
  - **Static schema:** destination/mask, gateway, device, metric; add/delete/detail flows.
  - **Decision:** list is a read candidate. CRUD requires runtime row IDs and complete detail/add fixtures.

- **IPv6 Static Routes** — `units.network.ipv6_st_routes`
  - **Current:** Placeholder.
  - **Static schema:** destination/prefix, gateway, interface, metric; add/delete/detail flows.
  - **Decision:** list is a read candidate. CRUD requires runtime row IDs and complete detail/add fixtures.

- **Hosts** — `units.network.hosts`
  - **Current:** Placeholder.
  - **Static schema:** host IP, name, aliases; add/delete/detail flows.
  - **Decision:** list is a read candidate. CRUD requires runtime row IDs and complete detail/add fixtures.

- **IPv4 Filter Table** — `units.network.firewall.filter4Table`
- **IPv6 Filter Table** — `units.network.firewall.filter6Table`
  - **Current:** Placeholders.
  - **Static contract:** chain/rule list, add, delete, policy, reorder, and conditional rule forms.
  - **Decision:** read-only chain/rule projection is possible. Writes remain fixture-gated because conditional protocol branches and ordering/policy operations are lockout-sensitive.

- **SNMP** — `units.network.SNMP`
  - **Current:** Placeholder.
  - **Static schema:** principal/community/user rows, versions, source, OID, permission, system contact/location, and collection CRUD.
  - **Decision:** filtered read candidate. Never return communities, authentication/privacy keys, or password-like values. Writes require complete version-specific fixtures.

### Authentication

- **Appliance Authentication** — `units.authentication.unit_authentication`
- **RADIUS** — `units.authentication.authenticationservers.radius`
- **TACACS+** — `units.authentication.authenticationservers.Tacacsplus`
- **LDAP(S)/AD** — `units.authentication.authenticationservers.ldap_ad`
- **Kerberos** — `units.authentication.authenticationservers.kerberos`
- **NIS** — `units.authentication.authenticationservers.nis`
- **DSView server** — `units.authentication.authenticationservers.dsviewsrv`
  - **Current:** All placeholders.
  - **Static contract:** fixed `save` paths and backend schemas are known. RADIUS, TACACS+, and LDAP include secrets, confirmations, conditional mappings, or hidden state.
  - **Decision:** a redacted read summary is possible. No secret value may be returned. Writes remain fixture-gated because an incomplete mutation can lock out all administrators; secret fields must use explicit keep/replace semantics.

### Users and authorization

- **User Names** — `units.users.local_accounts.user_names`
  - **Current:** The path is used only as a conservative capability gate for REST token administration; the actual PM3000 user list/CRUD is not implemented.
  - **Static contract:** user table; add, edit, delete; groups, password, force-change, and account/password aging fields.
  - **Decision:** user list is a read candidate. CRUD requires runtime row IDs, full add/edit fixtures, reserved-account protection, and a last-administrator safeguard.

- **Password Rules** — `units.users.local_accounts.password_rules`
  - **Current:** Placeholder.
  - **Static contract:** enabled, minimum digits/uppercase/special/length, minimum/maximum age, and warning days.
  - **Decision:** read candidate. The field set appears bounded, but one complete `get`/`save` pair is still required before mutation to confirm grouped and hidden form state.

- **Groups** — `units.users.authorization.authorgroups`
  - **Current:** Placeholder.
  - **Static contract:** group list and authorization CRUD/membership.
  - **Decision:** list is a read candidate. Writes require runtime row IDs, complete permission-tree fixtures, and last-admin/lockout safeguards.

### Events, logging, and sessions

- **Event List** — `units.event_notification.events`
  - **Current:** Placeholder.
  - **Static schema:** event number/description and trap/syslog/DSView/email/SMS selections, including multi-edit.
  - **Decision:** list is a read candidate. Writes require complete single- and multi-edit fixtures.

- **Event Destinations** — `units.event_notification.settings`
  - **Current:** Placeholder.
  - **Static schema:** syslog, SNMP trap, SMS, email, and DSView destination groups.
  - **Decision:** redacted read candidate. Writes require complete forms; credentials and shared secrets must never be reflected.

- **Data Buffering** — `units.event_notification.global_settings_databuffering`
  - **Current:** Placeholder.
  - **Static schema:** local, NFS, and syslog buffering configuration.
  - **Decision:** redacted read candidate; writes require a complete form pair.

- **Appliance Logging** — `units.event_notification.sessions`
  - **Current:** Placeholder.
  - **Static schema:** session/logging configuration.
  - **Decision:** read candidate; writes require a complete form pair.

- **Active Sessions** — `units.activeSessions`
  - **Current:** Placeholder.
  - **Static schema:** user, client IP, creation time, session/connection type, and session ID; backend supports session kill.
  - **Decision:** high-priority read candidate with session IDs represented as opaque transient IDs. Kill requires a fresh list, exact row resolution, self-session protection, confirmation, and a captured request/response pair.

### Monitoring

- **Monitoring / Devices** — `units.monitoring.networkmon.monitoringDevice`
- **Monitoring / IPv4 Routing Table** — `units.monitoring.networkmon.monitoringIpv4RouteTable`
- **Monitoring / IPv6 Routing Table** — `units.monitoring.networkmon.monitoringIpv6RouteTable`
- **Monitoring / Serial Ports** — `units.monitoring.serialstatistics`
  - **Current:** All placeholders.
  - **Static schema:** read-only network device/route tables and serial port profile, speed, signals, byte counters, framing/parity/break/overrun counters.
  - **Decision:** highest-priority missing read-only capability set.

### Current-user password

- **Change Password** — `units.change_password`
  - **Current:** Placeholder.
  - **Static contract:** `save` with `oldpassword`, `newpassword`, and `confirmpassword`.
  - **Decision:** this is structurally narrow but not yet enableable. It still requires sanitized request and success/error responses, a structural parser, memory clearing, no logging, CSRF/session binding, and a controlled user-run device test. A password change must not silently leave the browser session in an ambiguous state.

## Prioritized implementation conclusion

### Tier 0: implement the observed PDU status page

Implement `GET /api/v1/pdus` and `GET /api/v1/pdus/{pduId}` from the existing sanitized `pdu-management-get-request.xml` and `pdu-management-get-response.xml`. Project only an opaque PDU ID, vendor/model, position, outlet count/status, current, power, and raw alarm state. Do not expose `thresholds`, raw row IDs, or paths. Initially allow browser sessions with the exact navigation capability and unrestricted bearer `read`; outlet-limited tokens must receive `403` because aggregate PDU values may cover disallowed outlets.

### Tier 1: firmware-derived read-only expansion

Implement fixed, field-specific read endpoints and modern views. Proposed narrow REST boundaries are:

- `GET /api/v1/system/information` — appliance identity, firmware, and CPU summary;
- `GET /api/v1/system/usage/memory` — bounded memory rows;
- `GET /api/v1/system/usage/flash` — bounded flash rows;
- `GET /api/v1/monitoring/network/devices` — live device status;
- `GET /api/v1/monitoring/network/routes/ipv4` and `/ipv6` — live routing tables;
- `GET /api/v1/monitoring/serial-ports` — serial status and error counters;
- `GET /api/v1/network/devices`, `/routes/ipv4`, `/routes/ipv6`, and `/hosts` — configured network inventory;
- `GET /api/v1/outlet-groups` — group status and membership summary;
- `GET /api/v1/events` and `/power-data-logging/status` — event policy and logging status.

These endpoints must not expose raw Avtrans XML. Each endpoint must use a fixed backend path, strict structural parser, bounded arrays/strings, explicit field allowlist, and backend/session authorization. Unknown or duplicate fields fail closed where they affect identity; harmless unsupported display fields may be omitted. Configured and live monitoring routes remain separate because they have different backend paths and semantics.

Start firmware-derived system and monitoring endpoints as cookie-authenticated browser routes. The current bearer `read` scope must not silently grant access to serial numbers, IP topology, routes, filesystems, or serial-port activity.

### Tier 2: sensitive read

Implement active-session viewing only after a sanitized GET fixture establishes practical row bounds. Do not expose raw backend session IDs.

### Writes: none currently enableable

The next low-blast-radius candidate is PDU rename, followed by current-user password change or language selection. Each still requires its own sanitized GET/mutation/success/error fixture set. No existing static form definition alone is sufficient to enable dispatch.

### Tier 3: configuration CRUD only after matched fixtures

Network, firewall, SNMP, authentication servers, users/groups, event destinations, buffering, boot/security, route/host CRUD, active-session kill, and all PDU-wide mutations require sanitized matching `get` and mutation fixtures before implementation.

### Permanently excluded or separately designed

- appliance and PDU firmware upgrade;
- generic Avtrans proxying;
- guessed runtime paths or row IDs;
- partial form saves;
- automatic destructive retries;
- factory reset, restore, reboot, or shutdown without a separately approved and tested operational design;
- serial viewer tunneling without a dedicated authenticated streaming design.

## Minimum evidence capture

For every future write page, capture without replaying or modifying it:

1. sanitized `get` request and response;
2. sanitized browser-generated mutation request;
3. sanitized success response;
4. sanitized validation or authorization failure response;
5. all conditional variants that change serialized fields;
6. runtime table row IDs and drilldown path variables where applicable.

Promote only manually reviewed sanitized fixtures into the repository. Keep raw captures and all credentials outside Git.
