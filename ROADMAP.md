# Roadmap

Development proceeds in small, independently testable milestones.

## Completed foundation

- Reproducible PPC32 big-endian e300c3 cross-toolchain
- Static Dropbear server and key generator
- Host-side ELF, QEMU-user, and isolated SSH verification
- Reported PM3000 hardware validation of the current Dropbear build, including port 22, classic SCP, and SysV startup after reboot
- Two-phase installer with isolated host-side state-transition and rollback simulation
- Backup-first modern-WebUI deployment tooling with an installed read-only `0.1` pilot
- PM3000-backed browser sessions and local REST-token administration
- Typed outlet/PDU inventory, fixed power actions, password change, and DSView/NIS settings
- Stage 9 milestone 1 system/monitoring reads
- Stage 9 milestone 2A fixed-form foundation plus Help and Language and Data Buffering settings

## Next milestones

1. **Installer device acceptance**
   - Run the packaged two-phase installer on a PM3000 using its single port-2222 test and confirmed port-22 activation.
   - Confirm installer preflight, idempotent reruns, rollback, resource use, startup fallback, and a separately approved reboot.
2. **Firmware inventory**
   - Document boot flow, partitions, root filesystem, update container, checksums/signatures, persistent data, and recovery paths.
   - Build read-only extraction and inspection tools before any image writer.
3. **Modern WebUI Stage 9 continuation**
   - Implement milestone 2B low-risk typed settings, then bounded static create/save flows, runtime-resolved CRUD, and parity closure.
   - Preserve Apache and the vendor `mod_avtrans -> uicontrold -> GSP/CACPD -> power API` authorization path; never add a generic backend write proxy.
4. **Controlled modern-WebUI device validation**
   - Validate current writes only through explicit maintenance-window approval, backup, rollback, recovery, and sanitized evidence gates.
   - Begin Stage 10 cutover only after pilot acceptance; offline milestone artifacts are not product releases.
   - Add external MQTT/openHAB integration only after the narrow REST contract and device behavior are stable.
5. **ACME certificates**
   - Start with off-device issuance and controlled certificate deployment.
   - Evaluate a native `lego` build only after kernel, storage, memory, clock, and key-protection checks.
6. **Firmware packaging**
   - Create reproducible overlay/image tooling with strict size, integrity, recovery, and rollback validation.
   - Publish a complete firmware update only after its format and device recovery path are proven.

Every milestone must document provenance, checksums, tests, limitations, installation, and rollback. Vendor firmware and device-specific secrets are never release assets.
