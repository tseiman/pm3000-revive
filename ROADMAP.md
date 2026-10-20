# Roadmap

Development proceeds in small, independently testable milestones.

## Completed foundation

- Reproducible PPC32 big-endian e300c3 cross-toolchain
- Static Dropbear server and key generator
- Host-side ELF, QEMU-user, and isolated SSH verification
- Reported PM3000 hardware validation of the current Dropbear build, including port 22, classic SCP, and SysV startup after reboot
- Two-phase installer with isolated host-side state-transition and rollback simulation

## Next milestones

1. **Installer device acceptance**
   - Run the packaged two-phase installer on a PM3000 using its single port-2222 test and confirmed port-22 activation.
   - Confirm installer preflight, idempotent reruns, rollback, resource use, startup fallback, and a separately approved reboot.
2. **Firmware inventory**
   - Document boot flow, partitions, root filesystem, update container, checksums/signatures, persistent data, and recovery paths.
   - Build read-only extraction and inspection tools before any image writer.
3. **Web UI and REST evidence**
   - Continue the verified [`modern-WebUI/`](modern-WebUI/) stages with sanitized Avtrans fixtures and strict read-only contracts.
   - Preserve Apache and the vendor `mod_avtrans -> uicontrold -> GSP/CACPD -> power API` authorization path.
4. **Compact Web UI and automation facade**
   - Build a dependency-free modern UI and small native bearer-token CGI adapter, starting read-only.
   - Add multiple scoped tokens and individual outlet actions only after exact contracts, backup/rollback, and manual device acceptance are proven.
   - Add an external MQTT/openHAB integration after the narrow REST contract is stable.
5. **ACME certificates**
   - Start with off-device issuance and controlled certificate deployment.
   - Evaluate a native `lego` build only after kernel, storage, memory, clock, and key-protection checks.
6. **Firmware packaging**
   - Create reproducible overlay/image tooling with strict size, integrity, recovery, and rollback validation.
   - Publish a complete firmware update only after its format and device recovery path are proven.

Every milestone must document provenance, checksums, tests, limitations, installation, and rollback. Vendor firmware and device-specific secrets are never release assets.
