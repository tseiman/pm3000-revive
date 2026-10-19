# Roadmap

Development proceeds in small, independently testable milestones.

## Completed foundation

- Reproducible PPC32 big-endian e300c3 cross-toolchain
- Static Dropbear server and key generator
- Host-side ELF, QEMU-user, and isolated SSH verification
- Manual parallel-install test procedure

## Next milestones

1. **Device validation**
   - Test the current Dropbear build on a PM3000 using port 2222.
   - Confirm kernel compatibility, entropy, account lookup, PTY commands, resource use, and rollback.
2. **Firmware inventory**
   - Document boot flow, partitions, root filesystem, update container, checksums/signatures, persistent data, and recovery paths.
   - Build read-only extraction and inspection tools before any image writer.
3. **RPC and automation**
   - Document the existing RPC protocol from authorized captures.
   - Implement a read-only client and test fixtures.
   - Add an external REST/MQTT bridge suitable for openHAB before considering an on-device service.
4. **Web UI modernization**
   - Build a modern UI against the documented bridge/API.
   - Run it externally first; assess on-device deployment only after resource and security testing.
5. **ACME certificates**
   - Start with off-device issuance and controlled certificate deployment.
   - Evaluate a native `lego` build only after kernel, storage, memory, clock, and key-protection checks.
6. **Firmware packaging**
   - Create reproducible overlay/image tooling with strict size, integrity, recovery, and rollback validation.
   - Publish a complete firmware update only after its format and device recovery path are proven.

Every milestone must document provenance, checksums, tests, limitations, installation, and rollback. Vendor firmware and device-specific secrets are never release assets.
