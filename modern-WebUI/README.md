# PM3000 Modern Web UI

This directory contains the clean-room design and future implementation of a compact modern Web UI and bearer-token REST facade for Avocent PM3000 firmware `2.0.1.23`.

## Current status

**Analysis and staged planning only.** No replacement UI, REST adapter, or device installer is provided yet.

Confirmed architecture:

```text
browser -> Apache /appliance/avtrans -> mod_avtrans -> /dev/avtrans_socket
        -> uicontrold -> GSP session/authorization -> CACPD -> power API
```

The design keeps Apache and the vendor backend. The first REST scope is deliberately narrow: outlet inventory/status and individual `on`, `off`, or `cycle` actions after their exact Avtrans contracts have been captured and approved.

## Documents

- [Architecture and security analysis](ANALYSIS.md)
- [Implementation stages](STAGES.md)
- [Protocol boundary](docs/PROTOCOL.md)
- [Manual Avtrans capture procedure](docs/CAPTURE.md)
- [Reported device storage baseline](docs/DEVICE-STORAGE.md)
- [Synthetic fixture notes](fixtures/synthetic/README.md)
- [Resume status](STATUS.md)
- [Legacy compatibility patch](../fix-WebUI/README.md)

## Safety boundary

- No PM3000 is contacted automatically.
- No script reboots a device or switches an outlet without an explicit later operator test.
- Vendor firmware files, binaries, credentials, sessions, certificates, and private backups are not repository content.
- Deployment will require a complete verified remote-to-host backup before the first remote installation write.
