# Reported PM3000 Storage Baseline

This is an operator-reported `df -h` snapshot from 2026-10-20. It is planning evidence, not an installation preflight result. Deployment must measure the target device again immediately before backup and staging.

- `/`: 55.0 MiB total, 26.1 MiB used, **28.9 MiB available**.
- `/mnt/hdCnf` and `/etc`: the same 5.0 MiB filesystem, **3.4 MiB available**.
- `/home`: the same 5.0 MiB configuration filesystem, **3.4 MiB available**.
- `/var`: 28.6 MiB total, 872 KiB used, **27.8 MiB available**; treat it as potentially volatile until the mount behavior is confirmed.
- `/mnt/hdUser`: 4.0 MiB total, 1.7 MiB used, **2.3 MiB available**.
- `/dev`: 10.0 MiB tmpfs, **10.0 MiB available**.

## Design consequences

- The modern runtime target remains at or below 400 KiB.
- Persistent releases and token configuration must fit within the currently tight `/mnt/hdUser` budget if that location is retained.
- `/var` may be suitable for temporary backup/package staging, but never for the only backup copy.
- The complete pre-install backup is transferred to and verified on the administration host before installation.
- No script assumes the reported free space is still available.
