# PM3000 Storage Baselines

These snapshots are planning evidence, not installation preflight results. Deployment must measure the target device again immediately before backup and staging.

## Authenticated read-only Web UI snapshot — 2026-10-20

The firmware `Flash Usage` and `Memory` pages reported:

- `/`: 56,320 KiB total, 26,648 KiB used, **29,672 KiB (29.0 MiB) available**.
- `/etc`, `/home`, and `/mnt/hdCnf`: the same 5,120 KiB filesystem, **3,476 KiB (3.4 MiB) available**.
- `/var`: 29,296 KiB total, 1,120 KiB used, **28,176 KiB (27.5 MiB) available**; treat it as potentially volatile until mount behavior is confirmed.
- `/mnt/hdUser`: 4,096 KiB total, 1,724 KiB used, **2,372 KiB (2.3 MiB) available**.
- `/dev`: 10,240 KiB tmpfs, **10,224 KiB (10.0 MiB) available**.
- RAM: 256,616 KiB total, 187,528 KiB free at capture time; no swap configured.

The values were obtained through authenticated read-only Avtrans page requests. No configuration or power action was sent.

## Earlier operator-reported `df -h` snapshot — 2026-10-20

- `/`: 55.0 MiB total, 26.1 MiB used, **28.9 MiB available**.
- `/mnt/hdCnf` and `/etc`: the same 5.0 MiB filesystem, **3.4 MiB available**.
- `/home`: the same 5.0 MiB configuration filesystem, **3.4 MiB available**.
- `/var`: 28.6 MiB total, 872 KiB used, **27.8 MiB available**.
- `/mnt/hdUser`: 4.0 MiB total, 1.7 MiB used, **2.3 MiB available**.
- `/dev`: 10.0 MiB tmpfs, **10.0 MiB available**.

## Design consequences

- The production release currently uses about 500 KiB of regular payload and is capped at 544 KiB; each install still performs a live capacity check with 256 KiB additional transactional headroom.
- Persistent releases and token configuration must fit within the currently tight `/mnt/hdUser` budget if that location is retained.
- `/var` may be suitable for temporary backup/package staging, but never for the only backup copy.
- The complete pre-install backup is transferred to and verified on the administration host before installation.
- No script assumes the reported free space is still available.
