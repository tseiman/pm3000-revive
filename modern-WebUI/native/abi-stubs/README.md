# PM3000 firmware ABI link stubs

These files provide **build-time symbol metadata only** for the dynamically linked
`pm3000-gsp-session-helper`:

- `libgsp-auth-link.c` exports the seven GSP session symbols used by the helper
  under the runtime SONAME `libgsp_auth.so`.
- `libc-glibc20-link.c` and `glibc-2.0.map` export the required libc surface
  under `libc.so.6` with symbol version `GLIBC_2.0`.

The generated stub shared objects are written below `native/build/abi-stubs/`.
They are not included in the PM3000 release archive and must never be installed
on an appliance. The deployed helper resolves the same imports from the vendor
libraries already present in the PM3000 firmware.

This keeps GitHub Actions reproducible without redistributing firmware binaries.
The release build audits the helper's `DT_NEEDED` entries, GLIBC symbol versions,
PowerPC architecture, interpreter, and unresolved compiler millicode symbols.
