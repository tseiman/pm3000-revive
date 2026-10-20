# PM3000 Web UI compatibility fix

This directory preserves a compatibility patch for the legacy Avocent PM3000 web interface from firmware `2.0.1.23`. It repairs browser-sensitive XSL output and JavaScript DOM traversal. It is a stabilization aid for the vendor UI, not the planned modern replacement UI.

## Contents

- `webui-2.0.1.23-to-tested-state.patch` — patch for `scripts-20150511.js` and `transformation.xsl`.
- `file-hashes.json` — byte-exact hashes and sizes of the observed original and tested-state backup files. Because the patch is LF-normalized, `backup_sha256` is not guaranteed to equal a newly patched file with different line endings.
- `REPAIR-NOTES.de.md` — detailed German investigation and handover notes, with private operational identifiers removed for public release.

## Important limits

- Apply only to firmware `2.0.1.23` files matching the `original_sha256` values in `file-hashes.json`.
- The patch alone is incomplete on a clean firmware image. It also expects `document.load_client_injection.js` and a separately modified `xwire/xWireClientFull.jsb`; neither is included.
- The captured state contains historical debug logging that may expose response or session data in the browser console. Review and remove it before production use.
- Browser syntax checks and selected manual interactions passed, but complete navigation, configuration writes, outlet actions, and cross-browser behavior remain unverified.
- Do not deploy automatically, reboot the PDU, or overwrite files without a tested backup and recovery path.

## Controlled installation

Work from a trusted management session. Keep the vendor files and backups outside the web root. First verify the unmodified inputs:

```bash
sha256sum /usr/share/apache2/htdocs/scripts-20150511.js
sha256sum /usr/share/apache2/htdocs/transformation.xsl
```

Expected hashes:

```text
7d81064e772a02c7987b68be906372f9f80ec558ff8798a8215879ca923be368  scripts-20150511.js
5534a71c61b62c9df426d3efebd3699daaed7cf7e2dce776944613bcdaef3337  transformation.xsl
```

Stop if either hash differs. On a workstation, copy the two verified files into a staging tree and test the patch before changing the device:

```bash
mkdir -p work/usr/share/apache2/htdocs
cp scripts-20150511.js transformation.xsl work/usr/share/apache2/htdocs/
patch --dry-run -p1 -d work < webui-2.0.1.23-to-tested-state.patch
patch -p1 -d work < webui-2.0.1.23-to-tested-state.patch
```

Do not install the staged result until the two missing companion files have been obtained from an approved backup, reviewed, and tested together. Preserve the original ownership and modes when manually replacing files. Static JS/XSL changes should not require an Apache restart; use a full browser reload with cache disabled.

## Verification and rollback

Before any write operation, verify read-only login, navigation, tables, forms, and browser-console output. Test configuration writes only after explicit approval, beginning with a non-critical setting. Never use outlet switching as a smoke test.

If a regression occurs, restore all related Web UI files as one set from the pre-change backup. See `REPAIR-NOTES.de.md` for detailed findings, known dependencies, and remaining work.

## Provenance and licensing

The patch and handover notes were supplied from an observed PM3000 repair. The patch necessarily contains limited context from Avocent/Vertiv web files. No license for that vendor code has been established; the repository's MIT license does not relicense it. Do not add firmware images or complete vendor source files.
