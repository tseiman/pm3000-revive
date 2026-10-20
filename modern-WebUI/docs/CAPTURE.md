# Capturing Avtrans Evidence

This procedure collects the minimum protocol evidence needed for Stage 1. It does not require SSH, a device reboot, an outlet action, or replaying a request.

## Prerequisites

- A normal browser session that can open the existing PM3000 Web UI.
- Python 3 on the workstation containing this repository.
- A private local directory outside the repository for raw captures.

## Capture

1. Create a private local directory for raw XML. Do not place it below the Git checkout.
2. Open the browser developer tools and select **Network**.
3. Filter requests by `avtrans`.
4. Use the existing UI normally and collect the request body and response body separately for:
   - initial `login/get`;
   - login submission and its response;
   - successful header response;
   - navigation request and response;
   - outlet/PDU inventory request and response;
   - one read-only outlet-status request and response.
5. Save each body as an individual `.xml` file in the private directory.

Do not export or submit a complete HAR. It contains unrelated headers and may retain session or device data. Do not use **Replay**, **Resend**, **Edit and resend**, or a copied `curl` command. Do not capture `on`, `off`, or `cycle` in Stage 1.

## Sanitize

Run the sanitizer once per raw XML file. The input and output must be different paths:

```bash
cd pm3000-revive
python3 modern-WebUI/tools/sanitize_avtrans.py \
  /private/path/raw-navigation-response.xml \
  /private/path/sanitized-navigation-response.xml
```

The sanitizer automatically replaces:

- Avtrans session IDs;
- login usernames and passwords;
- credential-, token-, certificate-, and common network-configuration fields;
- RFC1918 IPv4 addresses;
- hostnames ending in `.local`, `.lan`, `.internal`, `.home`, or `.mdn`.

For an additional device label or serial number, add one or more literal replacements:

```bash
python3 modern-WebUI/tools/sanitize_avtrans.py \
  /private/path/raw.xml \
  /private/path/sanitized.xml \
  --redact 'device-label' \
  --redact 'device-serial'
```

Do not put passwords, tokens, or session IDs on the command line; their structured fields are already handled automatically.

## Review before sharing

Open every sanitized output and verify that it contains no:

- username, password, token, session ID, or certificate material;
- device hostname, private address, serial number, or site-specific label;
- unrelated browser headers or cookies.

Share only the reviewed sanitized XML files. Keep or delete the raw files according to local policy; never commit them.

## Expected Stage 1 result

The sanitized files will be compared with the synthetic fixtures and recorded as observed protocol evidence. Their concrete paths, action IDs, row IDs, and controls remain data from the backend; they are not generalized into a free-form command interface.
