# Apache 2.2 TLS compatibility patch

This directory records the narrow TLS configuration change verified on PM3000 firmware 2.0.1.23.

## Purpose

The stock Apache 2.2.23/mod_ssl configuration prefers `DHE-RSA-AES256-GCM-SHA384` with a built-in 1024-bit finite-field Diffie-Hellman group. Current OpenSSL security policy rejects that group as too small. Apache 2.2.23 cannot configure a larger custom group through modern directives such as `SSLOpenSSLConfCmd`.

`httpd-ssl.conf.patch` sets the following RSA cipher list only inside the port-443 virtual host:

```apache
SSLCipherSuite AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA
```

The DSView virtual host on port 3502 retains the vendor-global cipher configuration.

## Security and compatibility boundary

- The patch removes the weak 1024-bit DHE path from HTTPS on port 443.
- The verified negotiated suite is `AES256-GCM-SHA384` over TLS 1.2.
- Certificate-chain and hostname verification remain enabled and succeed with the local trust store.
- Static RSA key exchange does **not** provide forward secrecy.
- Some current browsers no longer support static RSA key exchange. Verify every required client before deployment.
- Long-term remediation requires a modern TLS terminator or a carefully validated Apache/mod_ssl replacement compatible with the proprietary modules.

## Apply only after backup

Do not modify the appliance until the complete host-side backup gate described by the project has succeeded. The stock firmware image does not contain a `patch` utility, so apply this artifact on the administration host against a staged appliance-root tree:

```bash
patch --dry-run -p1 -d /path/to/staged-root < httpd-ssl.conf.patch
patch -p1 -d /path/to/staged-root < httpd-ssl.conf.patch
```

The patch targets the unmodified firmware 2.0.1.23 file. It must stop rather than guess if the target file has already been edited. Compare the staged result with its backup and deploy only:

```text
/etc/apache2/extra/httpd-ssl.conf
```

After the backup has been transferred to the host and verified, validate the deployed configuration on the appliance before reload:

```bash
/usr/sbin/httpd -t -D SSL -f /etc/apache2/httpd.conf
/etc/init.d/apache2 reload
```

Keep the active SSH session open until HTTPS verification succeeds. A failed syntax check must stop the procedure before reload.

## Rollback

Restore the exact backed-up `/etc/apache2/extra/httpd-ssl.conf`, run the same Apache syntax check, and reload only after `Syntax OK`. Do not attempt to reverse the patch against an unknown or manually edited live file.

## Verification

From a trusted administration host:

```bash
curl --fail --show-error --silent --output /dev/null \
  --write-out 'status=%{http_code} verify=%{ssl_verify_result}\n' \
  https://pdu.example.invalid/

openssl s_client \
  -connect pdu.example.invalid:443 \
  -servername pdu.example.invalid \
  -brief </dev/null
```

Expected essentials:

```text
status=200 verify=0
Protocol version: TLSv1.2
Ciphersuite: AES256-GCM-SHA384
Verification: OK
```

The hostname is an environment-specific example; substitute the target appliance name when applying the patch elsewhere.
