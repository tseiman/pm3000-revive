#!/usr/bin/env python3
"""Host behavior tests for fixed-purpose ACME maintenance/activation."""

from __future__ import annotations

import os
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "pm3000-acme-maintenance.sh"


class AcmeMaintenanceTests(unittest.TestCase):
    def make_activation_fixture(self, work: Path, *, httpd_ok: bool = True):
        managed = work / "managed"
        issued = work / "issued"
        trust = issued / "trust"
        managed.mkdir(mode=0o700)
        trust.mkdir(parents=True, mode=0o700)
        issued.chmod(0o700)
        fullchain = (b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
                     b"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n")
        key = b"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
        (issued / "certificate.pem").write_bytes(fullchain)
        (issued / "certificate-key.pem").write_bytes(key)
        (trust / "managed-ca.pem").write_bytes(b"ca\n")
        for path in (issued / "certificate.pem", issued / "certificate-key.pem", trust / "managed-ca.pem"):
            path.chmod(0o600)
        config = work / "httpd-ssl.conf"
        config.write_text(
            "SSLCertificateFile /etc/CA/pdu1.tsei.mdn.pem\n"
            "SSLCertificateKeyFile /etc/CA/pdu1.tsei.mdn.key\n"
            "SSLCertificateChainFile /etc/CA/ca.tsei.mdn.crt\n", encoding="ascii")
        served = work / "served.pem"
        served.write_bytes(fullchain)
        calls = work / "calls"
        acme = work / "acme"
        acme.write_text("#!/bin/sh\nexit 0\n", encoding="ascii"); acme.chmod(0o755)
        reload = work / "reload"
        reload.write_text(f"#!/bin/sh\nprintf 'reload\\n' >>'{calls}'\nexit 0\n", encoding="ascii"); reload.chmod(0o755)
        httpd = work / "httpd"
        httpd.write_text(f"#!/bin/sh\nexit {0 if httpd_ok else 1}\n", encoding="ascii"); httpd.chmod(0o755)
        atomic = work / "atomic"
        atomic.write_text(
            "#!/usr/bin/env python3\n"
            "import os, stat, sys\n"
            "a=sys.argv[1:]\n"
            "if a[0].startswith('--verify-private'):\n"
            " p=a[1]; s=os.lstat(p)\n"
            " ok=(not stat.S_ISLNK(s.st_mode) and s.st_uid==os.geteuid())\n"
            " if 'regular' in a[0]: ok=ok and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600\n"
            " else: ok=ok and stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700\n"
            " raise SystemExit(0 if ok else 1)\n"
            "parent,source,dest,kind=a; os.replace(os.path.join(parent,source),os.path.join(parent,dest))\n",
            encoding="ascii"); atomic.chmod(0o755)
        openssl = work / "openssl"
        openssl.write_text(
            f"#!/bin/sh\n"
            "case \"$1\" in\n"
            " dgst) value=$(sha256sum \"$3\"); echo \"SHA256($3)= ${value%% *}\";;\n"
            " verify) exit 0;;\n"
            " rsa) echo 'Modulus=match';;\n"
            " s_client) cat '" + str(served) + "';;\n"
            " x509) case \"$*\" in *-modulus*) echo 'Modulus=match';; *-fingerprint*) echo 'sha256 Fingerprint=fixed';; *) exit 0;; esac;;\n"
            " *) exit 1;;\n"
            "esac\n", encoding="ascii"); openssl.chmod(0o755)
        source = HELPER.read_text(encoding="ascii")
        replacements = {
            "MANAGED_ROOT=/etc/CA/pm3000-acme": f"MANAGED_ROOT={managed}",
            "ISSUED_ROOT=/mnt/hdUser/pm3000-revive/acme": f"ISSUED_ROOT={issued}",
            "APACHE_CONFIG=/etc/apache2/extra/httpd-ssl.conf": f"APACHE_CONFIG={config}",
            "OPENSSL=/usr/bin/openssl": f"OPENSSL={openssl}",
            "ACME=/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme": f"ACME={acme}",
            "ATOMIC=/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-atomic-publish": f"ATOMIC={atomic}",
            "HTTPD=/usr/sbin/httpd": f"HTTPD={httpd}",
            "APACHE_RELOAD=/etc/init.d/apache2": f"APACHE_RELOAD={reload}",
            "ORIGINAL_CONFIG_SHA=9c693be2e5e2bf7ea5f35a3b8578754fcbd6a941d222c4c6a0074ca510cc1f19":
                f"ORIGINAL_CONFIG_SHA={hashlib.sha256(config.read_bytes()).hexdigest()}",
        }
        for old, new in replacements.items():
            self.assertIn(old, source); source = source.replace(old, new)
        candidate = work / "maintenance"
        candidate.write_text(source, encoding="ascii"); candidate.chmod(0o755)
        return candidate, managed, issued, config, calls

    def test_partial_publication_is_repaired_instead_of_reported_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate, managed, _issued, _config, calls = self.make_activation_fixture(Path(temporary))
            (managed / "certificate.pem").write_bytes(
                b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
            (managed / "certificate.pem").chmod(0o600)
            result = subprocess.run([str(candidate), "force"], text=True, capture_output=True,
                                    env={"PATH": "/usr/bin:/bin"}, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('"result":"activated"', result.stdout)
            self.assertTrue((managed / "private-key.pem").is_file())
            self.assertTrue((managed / "chain.pem").is_file())
            self.assertEqual("reload\n", calls.read_text(encoding="ascii"))

    def test_unsafe_linked_active_file_is_never_accepted_as_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate, managed, _issued, _config, _calls = self.make_activation_fixture(Path(temporary))
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
            outside.chmod(0o600)
            os.link(outside, managed / "certificate.pem")
            result = subprocess.run([str(candidate), "force"], text=True, capture_output=True,
                                    env={"PATH": "/usr/bin:/bin"}, check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('"result":"unchanged"', result.stdout)
            self.assertEqual(b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", outside.read_bytes())

    def test_activation_failure_overrides_issuance_success_and_retains_failed_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate, managed, issued, _config, _calls = self.make_activation_fixture(
                Path(temporary), httpd_ok=False)
            result = subprocess.run([str(candidate), "force"], text=True, capture_output=True,
                                    env={"PATH": "/usr/bin:/bin"}, check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('"result":"rollback_uncertain"', result.stdout)
            status = subprocess.run([str(candidate), "status"], text=True, capture_output=True,
                                    env={"PATH": "/usr/bin:/bin"}, check=False)
            self.assertEqual(0, status.returncode, status.stderr)
            self.assertEqual('{"state":"failed","phase":"certificate_publication","reason":"publication"}\n', status.stdout)
            self.assertTrue(list(managed.glob(".rollback.*")))
            self.assertTrue((issued / "activation-status-v1").is_file())

    def test_helper_keeps_activation_paths_and_commands_closed(self) -> None:
        source = HELPER.read_text(encoding="ascii")
        self.assertIn("-checkend 2592000", source)
        self.assertIn("/etc/CA/pm3000-acme", source)
        self.assertIn("ORIGINAL_CONFIG_SHA=9c693be2e5e2bf7ea5f35a3b8578754fcbd6a941d222c4c6a0074ca510cc1f19", source)
        self.assertNotIn("SSLCACertificateFile", source)
        self.assertIn('"$HTTPD" -t -D SSL -f /etc/apache2/httpd.conf', source)
        self.assertIn('"$APACHE_RELOAD" reload', source)
        self.assertIn("-fingerprint -sha256", source)

    def test_scheduled_valid_certificate_not_due_is_a_closed_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            managed = work / "managed"
            managed.mkdir()
            (managed / "certificate.pem").write_text("active certificate\n", encoding="ascii")
            log = work / "calls"
            fake_openssl = work / "openssl"
            fake_openssl.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'" + str(log) + "'\n"
                "[ \"$1:$2:$3:$4:$5\" = 'x509:-in:" + str(managed / "certificate.pem")
                + ":-noout:-checkend' ] && [ \"$6\" = 2592000 ] && exit 0\nexit 99\n",
                encoding="ascii",
            )
            fake_openssl.chmod(0o755)
            fake_fail = work / "must-not-run"
            fake_fail.write_text("#!/bin/sh\nexit 98\n", encoding="ascii")
            fake_fail.chmod(0o755)

            source = HELPER.read_text(encoding="ascii")
            replacements = {
                'MANAGED_ROOT=/etc/CA/pm3000-acme': f'MANAGED_ROOT={managed}',
                'OPENSSL=/usr/bin/openssl': f'OPENSSL={fake_openssl}',
                'ACME=/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme': f'ACME={fake_fail}',
                'APACHE_RELOAD=/etc/init.d/apache2': f'APACHE_RELOAD={fake_fail}',
            }
            for old, new in replacements.items():
                self.assertIn(old, source)
                source = source.replace(old, new)
            candidate = work / "maintenance"
            candidate.write_text(source, encoding="ascii")
            candidate.chmod(0o755)

            result = subprocess.run(
                [str(candidate), "scheduled"], text=True, capture_output=True,
                env={"PATH": "/usr/bin:/bin"}, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                '{"mode":"scheduled","result":"not_due","changed":false,"reloaded":false}\n',
                result.stdout,
            )
            self.assertEqual("", result.stderr)
            self.assertEqual(
                f"x509 -in {managed / 'certificate.pem'} -noout -checkend 2592000\n",
                log.read_text(encoding="ascii"),
            )


if __name__ == "__main__":
    unittest.main()
