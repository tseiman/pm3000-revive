#!/usr/bin/env python3
"""Focused contract tests for the one-command host installer."""

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-install.sh"


class Stage7InstallContractTests(unittest.TestCase):
    def test_single_connection_install_contract_is_simple_and_noninteractive(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("ControlMaster=no", source)
        self.assertIn("ControlPath=none", source)
        self.assertIn("ControlPersist=no", source)
        self.assertNotIn("ControlMaster=yes", source)
        self.assertNotIn("scp ", source)
        self.assertIn("format=tarfile.USTAR_FORMAT", source)
        self.assertIn('("release.tar", "BACKUP_COMPLETE", "device-install.sh", "remote-install.sh")', source)
        self.assertNotIn("tar cf -", source)
        self.assertIn("RELEASE_MANIFEST.json", source)
        self.assertIn("BACKUP_COMPLETE", source)
        self.assertIn("device-install.sh", source)
        self.assertIn("compatibility.complete=yes", source)
        self.assertIn('LD_BIND_NOW=1 "$acme" renew --invalid', source)
        self.assertIn('[ "$acme_status" -eq 2 ]', source)
        self.assertIn("install.complete=yes", source)
        ssh_invocations = re.findall(r"\|\s*ssh(?:\s|$)", source)
        self.assertEqual(1, len(ssh_invocations), ssh_invocations)
        for forbidden in (
            "sshpass", "read -s", "SSH_ASKPASS", "device-rollback.sh",
            "poweroff", "reboot", "-O exit", "-MNf",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(0, subprocess.run(["bash", "-n", str(SCRIPT)]).returncode)

    def test_operator_progress_messages_cover_each_major_phase(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for message in (
            "Validating the release package and full backup locally",
            "Preparing a POSIX ustar installation payload",
            "Opening one non-multiplexed SSH connection",
            "Verifying uploaded release checksum",
            "Checking release archive allowlist",
            "Checking private runtime ownership and permissions",
            "Running read-only PPC/CGI compatibility health check",
            "Installing release",
            "Validating Apache configuration",
            "Checking the activated REST health endpoint",
            "Installation completed successfully",
        ):
            self.assertIn(message, source)


if __name__ == "__main__":
    unittest.main()
