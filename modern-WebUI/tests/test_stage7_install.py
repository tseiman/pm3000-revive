#!/usr/bin/env python3
"""Focused contract tests for the one-command host installer."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-install.sh"


class Stage7InstallContractTests(unittest.TestCase):
    def test_controlmaster_install_contract_is_simple_and_noninteractive(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("ControlMaster=yes", source)
        self.assertIn('ControlPath="$control_path"', source)
        self.assertIn("ControlPersist=60", source)
        self.assertIn('ssh -o ControlMaster=yes -o ControlPath="$control_path" -o ControlPersist=60 -MNf "$target"', source)
        self.assertIn('scp "${scp_options[@]}"', source)
        self.assertIn("RELEASE_MANIFEST.json", source)
        self.assertIn("BACKUP_COMPLETE", source)
        self.assertIn("device-install.sh", source)
        self.assertIn("compatibility.complete=yes", source)
        self.assertIn("install.complete=yes", source)
        for forbidden in ("sshpass", "read -s", "SSH_ASKPASS", "device-rollback.sh", "poweroff", "reboot"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(0, subprocess.run(["bash", "-n", str(SCRIPT)]).returncode)


if __name__ == "__main__":
    unittest.main()
