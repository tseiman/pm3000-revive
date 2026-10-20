import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-first-backup.sh"


class Stage7MacBackupTests(unittest.TestCase):
    def _run(self, inventory: str):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        ssh = fake_bin / "ssh"
        ssh.write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$FAKE_INVENTORY\"\n")
        ssh.chmod(0o755)
        backup_parent = root / "backups"
        backup_parent.mkdir()
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["FAKE_INVENTORY"] = inventory
        result = subprocess.run(
            ["bash", str(SCRIPT), "--target", "root@pdu1", "--backup-dir", str(backup_parent)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        return root, backup_parent, result

    def test_creates_private_local_marker_only_after_absent_inventory(self):
        inventory = (
            "pm3000_first_backup.format=1\n"
            "system.kernel=Linux\n"
            "system.release=2.6.23\n"
            "system.machine=ppc\n"
            "firmware.sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            "path.pm3000_revive=absent\n"
            "path.apache_config=absent\n"
            "pm3000_first_backup.complete=yes\n"
        )
        _, backup_parent, result = self._run(inventory)
        self.assertEqual(result.returncode, 0, result.stderr)
        directories = list(backup_parent.iterdir())
        self.assertEqual(len(directories), 1)
        backup = directories[0]
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertTrue((backup / "REMOTE_INVENTORY.txt").is_file())
        self.assertTrue((backup / "BACKUP_ARCHIVE.tar").is_file())
        self.assertTrue((backup / "BACKUP_MANIFEST.json").is_file())
        marker = (backup / "BACKUP_COMPLETE").read_text().splitlines()
        self.assertEqual(len(marker), 2)
        self.assertTrue(all(len(line) == 64 for line in marker))
        self.assertIn(f"backup_dir={backup}", result.stdout)

    def test_refuses_first_install_backup_when_a_managed_path_exists(self):
        inventory = (
            "pm3000_first_backup.format=1\n"
            "path.pm3000_revive=directory\n"
            "path.apache_config=absent\n"
            "pm3000_first_backup.complete=yes\n"
        )
        _, backup_parent, result = self._run(inventory)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(backup_parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
