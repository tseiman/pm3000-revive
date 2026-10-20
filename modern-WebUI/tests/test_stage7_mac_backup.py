import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-first-backup.sh"


class Stage7MacBackupTests(unittest.TestCase):
    def test_is_portable_across_macos_and_linux_host_tools(self):
        source = SCRIPT.read_text()
        self.assertNotIn("shasum", source)
        self.assertNotIn("sha256sum", source)
        for command in ("mkdir", "chmod", "rm", "cd", "mv"):
            with self.subTest(command=command):
                self.assertNotRegex(source, rf"(?m)^\s*{command}[^\n]*\s--(?:\s|$)")

    def _fixture_archive(self, path: Path) -> None:
        with tarfile.open(path, "w") as archive:
            for name, data, mode in (
                ("etc/version", b"PM3000 firmware\n", 0o644),
                ("etc/apache2/httpd.conf", b"ServerRoot /etc/apache2\n", 0o600),
                ("mnt/hdUser/private-secret", b"secret-value\n", 0o600),
                ("usr/share/apache2/htdocs/index.xml", b"<index/>\n", 0o644),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = mode
                archive.addfile(info, io.BytesIO(data))

    def _run(self, archive_override=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        backup_parent = root / "backups"
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fixture = root / "fixture.tar"
        if archive_override is None:
            self._fixture_archive(fixture)
        else:
            archive_override(fixture)
        fake_ssh = fake_bin / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "program = sys.stdin.read()\n"
            "if 'tar cf -' in program:\n"
            "    sys.stdout.buffer.write(pathlib.Path(os.environ['FAKE_ARCHIVE']).read_bytes())\n"
            "else:\n"
            "    print('pm3000_full_backup.format=1')\n"
            "    print('system.kernel=Linux')\n"
            "    print('system.release=2.6.23')\n"
            "    print('system.machine=ppc')\n"
            "    print('firmware.sha256=' + 'a' * 64)\n"
            "    print('excluded.virtual=dev,proc,sys')\n"
            "    print('pm3000_full_backup.complete=yes')\n"
        )
        fake_ssh.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["FAKE_ARCHIVE"] = str(fixture)
        result = subprocess.run(
            ["bash", str(SCRIPT), "--target", "root@pdu1", "--backup-dir", "backups"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd=root,
            check=False,
        )
        return backup_parent, result

    def test_streams_real_full_backup_with_secret_payload(self):
        backup_parent, result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        directories = list(backup_parent.glob("stage7-full-backup-*"))
        self.assertEqual(len(directories), 1)
        backup = directories[0]
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        archive_path = backup / "BACKUP_ARCHIVE.tar"
        self.assertEqual(archive_path.stat().st_mode & 0o777, 0o600)
        with tarfile.open(archive_path, "r:") as archive:
            secret = archive.extractfile("mnt/hdUser/private-secret")
            self.assertIsNotNone(secret)
            assert secret is not None
            self.assertEqual(secret.read(), b"secret-value\n")
        manifest = json.loads((backup / "BACKUP_MANIFEST.json").read_text())
        names = {entry["path"] for entry in manifest["entries"]}
        self.assertIn("etc/apache2/httpd.conf", names)
        self.assertIn("mnt/hdUser/private-secret", names)
        self.assertIn("usr/share/apache2/htdocs/index.xml", names)
        self.assertEqual(manifest["excluded_virtual_filesystems"], ["dev", "proc", "sys"])
        self.assertEqual(len((backup / "BACKUP_COMPLETE").read_text().splitlines()), 2)
        self.assertIn("backup_complete=yes", result.stdout)

    def test_rejects_unsafe_archive_member(self):
        def unsafe(path):
            with tarfile.open(path, "w") as archive:
                data = b"escape"
                info = tarfile.TarInfo("../escape")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

        backup_parent, result = self._run(unsafe)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe archive member", result.stderr)
        if backup_parent.exists():
            self.assertEqual(list(backup_parent.glob("stage7-full-backup-*")), [])


if __name__ == "__main__":
    unittest.main()
