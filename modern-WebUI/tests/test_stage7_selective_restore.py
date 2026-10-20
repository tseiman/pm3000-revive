import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "modern-WebUI" / "deploy" / "stage7-selective-restore.py"


class Stage7SelectiveRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backup = Path(self.temporary.name) / "backup"
        self.backup.mkdir()
        archive_path = self.backup / "BACKUP_ARCHIVE.tar"
        entries = []
        with tarfile.open(archive_path, "w") as archive:
            for name, data in (
                ("usr/share/apache2/htdocs/index.xml", b"legacy\n"),
                ("mnt/hdUser/pm3000-revive/webui/releases/r1/web/index.html", b"modern\n"),
                ("mnt/hdUser/pm3000-revive/rest/tokens.json", b"secret\n"),
                ("etc/apache2/httpd.conf", b"apache\n"),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
                entries.append({"path": name, "type": "file", "size": len(data)})
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        manifest = {
            "archive_sha256": archive_hash,
            "entries": entries,
            "excluded_virtual_filesystems": ["dev", "proc", "sys"],
            "format": 3,
            "target": "root@pdu1",
        }
        manifest_path = self.backup / "BACKUP_MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        (self.backup / "BACKUP_COMPLETE").write_text(archive_hash + "\n" + manifest_hash + "\n")

    def run_tool(self, *arguments):
        return subprocess.run(
            ["python3", str(TOOL), "--backup", str(self.backup), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_legacy_webui_plan_contains_only_legacy_web_tree(self):
        result = self.run_tool("--profile", "legacy-webui")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usr/share/apache2/htdocs/index.xml", result.stdout)
        self.assertNotIn("tokens.json", result.stdout)
        self.assertNotIn("etc/apache2/httpd.conf", result.stdout)
        self.assertIn("apply=no", result.stdout)

    def test_prepared_modern_webui_tar_excludes_tokens_and_unrelated_files(self):
        output = Path(self.temporary.name) / "modern-restore.tar"
        result = self.run_tool("--profile", "modern-webui", "--prepare", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(output, "r:") as archive:
            names = archive.getnames()
        self.assertEqual(names, ["mnt/hdUser/pm3000-revive/webui/releases/r1/web/index.html"])
        self.assertNotIn("tokens.json", "\n".join(names))
        self.assertIn("apply=no", result.stdout)


if __name__ == "__main__":
    unittest.main()
