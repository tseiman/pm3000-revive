import hashlib
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "modern-WebUI" / "deploy"
BUILDER = DEPLOY / "build-acme-hardware-acceptance.py"


class AcmeHardwareAcceptanceTests(unittest.TestCase):
    def test_builder_emits_closed_one_password_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            candidate = work / "pm3000-acme"
            candidate.write_bytes(b"ppc candidate")
            candidate.chmod(0o755)
            output = work / "acceptance.zip"
            result = subprocess.run(
                [sys.executable, str(BUILDER), "--candidate", str(candidate),
                 "--output", str(output), "--version", "v5"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), [
                    "pm3000-acme-v5-acceptance/README.md",
                    "pm3000-acme-v5-acceptance/SHA256SUMS",
                    "pm3000-acme-v5-acceptance/verify.py",
                    "pm3000-acme-v5-acceptance/run.sh",
                    "pm3000-acme-v5-acceptance/pm3000-acme",
                ])
                for info in archive.infolist():
                    mode = (info.external_attr >> 16) & 0o777
                    expected = 0o755 if info.filename.endswith((".py", ".sh", "pm3000-acme")) else 0o644
                    self.assertEqual(mode, expected, info.filename)
                run = archive.read("pm3000-acme-v5-acceptance/run.sh").decode("ascii")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            self.assertIn(digest, run)
            self.assertNotIn("sha256sum", run)
            self.assertIn("openssl dgst -sha256", run)
            self.assertNotIn("scp ", run)
            self.assertEqual(run.count("| ssh "), 1)
            self.assertIn("ControlMaster=no", run)
            self.assertIn("ControlPath=none", run)
            self.assertIn("ControlPersist=no", run)
            self.assertIn("tarfile.USTAR_FORMAT", run)
            self.assertIn("/tmp/pm3000-acme-v5-acceptance", run)
            self.assertEqual(run.count('renew --foreground --debug'), 1)
            self.assertIn("trap", run)
            self.assertIn("temporary_cleanup=complete", run)
            self.assertIn("http01_cleanup=complete", run)

            extracted = work / "extracted"
            subprocess.run(["unzip", "-q", str(output), "-d", str(extracted)], check=True)
            root = extracted / "pm3000-acme-v5-acceptance"
            verified = subprocess.run([sys.executable, str(root / "verify.py")], cwd=root,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("bundle.verify.complete=yes", verified.stdout)
            self.assertEqual(stat.S_IMODE((root / "run.sh").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((root / "pm3000-acme").stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
