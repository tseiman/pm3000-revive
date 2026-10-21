import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-device-compatibility.sh"
BACKUP_SCRIPT = ROOT / "modern-WebUI" / "deploy" / "stage7-first-backup.sh"
DEPLOY = ROOT / "modern-WebUI" / "deploy"
TARGET = "root@pdu1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Stage7DeviceCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["make", "-C", str(DEPLOY), "host"], check=True,
                       stdout=subprocess.DEVNULL)
        cls.host_helper = DEPLOY / "build" / "pm3000-atomic-publish-host"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.log = self.root / "transport.log"
        self.environment = os.environ.copy()
        self.environment["PATH"] = f"{self.fake_bin}:{self.environment['PATH']}"
        self.environment["FAKE_TRANSPORT_LOG"] = str(self.log)
        device = self.root / "device"
        private_rest = device / "mnt/hdUser/pm3000-revive/rest"
        private_credentials = device / "etc/pm3000-rest"
        private_rest.mkdir(parents=True, mode=0o700)
        private_credentials.mkdir(parents=True, mode=0o700)
        for path, payload in (
            (private_rest / "tokens.json", b"{}\n"),
            (private_rest / "tokens.json.lock", b""),
            (private_credentials / "controller.credentials", b"user\npassword\n"),
        ):
            path.write_bytes(payload)
            path.chmod(0o600)
        self.environment["FAKE_DEVICE_ROOT"] = str(device)
        self.backup = self._create_real_backup()
        self.package = self.root / "pm3000-release-test.tar"
        self._create_package()
        self._install_transport_fakes()

    def _create_real_backup(self):
        fixture = self.root / "fixture.tar"
        with tarfile.open(fixture, "w") as archive:
            for name in ("etc/version", "mnt/hdUser/state", "usr/share/apache2/htdocs/index.xml"):
                payload = (name + "\n").encode()
                member = tarfile.TarInfo(name)
                member.mode = 0o600
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        fake_ssh = self.fake_bin / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "program = sys.stdin.read()\n"
            "if 'tar cf -' in program:\n"
            "    sys.stdout.buffer.write(pathlib.Path(os.environ['FAKE_ARCHIVE']).read_bytes())\n"
            "else:\n"
            "    print('pm3000_full_backup.format=1')\n"
            "    print('system.machine=ppc')\n"
            "    print('excluded.virtual=dev,proc,sys')\n"
            "    print('pm3000_full_backup.complete=yes')\n"
        )
        fake_ssh.chmod(0o755)
        environment = self.environment.copy()
        environment["FAKE_ARCHIVE"] = str(fixture)
        result = subprocess.run(
            ["bash", str(BACKUP_SCRIPT), "--target", TARGET, "--backup-dir", "backups"],
            cwd=self.root, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = list((self.root / "backups").glob("stage7-full-backup-*"))
        self.assertEqual(len(backups), 1)
        return backups[0]

    def _create_package(self, extra_member=False, malicious_link=None):
        helper = self.host_helper.read_bytes()
        rest = (
            b"#!/bin/sh\n"
            b"printf 'Status: 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n'\n"
            b"printf '{\"apiVersion\":\"v1\",\"status\":\"live\"}\\n'\n"
        )
        members = [
            ("RELEASE_MANIFEST.json", b"{}\n", 0o600),
            ("RELEASE_SHA256SUMS", b"test\n", 0o600),
            ("apache/pm3000-revive.conf", b"test\n", 0o644),
            ("bin/pm3000-atomic-publish", helper, 0o755),
            ("bin/pm3000-rest", rest, 0o755),
            ("web/app.js", b"test\n", 0o644),
            ("web/index.html", b"test\n", 0o644),
            ("web/styles.css", b"test\n", 0o644),
        ]
        if extra_member:
            members.append(("unexpected", b"no\n", 0o600))
        with tarfile.open(self.package, "w") as archive:
            for name, payload, mode in members:
                member = tarfile.TarInfo(name)
                member.mode = mode
                if name == "web/app.js" and malicious_link is not None:
                    link_type, target = malicious_link
                    member.type = tarfile.SYMTYPE if link_type == "symlink" else tarfile.LNKTYPE
                    member.linkname = target
                    archive.addfile(member)
                    continue
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        Path(str(self.package) + ".sha256").write_text(
            f"{sha256(self.package)}  {self.package.name}\n"
        )

    def _install_transport_fakes(self):
        fake_ssh = self.fake_bin / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys\n"
            "log = pathlib.Path(os.environ['FAKE_TRANSPORT_LOG'])\n"
            "body = sys.stdin.buffer.read()\n"
            "with log.open('ab') as stream:\n"
            "    stream.write(('ssh ' + json.dumps(sys.argv[1:]) + '\\n').encode())\n"
            "    stream.write(body)\n"
            "    stream.write(b'\\n---remote-body-end---\\n')\n"
            "device = os.environ['FAKE_DEVICE_ROOT'].encode()\n"
            "body = body.replace(b'/mnt/hdUser/pm3000-revive/rest', device + b'/mnt/hdUser/pm3000-revive/rest')\n"
            "body = body.replace(b'/etc/pm3000-rest', device + b'/etc/pm3000-rest')\n"
            "if len(sys.argv) >= 3 and sys.argv[2] == 'sh':\n"
            "    result = subprocess.run(['sh', *sys.argv[3:]], input=body)\n"
            "else:\n"
            "    result = subprocess.run(['sh', '-c', sys.argv[2]])\n"
            "raise SystemExit(result.returncode)\n"
        )
        fake_ssh.chmod(0o755)
        fake_scp = self.fake_bin / "scp"
        fake_scp.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, shutil, sys\n"
            "log = pathlib.Path(os.environ['FAKE_TRANSPORT_LOG'])\n"
            "with log.open('a') as stream: stream.write('scp ' + json.dumps(sys.argv[1:]) + '\\n')\n"
            "if os.environ.get('FAKE_SCP_FAIL') == 'yes': raise SystemExit(7)\n"
            "source = pathlib.Path(sys.argv[-2])\n"
            "original = os.environ.get('FAKE_MUTATE_ORIGINAL')\n"
            "if original: pathlib.Path(original).write_bytes(b'mutated after snapshot')\n"
            "destination = pathlib.Path(sys.argv[-1].split(':', 1)[1])\n"
            "shutil.copyfile(source, destination)\n"
        )
        fake_scp.chmod(0o755)

    def run_compatibility(self, target=TARGET, environment=None):
        return subprocess.run(
            ["bash", str(SCRIPT), target, str(self.package), str(self.backup)],
            cwd=self.root, env=environment or self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def assert_no_remote_tree(self):
        self.assertEqual(list(Path("/tmp").glob("pm3000-stage7-compat-*")), [])

    def test_real_backup_gate_runs_exact_tmp_compatibility_and_cleans_up(self):
        result = self.run_compatibility()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("compatibility.complete=yes", result.stdout)
        self.assertIn("apply=no", result.stdout)
        transport = self.log.read_text()
        self.assertIn('scp ["-O"', transport)
        self.assertIn("--verify-release", transport)
        self.assertIn("PATH_INFO=/health", transport)
        self.assertNotIn("/etc/apache2", transport)
        self.assertIn("--verify-private-regular /mnt/hdUser/pm3000-revive/rest/tokens.json", transport)
        self.assertIn("--verify-private-regular /etc/pm3000-rest/controller.credentials", transport)
        self.assert_no_remote_tree()

    def test_rejects_backup_from_other_target_before_transport(self):
        result = self.run_compatibility("root@other-pdu")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target does not match", result.stderr)
        self.assertFalse(self.log.exists())

    def test_rejects_tampered_backup_before_transport(self):
        with (self.backup / "BACKUP_ARCHIVE.tar").open("ab") as stream:
            stream.write(b"tampered")
        result = self.run_compatibility()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("backup digest mismatch", result.stderr)
        self.assertFalse(self.log.exists())

    def test_rejects_bad_release_sidecar_before_transport(self):
        Path(str(self.package) + ".sha256").write_text("0" * 64 + f"  {self.package.name}\n")
        result = self.run_compatibility()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release package digest mismatch", result.stderr)
        self.assertFalse(self.log.exists())

    def test_remote_allowlist_failure_cleans_up(self):
        self._create_package(extra_member=True)
        result = self.run_compatibility()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release archive allowlist mismatch", result.stderr)
        self.assert_no_remote_tree()

    def test_symlink_member_cannot_modify_external_target(self):
        external = self.root / "external-target"
        external.write_text("unchanged\n")
        external.chmod(0o600)
        self._create_package(malicious_link=("symlink", str(external)))
        result = self.run_compatibility()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(external.read_text(), "unchanged\n")
        self.assertEqual(external.stat().st_mode & 0o777, 0o600)
        self.assert_no_remote_tree()

    def test_hardlink_member_is_rejected_and_cleaned_up(self):
        self._create_package(malicious_link=("hardlink", "bin/pm3000-rest"))
        result = self.run_compatibility()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_tree()

    def test_scp_failure_cleans_up(self):
        environment = self.environment.copy()
        environment["FAKE_SCP_FAIL"] = "yes"
        result = self.run_compatibility(environment=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_tree()
        self.assertIn("rm -rf", self.log.read_text())

    def test_scp_transfers_private_snapshot_not_mutated_original_path(self):
        environment = self.environment.copy()
        environment["FAKE_MUTATE_ORIGINAL"] = str(self.package)
        result = self.run_compatibility(environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.package.read_bytes(), b"mutated after snapshot")
        scp_line = next(line for line in self.log.read_text().splitlines() if line.startswith("scp "))
        self.assertNotIn(str(self.package), scp_line)
        self.assertIn("pm3000-stage7-compat-host.", scp_line)
        self.assert_no_remote_tree()

    def test_rejects_option_like_target(self):
        result = self.run_compatibility("-oProxyCommand=false")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe SSH target", result.stderr)
        self.assertFalse(self.log.exists())

    def test_script_has_no_install_or_power_scope(self):
        source = SCRIPT.read_text()
        for forbidden in (
            "/etc/apache2", "/mnt/hdUser", "device-install.sh", "apache2 reload",
            "httpd -k", "reboot", "poweroff", "avtrans",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.lower())
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
