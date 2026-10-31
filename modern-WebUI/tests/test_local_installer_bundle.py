import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "modern-WebUI" / "deploy"
BUILDER = DEPLOY / "build-local-installer.py"
ACCEPTED_SHA256 = "0aa205b837fa357cf3d7d0eb8a67c3df10fd929d9a8dc5c3a41c0383416832c0"


class LocalInstallerBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.release = self.work / "pm3000-release-test-final.tar"
        self._make_release()
        self.sidecar = Path(str(self.release) + ".sha256")
        digest = hashlib.sha256(self.release.read_bytes()).hexdigest()
        self.sidecar.write_text(f"{digest}  {self.release.name}\n", encoding="ascii")

    def _make_release(self):
        members = [
            ("RELEASE_MANIFEST.json", b'{"git_revision":"abcdef123456","release_id":"test-final"}\n', 0o600),
            ("RELEASE_SHA256SUMS", b"", 0o600),
            ("apache/listen.conf", (ROOT / "modern-WebUI/apache/listen.conf").read_bytes(), 0o644),
            ("apache/pm3000-revive.conf", b"apache\n", 0o644),
            ("bin/pm3000-acme", b"accepted", 0o755),
            ("bin/pm3000-acme-admin", b"admin", 0o4750),
            ("bin/pm3000-atomic-publish", b"publish", 0o755),
            ("bin/pm3000-gsp-session-helper", b"session", 0o4750),
            ("bin/pm3000-rest", b"rest", 0o755),
            ("web/app.js", b"app", 0o644),
            ("web/index.html", b"Build test-final (abcdef123456)", 0o644),
            ("web/styles.css", b"css", 0o644),
        ]
        sums = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, data, _ in members[2:]
        ).encode("ascii")
        members[1] = (members[1][0], sums, members[1][2])
        with tarfile.open(self.release, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = mode
                info.uid = info.gid = 0
                info.mtime = 0
                import io
                archive.addfile(info, io.BytesIO(data))

    def _run_post_acceptance(self, response):
        fake_bin = self.work / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        ssh = fake_bin / "ssh"
        ssh.write_text("#!/bin/sh\nprintf '%s\\n' 'pm3000_acme_status_exit=0'\n", encoding="ascii")
        curl = fake_bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "output=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
            "done\n"
            "printf '%s' \"$ACME_RESPONSE\" >\"$output\"\n"
            "printf 200\n",
            encoding="ascii",
        )
        ssh.chmod(0o755)
        curl.chmod(0o755)
        cookie = self.work / "cookies.txt"
        cookie.write_text("private-cookie\n", encoding="ascii")
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["TMPDIR"] = str(self.work)
        environment["ACME_RESPONSE"] = json.dumps(response, separators=(",", ":"))
        return subprocess.run(
            [str(DEPLOY / "post-install-read-only-acceptance.sh"),
             "root@example", "test-final", "https://example", str(cookie)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
        )

    def test_accepted_hash_and_resolved_documentation_are_pinned(self):
        build = (DEPLOY / "build-accepted-release.sh").read_text(encoding="ascii")
        acceptance = (DEPLOY / "acme-write-acceptance.template.sh").read_text(encoding="ascii")
        blocker = (ROOT / "modern-WebUI/docs/ACME-BOOTSTRAP-BLOCKER.md").read_text(encoding="utf-8")
        self.assertIn(ACCEPTED_SHA256, build)
        self.assertIn(ACCEPTED_SHA256, acceptance)
        self.assertNotIn("4d31d3340505532b02b093e7b83ced8d232feeecbb3b0b01daaf273b5ea617b4", build + acceptance + blocker)
        self.assertIn("resolved", blocker.lower())

    def test_accepted_release_packages_only_exact_hardware_accepted_acme_bytes(self):
        source = (DEPLOY / "build-accepted-release.sh").read_text(encoding="ascii")
        self.assertIn(f"expected_acme_sha256={ACCEPTED_SHA256}", source)
        self.assertIn('[ "$actual_acme_sha256" = "$expected_acme_sha256" ]', source)
        self.assertIn('--acme-binary "$accepted_acme"', source)
        self.assertIn('[ "$packaged_acme_sha256" = "$expected_acme_sha256" ]', source)
        self.assertEqual(
            hashlib.sha256((ROOT / "components/pm3000-acme/build/pm3000-acme").read_bytes()).hexdigest(),
            ACCEPTED_SHA256,
        )

    def test_post_install_acceptance_supports_closed_unconfigured_and_configured_projections(self):
        source = (DEPLOY / "post-install-read-only-acceptance.sh").read_text(encoding="ascii")
        self.assertIn('set(value) == {"configured", "caInstalled", "renewal"}', source)
        self.assertIn('set(value) != {"enabled", "directoryUrl", "caFile", "dnsNames", "revision", "renewal"}', source)
        self.assertIn('/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem', source)
        self.assertNotIn("status output mismatch", source)
        self.assertIn("/api/v1/settings/acme", source)
        self.assertIn("acme_http_projection=%s", source)
        self.assertNotIn("--location", source)
        self.assertIn("trap", source)

    def test_generated_readme_accepts_either_closed_acme_projection(self):
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("configured or unconfigured projection", source)
        self.assertIn("acme_http_projection=configured|unconfigured", source)

    def test_post_install_acceptance_accepts_unconfigured_without_printing_body(self):
        response = {"configured": False, "caInstalled": True, "renewal": {"state": "never_run"}}
        result = self._run_post_acceptance(response)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("acme_http_projection=unconfigured", result.stdout)
        self.assertNotIn(json.dumps(response, separators=(",", ":")), result.stdout + result.stderr)

    def test_post_install_acceptance_accepts_configured_failed_projection(self):
        response = {
            "enabled": True,
            "directoryUrl": "https://acme.example/directory",
            "caFile": "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem",
            "dnsNames": ["pdu.example", "pdu-2.example"],
            "revision": f'"{"a" * 64}"',
            "renewal": {"state": "failed", "phase": "challenge_acceptance", "reason": "rejected"},
        }
        result = self._run_post_acceptance(response)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("acme_http_projection=configured", result.stdout)
        self.assertNotIn("directoryUrl", result.stdout + result.stderr)

    def test_post_install_acceptance_rejects_open_or_invalid_configured_projection(self):
        valid = {
            "enabled": False,
            "directoryUrl": "https://acme.example/directory",
            "caFile": "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem",
            "dnsNames": ["pdu.example"],
            "revision": f'"{"b" * 64}"',
            "renewal": {"state": "failed", "phase": "challenge_acceptance", "reason": "timeout"},
        }
        invalid = []
        invalid.append({**valid, "secret": "must-not-print"})
        invalid.append({**valid, "caFile": "/operator/controlled.pem"})
        invalid.append({**valid, "revision": 'W/"' + "b" * 64 + '"'})
        invalid.append({**valid, "dnsNames": ["duplicate.example", "duplicate.example"]})
        invalid.append({**valid, "renewal": {"state": "failed", "phase": "challenge_acceptance"}})
        invalid.append({**valid, "renewal": {"state": "running", "phase": "order", "reason": "http"}})
        for response in invalid:
            with self.subTest(response=response):
                result = self._run_post_acceptance(response)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("must-not-print", result.stdout + result.stderr)

    def test_native_adapter_documents_complete_twelve_member_archive(self):
        documentation = (ROOT / "modern-WebUI/docs/NATIVE-ADAPTER.md").read_text(encoding="utf-8")
        self.assertIn("complete twelve-member production archive", documentation)
        self.assertNotIn("complete eleven-member production archive", documentation)

    def test_builder_creates_closed_relative_self_verifying_zip(self):
        output = self.work / "installer.zip"
        result = subprocess.run(
            [sys.executable, str(BUILDER), "--release", str(self.release),
             "--output", str(output), "--accepted-acme-sha256",
             hashlib.sha256(b"accepted").hexdigest()],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            self.assertEqual(names, [
                "pm3000-installer/README.md",
                "pm3000-installer/SHA256SUMS",
                "pm3000-installer/verify.py",
                "pm3000-installer/release/pm3000-release-test-final.tar",
                "pm3000-installer/release/pm3000-release-test-final.tar.sha256",
                "pm3000-installer/scripts/device-install.sh",
                "pm3000-installer/scripts/device-rollback.sh",
                "pm3000-installer/scripts/post-install-read-only-acceptance.sh",
                "pm3000-installer/scripts/stage7-first-backup.sh",
                "pm3000-installer/scripts/stage7-install.sh",
            ])
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0o777
                expected = 0o755 if info.filename.endswith((".py", ".sh")) else 0o644
                self.assertEqual(mode, expected, info.filename)
        extract = self.work / "extract"
        with zipfile.ZipFile(output) as archive:
            archive.extractall(extract)
        verifier = extract / "pm3000-installer/verify.py"
        verified = subprocess.run([sys.executable, str(verifier)], cwd=verifier.parent,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("bundle.verify.complete=yes", verified.stdout)
        self.assertIn("release_id=test-final", verified.stdout)
        self.assertIn("git_revision=abcdef123456", verified.stdout)

    def test_verifier_rejects_bundle_member_tampering(self):
        output = self.work / "installer.zip"
        expected = hashlib.sha256(b"accepted").hexdigest()
        result = subprocess.run([sys.executable, str(BUILDER), "--release", str(self.release),
                                 "--output", str(output), "--accepted-acme-sha256", expected])
        self.assertEqual(result.returncode, 0)
        extract = self.work / "tampered"
        with zipfile.ZipFile(output) as archive:
            archive.extractall(extract)
        root = extract / "pm3000-installer"
        (root / "scripts/stage7-install.sh").write_text("tampered\n", encoding="ascii")
        result = subprocess.run([sys.executable, str(root / "verify.py")], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
