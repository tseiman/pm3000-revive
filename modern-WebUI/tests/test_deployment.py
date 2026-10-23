import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODERN = ROOT / "modern-WebUI"
DEPLOY = MODERN / "deploy"
HELPER = DEPLOY / "deployment.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("stage6_deployment", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def device_install_function_harness():
    installer = (DEPLOY / "device-install.sh").read_text(encoding="ascii")
    begin = "# BEGIN DISK PREFLIGHT TEST FUNCTIONS\n"
    end = "# END DISK PREFLIGHT TEST FUNCTIONS\n"
    functions = installer.split(begin, 1)[1].split(end, 1)[0]
    return "#!/bin/sh\nset -eu\n" + functions + r'''
operation=$1
shift
case "$operation" in
    preflight) check_release_capacity "$1" "$2" "$3";;
    extract) extract_release_archive "$1" "$2";;
    *) exit 2;;
esac
'''


class DeviceInstallDiskPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.archive = self.root / "release.tar"
        self.archive.write_bytes(b"archive")
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.harness = self.root / "harness.sh"
        self.harness.write_text(device_install_function_harness(), encoding="ascii")
        self.harness.chmod(0o755)
        self._write_command("wc", '#!/bin/sh\nprintf "%b" "$FAKE_WC_OUTPUT"\nexit "${FAKE_WC_STATUS:-0}"\n')
        self._write_command("df", '#!/bin/sh\nprintf "%b" "$FAKE_DF_OUTPUT"\nexit "${FAKE_DF_STATUS:-0}"\n')
        self._write_command(
            "tar",
            '#!/bin/sh\n'
            '[ "${FAKE_TAR_MODE:-complete}" != fail ] || exit 9\n'
            'mkdir -p RELEASE_MANIFEST.json.d apache bin web\n'
            'rm -rf RELEASE_MANIFEST.json.d\n'
            'for member in RELEASE_MANIFEST.json RELEASE_SHA256SUMS apache/pm3000-revive.conf '
            'bin/pm3000-atomic-publish bin/pm3000-gsp-session-helper bin/pm3000-rest '
            'web/app.js web/index.html web/styles.css; do\n'
            '  [ "${FAKE_TAR_MODE:-complete}:$member" = incomplete:web/styles.css ] || : >"$member"\n'
            'done\n',
        )

    def _write_command(self, name, text):
        command = self.bin / name
        command.write_text(text, encoding="ascii")
        command.chmod(0o755)

    def run_harness(self, operation, *, wc_output="1024", df_output="fs 1000 100 900 10% /mnt/hdUser\n",
                    wc_status=0, df_status=0, tar_mode="complete", filesystem="/mnt/hdUser"):
        env = os.environ.copy()
        env.update({
            "PATH": str(self.bin) + os.pathsep + env["PATH"],
            "FAKE_WC_OUTPUT": wc_output,
            "FAKE_WC_STATUS": str(wc_status),
            "FAKE_DF_OUTPUT": df_output,
            "FAKE_DF_STATUS": str(df_status),
            "FAKE_TAR_MODE": tar_mode,
        })
        arguments = ([str(self.archive), filesystem, str(self.scratch)]
                     if operation == "preflight" else [str(self.archive), str(self.stage)])
        return subprocess.run(
            [str(self.harness), operation, *arguments], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def test_low_space_fails_and_exact_boundary_passes(self):
        persistent_release_root = self.root / "persistent" / "webui" / "releases"
        staging = persistent_release_root / ".candidate.stage6-tmp"
        low = self.run_harness(
            "preflight", df_output="fs 1000 744 256 75% /mnt/hdUser\n",
            filesystem=str(persistent_release_root),
        )
        self.assertNotEqual(low.returncode, 0)
        self.assertIn("required_kib=257 available_kib=256", low.stderr)
        self.assertFalse(persistent_release_root.exists())
        self.assertFalse(staging.exists())
        boundary = self.run_harness("preflight", df_output="fs 1000 743 257 74% /mnt/hdUser\n")
        self.assertEqual(boundary.returncode, 0, boundary.stderr)

    def test_malformed_and_empty_df_output_fail_closed(self):
        for output in ("", "filesystem blocks used available capacity mounted\n", "fs 1000 100\n"):
            with self.subTest(output=output):
                result = self.run_harness("preflight", df_output=output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid release filesystem capacity", result.stderr)

    def test_nonzero_df_status_is_not_masked_by_last_line_parsing(self):
        result = self.run_harness(
            "preflight", df_status=7,
            df_output="fs 1000 743 257 74% /mnt/hdUser\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release filesystem capacity unavailable", result.stderr)

    def test_wc_whitespace_is_accepted_and_ceil_boundary_is_enforced(self):
        below_ceiling = self.run_harness(
            "preflight", wc_output="  \t1025 \t\n",
            df_output="header\nfs 1000 743 257 74% /mnt/hdUser\n",
        )
        self.assertNotEqual(below_ceiling.returncode, 0)
        self.assertIn("required_kib=258 available_kib=257", below_ceiling.stderr)
        exact_ceiling = self.run_harness(
            "preflight", wc_output="  \t1025 \t\n",
            df_output="header\nfs 1000 742 258 74% /mnt/hdUser\n",
        )
        self.assertEqual(exact_ceiling.returncode, 0, exact_ceiling.stderr)

    def test_nonzero_wc_status_fails_closed(self):
        result = self.run_harness("preflight", wc_output="1024\n", wc_status=7)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release archive size unavailable", result.stderr)

    def test_oversized_wc_value_is_rejected_before_shell_arithmetic(self):
        result = self.run_harness("preflight", wc_output="1000000000\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid release archive size", result.stderr)

    def test_oversized_available_value_is_rejected_before_shell_arithmetic(self):
        result = self.run_harness(
            "preflight", df_output="fs 1000000000 0 1000000000 0% /mnt/hdUser\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid release filesystem capacity", result.stderr)

    def test_explicit_tar_failure_is_reported(self):
        result = self.run_harness("extract", tar_mode="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release archive extraction failed", result.stderr)

    def test_tar_success_with_incomplete_tree_is_rejected(self):
        result = self.run_harness("extract", tar_mode="incomplete")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release archive extraction incomplete: web/styles.css", result.stderr)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.source = self.work / "source"
        (self.source / "web").mkdir(parents=True)
        (self.source / "native" / "build").mkdir(parents=True)
        (self.source / "deploy").mkdir(parents=True)
        (self.source / "deploy" / "build").mkdir()
        (self.source / "web" / "release-files.txt").write_text(
            "index.html\ttext/html; charset=utf-8\nstyles.css\ttext/css; charset=utf-8\napp.js\ttext/javascript; charset=utf-8\n", encoding="utf-8"
        )
        for name, data in {
            "index.html": b"index-v1 Build __PM3000_RELEASE_ID__ (__PM3000_GIT_REVISION__)",
            "styles.css": b"css-v1",
            "app.js": b"js-v1",
        }.items():
            (self.source / "web" / name).write_bytes(data)
        binary = self.source / "native" / "build" / "pm3000-rest-ppc32"
        binary.write_bytes(b"ELF-test")
        binary.chmod(0o755)
        session_helper = self.source / "native" / "build" / "pm3000-gsp-session-helper-ppc32"
        session_helper.write_bytes(b"ELF-session-helper-test")
        session_helper.chmod(0o755)
        helper = self.source / "deploy" / "build" / "pm3000-atomic-publish-ppc32"
        helper.write_bytes(b"ELF-helper-test")
        helper.chmod(0o755)
        (self.source / "deploy" / "pm3000-revive.conf").write_text(
            "Alias /modern/ /mnt/hdUser/pm3000-revive/webui/current/web/\n",
            encoding="utf-8",
        )

    def test_package_contains_only_allowlist_and_finished_byte_checksums(self):
        helper = load_helper()
        output = self.work / "release.tar"
        helper.build_release(self.source, output, "r1", "abcdef123456")

        with tarfile.open(output, "r:") as archive:
            names = archive.getnames()
            self.assertEqual(
                names,
                [
                    "RELEASE_MANIFEST.json",
                    "RELEASE_SHA256SUMS",
                    "apache/pm3000-revive.conf",
                    "bin/pm3000-atomic-publish",
                    "bin/pm3000-gsp-session-helper",
                    "bin/pm3000-rest",
                    "web/app.js",
                    "web/index.html",
                    "web/styles.css",
                ],
            )
            manifest = json.load(archive.extractfile("RELEASE_MANIFEST.json"))
            self.assertEqual(manifest["release_id"], "r1")
            modes = {entry["path"]: entry["mode"] for entry in manifest["files"]}
            self.assertEqual(0o4750, modes["bin/pm3000-gsp-session-helper"])
            index = archive.extractfile("web/index.html").read()
            self.assertIn(b"Build r1 (abcdef123456)", index)
            self.assertNotIn(b"__PM3000_", index)
            regular_bytes = sum(member.size for member in archive.getmembers() if member.isfile())
            self.assertLessEqual(regular_bytes, helper.MAX_RELEASE_REGULAR_BYTES)
            for entry in manifest["files"]:
                payload = archive.extractfile(entry["path"]).read()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"])
                self.assertEqual(len(payload), entry["size"])

    def test_package_rejects_complete_allowlist_above_release_budget(self):
        helper = load_helper()
        output = self.work / "oversized-release.tar"
        binary = self.source / "native" / "build" / "pm3000-rest-ppc32"
        binary.write_bytes(b"X" * (448 * 1024))
        with self.assertRaisesRegex(helper.DeploymentError, "448 KiB"):
            helper.build_release(self.source, output, "r1", "abcdef123456")
        self.assertFalse(output.exists())

    def test_deployment_documentation_matches_nine_member_archive(self):
        readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
        self.assertEqual(2, readme.count("nine-member allowlist"))
        self.assertNotIn("eight-member allowlist", readme)


class DeploymentSimulationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "device"
        self.backups = self.base / "backups"
        self.package = self.base / "release.tar"
        self.helper = load_helper()
        self._make_package("r2")
        self.legacy = self.root / "legacy-index"
        self.legacy.parent.mkdir(parents=True)
        self.legacy.write_bytes(b"legacy-ok")
        self.token = self.root / "mnt/hdUser/pm3000-revive/rest/tokens.json"
        self.token.parent.mkdir(parents=True)
        self.token.write_bytes(b'{"private":"token-store"}\n')
        self.old_release = self.root / "mnt/hdUser/pm3000-revive/webui/releases/r1"
        (self.old_release / "web").mkdir(parents=True)
        (self.old_release / "web/index.html").write_bytes(b"old-index")
        current = self.old_release.parent.parent / "current"
        current.symlink_to("releases/r1")
        self.config = self.root / "etc/apache2/conf.d/pm3000-revive.conf"
        self.config.parent.mkdir(parents=True)
        self.config.write_bytes(b"old-config\n")
        self.original_token = self.token.read_bytes()
        self.original_config = self.config.read_bytes()
        self.original_current = os.readlink(current)

    def _make_package(self, release_id):
        source = self.base / f"source-{release_id}"
        (source / "web").mkdir(parents=True, exist_ok=True)
        (source / "native/build").mkdir(parents=True, exist_ok=True)
        (source / "deploy").mkdir(parents=True, exist_ok=True)
        (source / "deploy/build").mkdir(parents=True, exist_ok=True)
        (source / "web/release-files.txt").write_text(
            "index.html\ttext/html\nstyles.css\ttext/css\napp.js\ttext/javascript\n"
        )
        for name in ("index.html", "styles.css", "app.js"):
            data = (release_id + "-" + name).encode()
            if name == "index.html":
                data += b" Build __PM3000_RELEASE_ID__ (__PM3000_GIT_REVISION__)"
            (source / "web" / name).write_bytes(data)
        (source / "native/build/pm3000-rest-ppc32").write_bytes(b"binary-" + release_id.encode())
        (source / "native/build/pm3000-gsp-session-helper-ppc32").write_bytes(
            b"session-helper-" + release_id.encode()
        )
        (source / "deploy/build/pm3000-atomic-publish-ppc32").write_bytes(b"helper-" + release_id.encode())
        (source / "deploy/pm3000-revive.conf").write_bytes(b"new-config-" + release_id.encode() + b"\n")
        self.helper.build_release(source, self.package, release_id)

    def deploy(self, fault=None):
        return self.helper.deploy_simulated(
            self.root, self.package, self.backups, fault=fault,
            syntax_check=lambda: fault != "config_check",
            reload_apache=lambda: fault != "reload",
            modern_health=lambda: fault != "health",
        )

    def assert_old_state(self):
        current = self.root / "mnt/hdUser/pm3000-revive/webui/current"
        self.assertEqual(os.readlink(current), self.original_current)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertFalse(self.old_release.parent / "r2" in [])
        self.assertFalse((self.old_release.parent / "r2").exists())
        self.assertFalse((self.old_release.parent / ".r2.stage6-tmp").exists())
        self.assertEqual(self.token.read_bytes(), self.original_token)

    def test_update_creates_verified_backup_before_stage_and_installs_exact_package(self):
        result = self.deploy()
        marker = Path(result["backup_dir"]) / "BACKUP_COMPLETE"
        self.assertTrue(marker.is_file())
        events = (Path(result["backup_dir"]) / "EVENTS").read_text().splitlines()
        self.assertLess(events.index("BACKUP_COMPLETE"), events.index("STAGE_PACKAGE"))
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), "releases/r2")
        with tarfile.open(self.package) as archive:
            expected = archive.extractfile("web/index.html").read()
        self.assertEqual((self.old_release.parent / "r2/web/index.html").read_bytes(), expected)
        self.assertEqual(stat.S_IMODE((self.old_release.parent / "r2").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.old_release.parent / "r2/web").stat().st_mode), 0o755)
        self.assertEqual(self.token.read_bytes(), self.original_token)
        with tarfile.open(Path(result["backup_dir"]) / "backup.tar") as backup:
            names = set(backup.getnames())
            self.assertIn("files/mnt/hdUser/pm3000-revive/rest/tokens.json", names)
            self.assertIn("files/mnt/hdUser/pm3000-revive/webui/releases/r1/web/index.html", names)
        manifest = json.loads((Path(result["backup_dir"]) / "BACKUP_MANIFEST.json").read_text())
        self.assertEqual(manifest["format"], 2)
        self.assertEqual(len(manifest["transaction_id"]), 32)
        self.assertIn("captured_at", manifest)
        self.assertEqual(manifest["target_identity"]["transport"], "simulation")
        active = json.loads((self.root / "mnt/hdUser/pm3000-revive/deploy/ACTIVE_TRANSACTION.json").read_text())
        self.assertEqual(active["transaction_id"], manifest["transaction_id"])
        by_path = {entry["path"]: entry for entry in manifest["entries"]}
        self.assertEqual(by_path["/mnt/hdUser/pm3000-revive/webui/current"]["type"], "symlink")
        self.assertEqual(by_path["/mnt/hdUser/pm3000-revive/webui/current"]["target"], "releases/r1")

    def test_fresh_install_records_absent_scope(self):
        shutil.rmtree(self.old_release.parent.parent)
        self.config.unlink()
        result = self.deploy()
        manifest = json.loads((Path(result["backup_dir"]) / "BACKUP_MANIFEST.json").read_text())
        by_path = {entry["path"]: entry for entry in manifest["entries"]}
        self.assertEqual(by_path["/mnt/hdUser/pm3000-revive/webui/current"]["type"], "absent")
        self.assertEqual(by_path["/etc/apache2/conf.d/pm3000-revive.conf"]["type"], "absent")

    def test_every_post_commit_failure_restores_old_state(self):
        for fault in ("state_publish", "active_publish", "after_release", "after_current",
                      "after_config", "config_check", "reload", "health", "complete_publish"):
            with self.subTest(fault=fault):
                with self.assertRaises(self.helper.DeploymentError):
                    self.deploy(fault)
                self.assert_old_state()

    def test_process_crash_boundaries_are_recoverable(self):
        script = DEPLOY / "deployment.py"
        for fault, exit_code in (
            ("crash_after_state", 86),
            ("crash_after_active", 87),
            ("crash_after_temp_dir", 90),
            ("crash_after_first_payload", 91),
            ("crash_after_release", 92),
            ("crash_after_current", 88),
            ("crash_after_config", 89),
        ):
            with self.subTest(fault=fault):
                before = set(self.backups.iterdir()) if self.backups.exists() else set()
                result = subprocess.run([
                    sys.executable, str(script), "deploy-sim",
                    "--root", str(self.root), "--package", str(self.package),
                    "--backup-dir", str(self.backups), "--fault", fault,
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertEqual(result.returncode, exit_code)
                created = set(self.backups.iterdir()) - before
                self.assertEqual(len(created), 1)
                backup = created.pop()
                self.assertFalse((backup / "DEPLOYMENT_COMPLETE").exists())
                if fault == "crash_after_state":
                    state_path = backup / "DEPLOYMENT_STATE.json"
                    original_state = state_path.read_bytes()
                    modified_state = json.loads(original_state)
                    modified_state["created_release"] = not modified_state["created_release"]
                    state_path.write_text(json.dumps(modified_state, sort_keys=True, separators=(",", ":")) + "\n")
                    with self.assertRaisesRegex(self.helper.DeploymentError, "state integrity"):
                        self.helper.rollback_simulated(self.root, backup)
                    state_path.write_bytes(original_state)
                self.helper.rollback_simulated(self.root, backup)
                self.assert_old_state()
                self.helper.rollback_simulated(self.root, backup)

    def test_fresh_install_crash_during_release_creation_restores_absent_tree(self):
        script = DEPLOY / "deployment.py"
        webui = self.root / "mnt/hdUser/pm3000-revive/webui"
        shutil.rmtree(webui)
        self.config.unlink()
        active = self.root / "mnt/hdUser/pm3000-revive/deploy/ACTIVE_TRANSACTION.json"
        for fault, exit_code in (
            ("crash_after_temp_dir", 90),
            ("crash_after_first_payload", 91),
            ("crash_after_release", 92),
        ):
            with self.subTest(fault=fault):
                before = set(self.backups.iterdir()) if self.backups.exists() else set()
                result = subprocess.run([
                    sys.executable, str(script), "deploy-sim",
                    "--root", str(self.root), "--package", str(self.package),
                    "--backup-dir", str(self.backups), "--fault", fault,
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertEqual(result.returncode, exit_code)
                backup = (set(self.backups.iterdir()) - before).pop()
                self.helper.rollback_simulated(self.root, backup)
                self.assertFalse(webui.exists())
                self.assertFalse(self.config.exists())
                self.assertFalse(active.exists())
                self.helper.rollback_simulated(self.root, backup)

    def test_prebackup_faults_make_no_install_or_staging_writes(self):
        for fault in ("backup_copy", "backup_digest", "backup_incomplete"):
            with self.subTest(fault=fault):
                with self.assertRaises(self.helper.DeploymentError):
                    self.deploy(fault)
                self.assert_old_state()
                self.assertFalse((self.root / "tmp/stage6-stage").exists())

    def test_verified_package_snapshot_survives_source_replacement(self):
        result = self.deploy("mutate_package_after_backup")
        self.assertEqual(result["release_id"], "r2")
        self.assertEqual(
            os.readlink(self.old_release.parent.parent / "current"), "releases/r2"
        )

    def test_release_read_uses_single_verified_snapshot(self):
        r2_package = self.package.read_bytes()
        r2_sidecar = self.package.with_name(self.package.name + ".sha256").read_bytes()
        self._make_package("r3")
        r3_package = self.package.read_bytes()
        self.package.write_bytes(r2_package)
        self.package.with_name(self.package.name + ".sha256").write_bytes(r2_sidecar)
        original_snapshot = self.helper._read_regular_snapshot

        def replace_after_snapshot(path, label):
            data = original_snapshot(path, label)
            if label == "release package":
                self.package.write_bytes(r3_package)
            return data

        self.helper._read_regular_snapshot = replace_after_snapshot
        try:
            manifest, _ = self.helper._read_release(self.package)
        finally:
            self.helper._read_regular_snapshot = original_snapshot
        self.assertEqual(manifest["release_id"], "r2")

    def test_failed_stage_never_commits(self):
        for fault in ("stage_copy", "stage_check"):
            with self.subTest(fault=fault):
                self._make_package("r2")
                with self.assertRaises(self.helper.DeploymentError):
                    self.deploy(fault)
                self.assert_old_state()

    def test_rejects_symlink_attack_in_install_parent(self):
        webui = self.old_release.parent.parent
        shutil.rmtree(webui)
        outside = self.base / "outside"
        outside.mkdir()
        webui.symlink_to(outside)
        with self.assertRaisesRegex(self.helper.DeploymentError, "symlink"):
            self.deploy()
        self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_release_child_symlink_and_unsafe_config_mode(self):
        attacked_release = self.old_release.parent / "r2"
        outside = self.base / "outside-release"
        outside.mkdir()
        attacked_release.symlink_to(outside)
        with self.assertRaisesRegex(self.helper.DeploymentError, "symlink"):
            self.deploy()
        attacked_release.unlink()
        self.config.chmod(0o666)
        with self.assertRaisesRegex(self.helper.DeploymentError, "mode"):
            self.deploy()

    def test_digest_mismatch_and_archive_traversal_are_rejected(self):
        damaged = bytearray(self.package.read_bytes())
        damaged[-1] ^= 1
        self.package.write_bytes(damaged)
        with self.assertRaises(self.helper.DeploymentError):
            self.deploy()
        self._make_package("r2")
        with tarfile.open(self.package, "a") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        sidecar = self.package.with_name(self.package.name + ".sha256")
        sidecar.write_text(hashlib.sha256(self.package.read_bytes()).hexdigest() + "  release.tar\n")
        with self.assertRaisesRegex(self.helper.DeploymentError, "unsafe|unexpected"):
            self.deploy()
        self.assertFalse((self.base / "escape").exists())

    def test_health_failure_reloads_restored_apache_state(self):
        reload_calls = []
        with self.assertRaisesRegex(self.helper.DeploymentError, "health"):
            self.helper.deploy_simulated(
                self.root, self.package, self.backups,
                reload_apache=lambda: reload_calls.append(True) or True,
                modern_health=lambda: False,
            )
        self.assertEqual(reload_calls, [True, True])
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), self.original_current)

    def test_existing_release_payload_drift_blocks_idempotent_retry(self):
        self.deploy()
        (self.old_release.parent / "r2/web/index.html").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(self.helper.DeploymentError, "drifted"):
            self.deploy()

    def test_only_active_transaction_can_be_rolled_back(self):
        first = self.deploy()
        second = self.deploy()
        with self.assertRaisesRegex(self.helper.DeploymentError, "integrity|active"):
            self.helper.rollback_simulated(self.root, Path(first["backup_dir"]))
        self.helper.rollback_simulated(self.root, Path(second["backup_dir"]))
        self.helper.rollback_simulated(self.root, Path(first["backup_dir"]))
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), self.original_current)

    def test_stale_backup_is_not_reused_and_retry_is_idempotent(self):
        stale = self.backups / "stale"
        stale.mkdir(parents=True)
        (stale / "BACKUP_COMPLETE").write_text("stale")
        first = self.deploy()
        second = self.deploy()
        self.assertNotEqual(first["backup_dir"], str(stale))
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), "releases/r2")
        self.assertEqual(self.token.read_bytes(), self.original_token)
        self.assertTrue(Path(second["backup_dir"], "BACKUP_COMPLETE").exists())

    def test_selected_backup_rollback_restores_bytes_and_preserves_tokens(self):
        result = self.deploy()
        self.token.write_bytes(b"new-private-token-state\n")
        self.helper.rollback_simulated(
            self.root, Path(result["backup_dir"]),
            syntax_check=lambda: True, reload_apache=lambda: True,
            legacy_health=lambda: self.legacy.read_bytes() == b"legacy-ok",
        )
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), self.original_current)
        self.assertEqual(self.config.read_bytes(), self.original_config)
        self.assertFalse((self.old_release.parent / "r2").exists())
        self.assertEqual(self.token.read_bytes(), b"new-private-token-state\n")
        self.assertTrue((Path(result["backup_dir"]) / "ROLLBACK_COMPLETE").is_file())
        # A repeated rollback of the exact transaction is a safe no-op.
        self.helper.rollback_simulated(self.root, Path(result["backup_dir"]))

    def test_rollback_resume_after_interrupted_restore(self):
        result = self.deploy()
        backup_dir = Path(result["backup_dir"])
        current = self.old_release.parent.parent / "current"
        original_switch = self.helper._switch_symlink

        def interrupt_current(path, target):
            if path == current:
                raise RuntimeError("simulated process interruption")
            return original_switch(path, target)

        self.helper._switch_symlink = interrupt_current
        try:
            with self.assertRaisesRegex(RuntimeError, "process interruption"):
                self.helper.rollback_simulated(self.root, backup_dir)
        finally:
            self.helper._switch_symlink = original_switch
        self.assertTrue((backup_dir / "ROLLBACK_PENDING").exists())
        self.assertEqual(os.readlink(current), "releases/r2")
        self.helper.rollback_simulated(self.root, backup_dir)
        self.assertEqual(os.readlink(current), "releases/r1")
        self.assertTrue((backup_dir / "ROLLBACK_COMPLETE").exists())

    def test_rollback_complete_is_integrity_bound_and_restored_state_verified(self):
        result = self.deploy()
        backup_dir = Path(result["backup_dir"])
        completion = backup_dir / "ROLLBACK_COMPLETE"
        completion.write_text("forged\n", encoding="ascii")
        with self.assertRaisesRegex(self.helper.DeploymentError, "completion state"):
            self.helper.rollback_simulated(self.root, backup_dir)
        self.assertEqual(os.readlink(self.old_release.parent.parent / "current"), "releases/r2")
        completion.unlink()
        self.helper.rollback_simulated(self.root, backup_dir)
        self.helper._switch_symlink(self.old_release.parent.parent / "current", "releases/r2")
        with self.assertRaisesRegex(self.helper.DeploymentError, "rollback state drifted"):
            self.helper.rollback_simulated(self.root, backup_dir)

    def test_rollback_refuses_live_managed_path_drift(self):
        path_names = [
            "config", "current", "release-manifest", "release-checksum-list",
            "release-payload", "release-extra",
            "release-root-0777", "release-root-0775", "release-root-0757",
        ]
        if os.geteuid() == 0:
            path_names.extend(("release-root-owner", "release-directory-owner", "release-file-owner"))
        for path_name in path_names:
            with self.subTest(path=path_name):
                result = self.deploy()
                release = self.old_release.parent / "r2"
                if path_name == "config":
                    self.config.write_bytes(b"operator-edit\n")
                elif path_name == "current":
                    current = self.old_release.parent.parent / "current"
                    current.unlink()
                    current.symlink_to("releases/r1")
                elif path_name == "release-manifest":
                    (release / "RELEASE_MANIFEST.json").write_bytes(b"{}\n")
                elif path_name == "release-checksum-list":
                    (release / "RELEASE_SHA256SUMS").write_bytes(b"0" * 64 + b"  web/index.html\n")
                elif path_name == "release-payload":
                    (release / "web/index.html").write_bytes(b"operator-edit\n")
                elif path_name == "release-extra":
                    (release / "unexpected").write_bytes(b"operator-file\n")
                elif path_name.startswith("release-root-0"):
                    release.chmod(int(path_name.rsplit("-", 1)[1], 8))
                elif path_name == "release-root-owner":
                    os.chown(release, 65534, 65534)
                elif path_name == "release-directory-owner":
                    os.chown(release / "web", 65534, 65534)
                else:
                    os.chown(release / "web/index.html", 65534, 65534)
                with self.assertRaisesRegex(self.helper.DeploymentError, "drifted|unsafe"):
                    self.helper.rollback_simulated(self.root, Path(result["backup_dir"]))
                # Recreate the fixture for the next subtest.
                self.tearDown()
                self.setUp()

    def test_rollback_rejects_incomplete_or_modified_backup(self):
        result = self.deploy()
        backup = Path(result["backup_dir"])
        (backup / "BACKUP_COMPLETE").unlink()
        with self.assertRaises(self.helper.DeploymentError):
            self.helper.rollback_simulated(self.root, backup)
        (backup / "BACKUP_COMPLETE").write_text("bad\n")
        with self.assertRaises(self.helper.DeploymentError):
            self.helper.rollback_simulated(self.root, backup)
    def test_rollback_syntax_failure_does_not_reload(self):
        result = self.deploy()
        reload_calls = []
        with self.assertRaisesRegex(self.helper.DeploymentError, "syntax"):
            self.helper.rollback_simulated(
                self.root, Path(result["backup_dir"]),
                syntax_check=lambda: False,
                reload_apache=lambda: reload_calls.append(True) or True,
            )
        self.assertEqual(reload_calls, [])
        backup = Path(result["backup_dir"])
        self.assertTrue((backup / "ROLLBACK_PENDING").is_file())
        self.assertFalse((backup / "ROLLBACK_COMPLETE").exists())
        self.helper.rollback_simulated(self.root, backup)
        self.assertTrue((backup / "ROLLBACK_COMPLETE").is_file())
        self.assertFalse((backup / "ROLLBACK_PENDING").exists())

    def test_rollback_rejects_backup_archive_traversal_even_with_updated_outer_digest(self):
        result = self.deploy()
        backup = Path(result["backup_dir"])
        archive_path = backup / "backup.tar"
        with tarfile.open(archive_path, "a") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        marker_lines = (backup / "BACKUP_COMPLETE").read_text().splitlines()
        marker_lines[0] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        (backup / "BACKUP_COMPLETE").write_text("\n".join(marker_lines) + "\n")
        with self.assertRaisesRegex(self.helper.DeploymentError, "unsafe"):
            self.helper.rollback_simulated(self.root, backup)
        self.assertFalse((self.base / "escape").exists())


class ScriptStructureTests(unittest.TestCase):
    def test_device_helpers_are_posix_sh_and_host_scripts_have_no_command_proxy(self):
        for name in ("device-install.sh", "device-rollback.sh"):
            text = (DEPLOY / name).read_text()
            self.assertTrue(text.startswith("#!/bin/sh\n"))
            self.assertNotIn("[[", text)
            self.assertNotIn("function ", text)
        for name in ("deploy.sh", "rollback.sh"):
            text = (DEPLOY / name).read_text()
            self.assertNotIn("eval ", text)
            self.assertNotIn("$@", text)

        installer = (DEPLOY / "device-install.sh").read_text()
        rollback = (DEPLOY / "device-rollback.sh").read_text()
        atomic_source = (DEPLOY / "atomic-publish.c").read_text()
        self.assertNotIn("tar tf \"$package\" |", installer)
        self.assertNotIn("mv -f", installer)
        self.assertNotIn("mv -f", rollback)
        self.assertIn('root=/mnt/hdUser/pm3000-revive', installer)
        self.assertIn('base=$root/webui', installer)
        self.assertIn('chmod 755 "$root" "$base" "$releases"', installer)
        self.assertIn("--verify-release \"$release\" \"$daemon_gid\"", installer)
        self.assertIn('initialize_private_directory "$root/rest"', installer)
        self.assertNotIn('verify_private_directory /etc/pm3000-rest', installer)
        self.assertIn('initialize_private_regular "$root/rest/tokens.json"', installer)
        self.assertIn('{"generation":1,"schemaVersion":1,"tokens":[]}', installer)
        self.assertIn('initialize_private_regular "$root/rest/tokens.json.lock"', installer)
        self.assertNotIn('controller.credentials', installer)
        helper_precheck = installer.index('bin/pm3000-gsp-session-helper \\\n')
        helper_chown = installer.index('chown 0:"$daemon_gid" "$tmp/bin/pm3000-gsp-session-helper"')
        self.assertLess(helper_precheck, helper_chown)
        self.assertIn('chown 0:"$daemon_gid" "$tmp/bin/pm3000-gsp-session-helper"', installer)
        self.assertIn('chmod 4750 "$tmp/bin/pm3000-gsp-session-helper"', installer)
        self.assertIn('--verify-private-directory-owner "$1" "$daemon_uid"', installer)
        self.assertIn('--verify-private-regular-owner "$1" "$daemon_uid"', installer)
        self.assertNotIn('chown daemon:daemon "$root/rest"', installer)
        self.assertNotIn('chmod 600 "$root/rest/tokens.json"', installer)
        self.assertIn('--set-private-regular-owner "$private_file" "$daemon_uid" "$daemon_gid"', installer)
        self.assertIn('--set-private-directory-owner "$private_directory" "$daemon_uid" "$daemon_gid"', installer)
        self.assertIn("fchown(descriptor, target_uid, target_gid)", atomic_source)
        self.assertIn("fchmod(descriptor, target_mode)", atomic_source)
        self.assertIn("st_uid != geteuid()", atomic_source)
        self.assertIn('package_snapshot=$work/release.tar', installer)
        self.assertNotIn('package path must be absolute', installer)
        self.assertIn('actual=$(sha256_file "$package_snapshot")', installer)
        self.assertIn('openssl dgst -sha256 "$1"', installer)
        self.assertIn('verify_release_sums "$tmp" "$tmp/RELEASE_SHA256SUMS"', installer)
        self.assertIn('tar tf "$package_snapshot"', installer)
        self.assertIn('tar xf "$_extract_archive"', installer)
        self.assertIn('for required_command in df tail tar wc', installer)
        capacity_check = installer.index('check_release_capacity "$package_snapshot" /mnt/hdUser "$work"')
        release_tree_create = installer.index('mkdir -p "$releases"')
        release_tree_chmod = installer.index('chmod 755 "$root" "$base" "$releases"')
        staging_create = installer.index('mkdir -m 700 "$tmp"')
        extraction = installer.index('extract_release_archive "$package_snapshot" "$tmp"')
        private_initialization = installer.index('initialize_private_directory "$root/rest"')
        self.assertLess(capacity_check, release_tree_create)
        self.assertLess(capacity_check, release_tree_chmod)
        self.assertLess(capacity_check, staging_create)
        self.assertLess(extraction, private_initialization)
        self.assertIn('packaged_helper=$tmp/bin/pm3000-atomic-publish', installer)
        self.assertIn('atomic_helper=$work/pm3000-atomic-publish', installer)
        self.assertNotIn('sha256sum', installer)
        self.assertNotIn('tar tf "$package"', installer)
        self.assertNotIn('tar xf "$package"', installer)
        self.assertNotIn('atomic_helper=$5', installer)
        self.assertNotIn('atomic_helper=$3', rollback)
        self.assertIn('package_snapshot=$work/release.tar', rollback)
        self.assertNotIn('package path must be absolute', rollback)
        self.assertIn('atomic_helper=$work/pm3000-atomic-publish', rollback)
        self.assertIn('actual=$(sha256_file "$package_snapshot")', rollback)
        self.assertIn('openssl dgst -sha256 "$1"', rollback)
        self.assertIn('cmp "$package_tree/RELEASE_MANIFEST.json" "$release/RELEASE_MANIFEST.json"', rollback)
        self.assertIn('verify_release_sums "$release" "$release/RELEASE_SHA256SUMS"', rollback)
        self.assertNotIn('sha256sum', rollback)
        self.assertIn('--verify-release "$release" "$daemon_gid"', rollback)
        self.assertIn('bin/pm3000-atomic-publish|bin/pm3000-gsp-session-helper|bin/pm3000-rest', rollback)
        self.assertIn('bin/pm3000-atomic-publish\nbin/pm3000-gsp-session-helper\nbin/pm3000-rest', rollback)
        self.assertIn('bin/pm3000-atomic-publish bin/pm3000-gsp-session-helper bin/pm3000-rest', rollback)
        self.assertIn('[ "$_sum_count" -eq 7 ]', rollback)
        self.assertIn('--verify-private-directory "$restore_dir"', rollback)
        apache = (DEPLOY / "pm3000-revive.conf").read_text()
        self.assertIn("ScriptAlias /api/v1 ", apache)
        self.assertIn("AcceptPathInfo On", apache)
        self.assertIn("DirectoryIndex index.html", apache)
        self.assertNotIn("ScriptAlias /modern/api/v1/", apache)

    def test_atomic_helper_replaces_symlink_to_directory_without_following_it(self):
        subprocess.run(["make", "-C", str(DEPLOY), "clean", "host"], check=True,
                       stdout=subprocess.DEVNULL)
        helper = DEPLOY / "build/pm3000-atomic-publish-host"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            (root / "current").symlink_to("old")
            (root / ".current.next").symlink_to("new")
            subprocess.run([str(helper), str(root), ".current.next", "current", "symlink"], check=True)
            self.assertEqual(os.readlink(root / "current"), "new")
            self.assertEqual(list(old.iterdir()), [])
            regular = root / "regular"
            regular.write_bytes(b"safe")
            subprocess.run([str(helper), "--verify-regular", str(regular)], check=True)
            private_regular = root / "private-regular"
            private_regular.write_bytes(b"secret")
            private_regular.chmod(0o600)
            subprocess.run([str(helper), "--verify-private-regular", str(private_regular)], check=True)
            subprocess.run([
                str(helper), "--verify-private-regular-owner",
                str(private_regular), str(os.geteuid()),
            ], check=True)
            self.assertNotEqual(
                subprocess.run([
                    str(helper), "--verify-private-regular-owner",
                    str(private_regular), str(os.geteuid() + 1),
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            private_regular.chmod(0o640)
            self.assertNotEqual(
                subprocess.run([str(helper), "--verify-private-regular", str(private_regular)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            subprocess.run([
                str(helper), "--set-private-regular-owner", str(private_regular),
                str(os.geteuid()), str(os.getegid()),
            ], check=True)
            self.assertEqual(private_regular.stat().st_mode & 0o7777, 0o600)
            symlink = root / "symlink"
            symlink.symlink_to("regular")
            self.assertNotEqual(
                subprocess.run([str(helper), "--verify-regular", str(symlink)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            original_mode = regular.stat().st_mode & 0o7777
            self.assertNotEqual(
                subprocess.run([
                    str(helper), "--set-private-regular-owner", str(symlink),
                    str(os.geteuid()), str(os.getegid()),
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            self.assertEqual(regular.stat().st_mode & 0o7777, original_mode)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            for arguments in (
                [str(helper), "--verify-private-regular", str(fifo)],
                [str(helper), "--set-private-regular-owner", str(fifo),
                 str(os.geteuid()), str(os.getegid())],
            ):
                self.assertNotEqual(
                    subprocess.run(arguments, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=2).returncode,
                    0,
                )
            hardlink = root / "hardlink"
            os.link(regular, hardlink)
            self.assertNotEqual(
                subprocess.run([str(helper), "--verify-regular", str(regular)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            private = root / "private"
            private.mkdir(mode=0o700)
            subprocess.run([str(helper), "--verify-private-directory", str(private)], check=True)
            subprocess.run([
                str(helper), "--verify-private-directory-owner",
                str(private), str(os.geteuid()),
            ], check=True)
            private.chmod(0o755)
            self.assertNotEqual(
                subprocess.run([str(helper), "--verify-private-directory", str(private)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )
            subprocess.run([
                str(helper), "--set-private-directory-owner", str(private),
                str(os.geteuid()), str(os.getegid()),
            ], check=True)
            self.assertEqual(private.stat().st_mode & 0o7777, 0o700)

    def test_atomic_helper_rejects_unsafe_existing_release_trees(self):
        subprocess.run(["make", "-C", str(DEPLOY), "clean", "host"], check=True,
                       stdout=subprocess.DEVNULL)
        helper = DEPLOY / "build/pm3000-atomic-publish-host"
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "release"
            for directory in (release, release / "apache", release / "bin", release / "web"):
                directory.mkdir()
                directory.chmod(0o755)
            files = {
                "RELEASE_MANIFEST.json": 0o600,
                "RELEASE_SHA256SUMS": 0o600,
                "apache/pm3000-revive.conf": 0o644,
                "bin/pm3000-atomic-publish": 0o755,
                "bin/pm3000-gsp-session-helper": 0o4750,
                "bin/pm3000-rest": 0o755,
                "web/app.js": 0o644,
                "web/index.html": 0o644,
                "web/styles.css": 0o644,
            }
            for name, mode in files.items():
                path = release / name
                path.write_bytes(name.encode())
                path.chmod(mode)

            def verify(expected_gid=None):
                command = [str(helper), "--verify-release", str(release)]
                if expected_gid is not None:
                    command.append(str(expected_gid))
                return subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ).returncode

            self.assertEqual(verify(), 0)
            self.assertEqual(verify(os.getegid()), 0)
            self.assertNotEqual(verify(os.getegid() + 1), 0)
            for unsafe_mode in (0o777, 0o775, 0o757):
                release.chmod(unsafe_mode)
                self.assertNotEqual(verify(), 0)
            release.chmod(0o755)
            (release / "web").chmod(0o775)
            self.assertNotEqual(verify(), 0)
            (release / "web").chmod(0o755)
            extra = release / "web/extra.js"
            extra.write_bytes(b"extra")
            self.assertNotEqual(verify(), 0)
            extra.unlink()
            app = release / "web/app.js"
            app.unlink()
            app.symlink_to("index.html")
            self.assertNotEqual(verify(), 0)
            app.unlink()
            source = release / "hardlink-source"
            source.write_bytes(b"hardlink")
            os.link(source, app)
            app.chmod(0o644)
            self.assertNotEqual(verify(), 0)
            app.unlink()
            source.unlink()
            app.write_bytes(b"web/app.js")
            app.chmod(0o600)
            self.assertNotEqual(verify(), 0)
            if os.geteuid() == 0:
                app.chmod(0o644)
                os.chown(app, 65534, 65534)
                self.assertNotEqual(verify(), 0)


    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is required for the offline device fault harness")
    def test_device_install_cleans_release_when_publish_reports_post_rename_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            mnt = root / "mnt"
            base = mnt / "hdUser/pm3000-revive/webui"
            releases = base / "releases"
            releases.mkdir(parents=True)
            (releases / "r1").mkdir()
            (base / "current").symlink_to("releases/r1")
            rest = mnt / "hdUser/pm3000-revive/rest"
            rest.mkdir(mode=0o700)
            for name in ("tokens.json", "tokens.json.lock"):
                (rest / name).write_bytes(b"{}\n")
                (rest / name).chmod(0o600)
            apache = root / "apache2"
            (apache / "conf.d").mkdir(parents=True)
            config = apache / "conf.d/pm3000-revive.conf"
            config.write_bytes(b"old-config\n")
            tmp_root = root / "tmp"
            package_tree = tmp_root / "input/tree"
            for directory in (package_tree / "apache", package_tree / "bin", package_tree / "web"):
                directory.mkdir(parents=True, exist_ok=True)
            helper = package_tree / "bin/pm3000-atomic-publish"
            helper.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "case \"$1\" in --verify-regular|--verify-release|--verify-private-directory|--verify-private-regular|--verify-private-directory-owner|--verify-private-regular-owner|--set-private-directory-owner|--set-private-regular-owner) exit 0;; esac\n"
                "parent=$1; source=$2; destination=$3; expected_type=$4\n"
                "rm -rf \"$parent/$destination\"\n"
                "mv \"$parent/$source\" \"$parent/$destination\"\n"
                "if [ \"$expected_type\" = directory ] && [ ! -e /tmp/post-rename-failed ]; then\n"
                "  if [ -e /tmp/make-ambiguous ]; then printf 'drift\\n' >>\"$parent/$destination/web/index.html\"; fi\n"
                "  : >/tmp/post-rename-failed; exit 1\n"
                "fi\n",
                encoding="ascii",
            )
            payloads = {
                "apache/pm3000-revive.conf": b"new-config\n",
                "bin/pm3000-atomic-publish": helper.read_bytes(),
                "bin/pm3000-gsp-session-helper": b"ELF-session-helper\n",
                "bin/pm3000-rest": b"#!/bin/sh\nexit 0\n",
                "web/app.js": b"app\n",
                "web/index.html": b"index\n",
                "web/styles.css": b"css\n",
            }
            for name, data in payloads.items():
                path = package_tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o4750 if name == "bin/pm3000-gsp-session-helper"
                           else 0o755 if name.startswith("bin/") else 0o644)
            entries = [
                {"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                 "size": len(data),
                 "mode": (0o4750 if name == "bin/pm3000-gsp-session-helper"
                          else 0o755 if name.startswith("bin/") else 0o644)}
                for name, data in sorted(payloads.items())
            ]
            manifest = json.dumps(
                {"format": 1, "release_id": "r2", "files": entries},
                sort_keys=True, separators=(",", ":"),
            ).encode() + b"\n"
            sums = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries).encode()
            (package_tree / "RELEASE_MANIFEST.json").write_bytes(manifest)
            (package_tree / "RELEASE_SHA256SUMS").write_bytes(sums)
            package = tmp_root / "input/release.tar"
            def root_owned_tarinfo(info):
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                return info

            with tarfile.open(package, "w") as archive:
                for name in ["RELEASE_MANIFEST.json", "RELEASE_SHA256SUMS",
                             "apache/pm3000-revive.conf", "bin/pm3000-atomic-publish",
                             "bin/pm3000-gsp-session-helper", "bin/pm3000-rest",
                             "web/app.js", "web/index.html", "web/styles.css"]:
                    archive.add(package_tree / name, arcname=name, recursive=False,
                                filter=root_owned_tarinfo)
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            backup_complete = tmp_root / "input/BACKUP_COMPLETE"
            backup_complete.write_text("1" * 64 + "\n" + "2" * 64 + "\n", encoding="ascii")
            installer = tmp_root / "input/installer"
            installer.write_bytes((DEPLOY / "device-install.sh").read_bytes())
            installer.chmod(0o755)
            usr_sbin = root / "usr-sbin"
            init_d = root / "init.d"
            usr_sbin.mkdir()
            init_d.mkdir()
            for path in (usr_sbin / "httpd", init_d / "apache2"):
                path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                path.chmod(0o755)
            passwd = root / "passwd"
            group = root / "group"
            passwd.write_text("daemon:x:0:0:daemon:/:/bin/sh\n", encoding="ascii")
            group.write_text("daemon:x:0:\n", encoding="ascii")
            command = [
                "bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
                "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/etc",
                "--bind", str(mnt), "/mnt", "--bind", str(apache), "/etc/apache2",
                "--ro-bind", str(passwd), "/etc/passwd", "--ro-bind", str(group), "/etc/group",
                "--bind", str(tmp_root), "/tmp", "--bind", str(usr_sbin), "/usr/sbin",
                "--bind", str(init_d), "/etc/init.d",
                "/bin/sh", "/tmp/input/installer", "/tmp/input/release.tar", digest, "r2",
                "/tmp/input/BACKUP_COMPLETE",
            ]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((base / "current").readlink(), Path("releases/r1"))
            self.assertEqual(config.read_bytes(), b"old-config\n")
            self.assertFalse((releases / "r2").exists())
            self.assertFalse((releases / ".r2.stage6-tmp").exists())
            (tmp_root / "post-rename-failed").unlink(missing_ok=True)
            (tmp_root / "make-ambiguous").touch()
            ambiguous = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(ambiguous.returncode, 0)
            self.assertEqual((base / "current").readlink(), Path("releases/r1"))
            self.assertEqual(config.read_bytes(), b"old-config\n")
            self.assertTrue((releases / "r2").is_dir(), ambiguous.stderr)
            self.assertFalse((releases / ".r2.stage6-tmp").exists())
            self.assertIn("automatic rollback incomplete", ambiguous.stderr)
            self.assertIn(str(Path("/mnt/hdUser/pm3000-revive/webui/releases/r2")), ambiguous.stderr)

    def test_native_release_shape_plus_approved_checksums_reject_byte_drift(self):
        subprocess.run(["make", "-C", str(MODERN / "native"), "target"], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["make", "-C", str(DEPLOY), "target"], check=True,
                       stdout=subprocess.DEVNULL)
        native_helper = DEPLOY / "build/pm3000-atomic-publish-ppc32"
        host_helper = DEPLOY / "build/pm3000-atomic-publish-host"
        if not host_helper.exists():
            subprocess.run(["make", "-C", str(DEPLOY), "host"], check=True,
                           stdout=subprocess.DEVNULL)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "release.tar"
            load_helper().build_release(MODERN, package, "byte-check")
            release = root / "release"
            release.mkdir()
            with tarfile.open(package, "r:") as archive:
                archive.extractall(release)
            self.assertTrue(native_helper.is_file())
            subprocess.run([str(host_helper), "--verify-release", str(release)], check=True)
            subprocess.run(["sha256sum", "-c", "RELEASE_SHA256SUMS"], cwd=release,
                           check=True, stdout=subprocess.DEVNULL)
            payload = release / "web/index.html"
            payload.write_bytes(b"tampered but structurally valid\n")
            payload.chmod(0o644)
            subprocess.run([str(host_helper), "--verify-release", str(release)], check=True)
            self.assertNotEqual(
                subprocess.run(["sha256sum", "-c", "RELEASE_SHA256SUMS"], cwd=release,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode,
                0,
            )

    def test_private_package_snapshot_is_immune_to_source_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "release.tar"
            replacement = root / "replacement.tar"
            private = root / "private"
            private.mkdir(mode=0o700)
            approved = b"approved-package" * 4096
            unapproved = b"replacement-package" * 4096
            source.write_bytes(approved)
            replacement.write_bytes(unapproved)
            snapshot = private / "release.tar"
            shutil.copyfile(source, snapshot)
            os.replace(replacement, source)
            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                             hashlib.sha256(approved).hexdigest())
            self.assertEqual(snapshot.read_bytes(), approved)
            self.assertEqual(source.read_bytes(), unapproved)


if __name__ == "__main__":
    unittest.main()
