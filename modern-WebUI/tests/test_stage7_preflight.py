import subprocess
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "modern-WebUI" / "deploy" / "device-preflight.sh"


class Stage7PreflightTests(unittest.TestCase):
    def test_preflight_runs_without_privileges_or_arguments_and_reports_read_only_limits(self):
        result = subprocess.run(
            ["sh", str(PREFLIGHT)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], "pm3000_preflight.format=1")
        self.assertIn("safety.mode=read-only", lines)
        self.assertIn("safety.device_changes=none", lines)
        self.assertIn("probe.authorization_forwarding=not_tested_requires_pilot", lines)
        self.assertIn("probe.directory_fsync=not_tested_requires_write_probe", lines)
        self.assertIn("path.root.type=directory", lines)
        self.assertFalse(any(line.startswith("path.path.") for line in lines))
        self.assertEqual(lines[-1], "pm3000_preflight.complete=yes")

    def test_preflight_source_contains_no_mutating_or_service_control_commands(self):
        source = PREFLIGHT.read_text(encoding="utf-8")
        forbidden_commands = (
            "mktemp", "rm", "cp", "mv", "chmod", "chown", "mkdir", "ln",
            "touch", "install", "scp", "ssh", "reload", "restart", "reboot",
            "poweroff", "mount", "kill", "sudo",
        )
        for command in forbidden_commands:
            with self.subTest(command=command):
                self.assertNotRegex(source, rf"(?m)^\\s*{command}(?:\\s|$)")
        self.assertNotIn(">>", source)
        self.assertNotIn("httpd -k", source)

    def test_preflight_is_posix_shell_syntax(self):
        result = subprocess.run(
            ["dash", "-n", str(PREFLIGHT)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
