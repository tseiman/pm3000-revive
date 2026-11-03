#!/usr/bin/env python3
"""Host tests for the fixed-purpose privileged ACME administration broker."""

from __future__ import annotations

import os
import json
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
MAGIC = b"PMA1"
CONFIG_SHOW = 1
CONFIG_REPLACE = 2
CA_INSTALL = 3
STATUS = 4
CONFIG_REVISION = 5
RENEW_ASYNC = 6
CONFIG_CREATE = 7
CA_CREATE = 8
BOOTSTRAP_STATUS = 9
SCHEDULE_SHOW = 10
SCHEDULE_REPLACE = 11
SCHEDULE_CREATE = 12
ETAG = b'"' + b"a" * 64 + b'"'
OK = 0
BAD_REQUEST = 1
EXEC_FAILED = 2
CHILD_FAILED = 3
OUTPUT_TOO_LARGE = 4
BUSY = 5
STARTUP_FAILED = 6
OUTCOME_UNKNOWN = 7


class AcmeAdminBrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.work = Path(cls.temporary.name)
        fake_source = cls.work / "fake-acme.c"
        fake_source.write_text(
            r'''#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv, char **envp) {
    unsigned char data[65537]; size_t length = 0; ssize_t amount; int index;
    while (length < sizeof(data) && (amount = read(0, data + length, sizeof(data) - length)) > 0)
        length += (size_t)amount;
    if (argc == 3 && strcmp(argv[1], "force") == 0 &&
        strcmp(argv[2], "--broker-startup-notify") == 0) {
        FILE *control = fopen("CONTROL_PATH", "rb");
        int startup = control == NULL ? 'A' : fgetc(control);
        if (control != NULL) fclose(control);
        if (startup == 'H') { sleep(6); return 0; }
        if (startup == 'E') return 9;
        if (write(3, &startup, 1) != 1) return 8;
        sleep(1);
        return 0;
    }
    printf("argc=%d", argc);
    for (index = 0; index < argc; ++index) printf(" argv%d=%s", index, argv[index]);
    printf(" input=%lu env=%s fd3=%s\n", (unsigned long)length,
           envp[0] == NULL ? "empty" : "set", fcntl(3, F_GETFD) == -1 ? "closed" : "open");
    if (length >= 4 && memcmp(data, "FAIL", 4) == 0) return 7;
    if (length >= 3 && memcmp(data, "BIG", 3) == 0) {
        for (index = 0; index < 9000; ++index) putchar('x');
    }
    return 0;
}
''',
            encoding="utf-8",
        )
        # fcntl declarations are intentionally supplied by the real header.
        fake_source.write_text(
            fake_source.read_text(encoding="utf-8").replace(
                "#include <unistd.h>", "#include <unistd.h>\n#include <fcntl.h>"
            ).replace(
                "CONTROL_PATH", str(cls.work / "startup-control")
            ),
            encoding="utf-8",
        )
        cls.fake = cls.work / "fake-acme"
        subprocess.run(
            ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
             str(fake_source), "-o", str(cls.fake)], check=True
        )
        cls.fake_cron = cls.work / "fake-cron"
        cls.fake_cron.write_text("#!/bin/sh\nprintf 'cron-reload-noise\\n'\n", encoding="ascii")
        cls.fake_cron.chmod(0o755)
        wrappers = cls.work / "identity-wrappers.c"
        wrappers.write_text(
            r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
extern int __real_getsockopt(int, int, int, void *, socklen_t *);
extern int __real_fsync(int);
static int mark_identity(char value) {
    int fd = open("IDENTITY_MARKER_PATH", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return -1;
    if (write(fd, &value, 1) != 1) { close(fd); return -1; }
    return close(fd);
}
int __wrap_setgid(gid_t value) {
    if (value != 0 || mark_identity('g') != 0) { errno = EPERM; return -1; }
    return 0;
}
int __wrap_setuid(uid_t value) {
    if (value != 0 || mark_identity('u') != 0) { errno = EPERM; return -1; }
    return 0;
}
uid_t __wrap_getuid(void) { return 1; }
uid_t __wrap_geteuid(void) { return 0; }
struct passwd *__wrap_getpwnam(const char *name) {
    static struct passwd daemon_account = { .pw_name = (char *)"daemon", .pw_uid = 1, .pw_gid = 1 };
    return name != 0 && name[0] == 'd' ? &daemon_account : 0;
}
int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
    struct ucred *peer = value;
    int result = __real_getsockopt(fd, level, option == 21 ? SO_PEERCRED : option, value, length);
    if (result == 0 && option == 21) peer->uid = 1;
    return result;
}
int __wrap_fsync(int fd) {
    static unsigned int directory_calls = 0;
    struct stat value;
    FILE *control;
    int fail_at = 0;
    if (fstat(fd, &value) == 0 && S_ISDIR(value.st_mode)) {
        ++directory_calls;
        control = fopen("FSYNC_CONTROL_PATH", "rb");
        if (control != NULL) { fail_at = fgetc(control) - '0'; fclose(control); }
        if (fail_at > 0 && directory_calls == (unsigned int)fail_at) {
            errno = EIO;
            return -1;
        }
    }
    return __real_fsync(fd);
}
''',
            encoding="utf-8",
        )
        wrappers.write_text(
            wrappers.read_text(encoding="utf-8").replace(
                "FSYNC_CONTROL_PATH", str(cls.work / "fsync-control")
            ).replace(
                "IDENTITY_MARKER_PATH", str(cls.work / "root-identity")
            ), encoding="utf-8",
        )
        cls.broker = cls.work / "pm3000-acme-admin"
        cls.schedule = cls.work / "schedule-v1"
        cls.crontab = cls.work / "root.crontab"
        cls.identity_marker = cls.work / "root-identity"
        subprocess.run(
            ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-DPM3000_TESTING", f'-DPM3000_TEST_EXECUTABLE="{cls.fake}"',
             f'-DPM3000_CRON_INIT="{cls.fake_cron}"',
             f'-DPM3000_SCHEDULE_PATH="{cls.schedule}"',
             f'-DPM3000_CRONTAB_PATH="{cls.crontab}"',
             str(NATIVE / "pm3000-acme-admin.c"), str(wrappers),
             "-Wl,--wrap=getuid", "-Wl,--wrap=geteuid", "-Wl,--wrap=getpwnam",
             "-Wl,--wrap=getsockopt", "-Wl,--wrap=fsync",
             "-Wl,--wrap=setgid", "-Wl,--wrap=setuid", "-o", str(cls.broker)], check=True
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def transact(self, opcode: int, payload: bytes = b"", *, extra: bytes = b"") -> tuple[int, int, bytes, int]:
        parent, child = socket.socketpair()
        try:
            process = subprocess.Popen(
                [str(self.broker)], stdin=child.fileno(), stdout=child.fileno(),
                stderr=subprocess.PIPE, close_fds=False,
            )
            child.close()
            parent.sendall(MAGIC + bytes((opcode, 0, 0, 0)) + struct.pack(">I", len(payload)) + payload + extra)
            parent.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                try:
                    part = parent.recv(65536)
                except ConnectionResetError:
                    break
                if not part:
                    break
                response.extend(part)
            stderr = process.communicate(timeout=5)[1]
            self.assertEqual(b"", stderr)
        finally:
            parent.close()
            child.close()
        self.assertGreaterEqual(len(response), 12, response)
        self.assertEqual(MAGIC, response[:4])
        length = struct.unpack(">I", response[8:12])[0]
        self.assertEqual(12 + length, len(response))
        return response[4], response[5], bytes(response[12:]), process.returncode

    def test_config_show_executes_only_the_fixed_cli_form(self) -> None:
        self.identity_marker.unlink(missing_ok=True)
        status, child_status, output, exit_status = self.transact(CONFIG_SHOW)
        self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
        self.assertIn(b"argc=3", output)
        self.assertIn(b"argv1=config argv2=show", output)
        self.assertIn(b"input=0 env=empty fd3=closed", output)
        self.assertEqual(b"gu", self.identity_marker.read_bytes())

    def test_config_revision_executes_only_the_fixed_cli_form(self) -> None:
        status, child_status, output, exit_status = self.transact(CONFIG_REVISION)
        self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
        self.assertIn(b"argc=3", output)
        self.assertIn(b"argv1=config argv2=revision", output)
        self.assertIn(b"input=0 env=empty fd3=closed", output)

    def test_payload_operations_use_fixed_argv_and_exact_bounded_input(self) -> None:
        cases = (
            (CONFIG_REPLACE, b'{"enabled":true}', b"argc=6", b"argv1=config argv2=replace argv3=--stdin argv4=--if-match"),
            (CA_INSTALL, b"certificate bundle", b"argc=6", b"argv1=ca argv2=install argv3=--stdin argv4=--if-match"),
        )
        for opcode, payload, argc, arguments in cases:
            with self.subTest(opcode=opcode):
                status, child_status, output, exit_status = self.transact(opcode, ETAG + payload)
                self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
                self.assertIn(argc, output)
                self.assertIn(arguments, output)
                self.assertIn(f"input={len(payload)}".encode(), output)
                self.assertIn(b"argv5=" + ETAG, output)

    def test_first_run_operations_use_only_if_none_match_fixed_cli_forms(self) -> None:
        cases = (
            (CONFIG_CREATE, b'{"enabled":false}', b"argc=6",
             b"argv1=config argv2=replace argv3=--stdin argv4=--if-none-match argv5=*"),
            (CA_CREATE, b"certificate bundle", b"argc=6",
             b"argv1=ca argv2=install argv3=--stdin argv4=--if-none-match argv5=*"),
        )
        for opcode, payload, argc, arguments in cases:
            with self.subTest(opcode=opcode):
                status, child_status, output, exit_status = self.transact(opcode, payload)
                self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
                self.assertIn(argc, output)
                self.assertIn(arguments, output)
                self.assertIn(f"input={len(payload)}".encode(), output)

        status, child_status, output, exit_status = self.transact(BOOTSTRAP_STATUS)
        self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
        self.assertIn(b"argc=3", output)
        self.assertIn(b"argv1=bootstrap argv2=status input=0", output)

    def test_rejects_missing_or_malformed_strong_etag_before_exec(self) -> None:
        malformed = (
            b"payload",
            b'W/"' + b"a" * 64 + b'"payload',
            b'"' + b"A" * 64 + b'"payload',
            b'"' + b"g" * 64 + b'"payload',
            b'"' + b"a" * 63 + b'"payload',
            b'"' + b"a" * 64 + b"xpayload",
            ETAG,
        )
        for opcode in (CONFIG_REPLACE, CA_INSTALL):
            for payload in malformed:
                with self.subTest(opcode=opcode, payload=payload[:8]):
                    self.assertEqual(
                        (BAD_REQUEST, 255, b"", 3), self.transact(opcode, payload)
                    )

    def test_status_uses_its_only_fixed_cli_form(self) -> None:
        status, child_status, output, exit_status = self.transact(STATUS)
        self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
        self.assertIn(b"argc=2", output)
        self.assertIn(b"argv1=status input=0", output)

    def test_schedule_preserves_unrelated_cron_and_uses_one_exact_fixed_block(self) -> None:
        self.schedule.unlink(missing_ok=True)
        self.crontab.write_bytes(b"# site job\n5 4 * * * /usr/local/site-job --keep='yes'\n")
        self.crontab.chmod(0o600)
        status, child, output, exit_status = self.transact(SCHEDULE_SHOW)
        self.assertEqual((OK, 0, 0), (status, child, exit_status))
        self.assertEqual({"managed": False, "enabled": False, "hour": 3, "minute": 17},
                         json.loads(output))

        self.assertEqual((OK, 0, b"", 0),
                         self.transact(SCHEDULE_CREATE, bytes((1, 23, 59))))
        expected = (b"# site job\n5 4 * * * /usr/local/site-job --keep='yes'\n"
                    b"# BEGIN PM3000 ACME SCHEDULE\n"
                    b"59 23 * * * /mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme-maintenance scheduled\n"
                    b"# END PM3000 ACME SCHEDULE\n")
        self.assertEqual(expected, self.crontab.read_bytes())
        self.assertEqual(0o600, self.crontab.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.schedule.stat().st_mode & 0o777)

        status, child, output, exit_status = self.transact(SCHEDULE_SHOW)
        model = json.loads(output)
        self.assertEqual((OK, 0, 0, True, 23, 59),
                         (status, child, exit_status, model["enabled"], model["hour"], model["minute"]))
        revision = model["revision"].encode("ascii")
        self.assertEqual((OK, 0, b"", 0),
                         self.transact(SCHEDULE_REPLACE, revision + bytes((0, 0, 0))))
        self.assertEqual(b"# site job\n5 4 * * * /usr/local/site-job --keep='yes'\n",
                         self.crontab.read_bytes())

    def test_schedule_inserts_one_boundary_after_crontab_without_final_newline(self) -> None:
        self.schedule.unlink(missing_ok=True)
        original = b"5 4 * * * /usr/local/site-job --keep='yes'"
        self.crontab.write_bytes(original)
        self.crontab.chmod(0o600)
        self.assertEqual((OK, 0, b"", 0),
                         self.transact(SCHEDULE_CREATE, bytes((1, 3, 17))))
        expected = (original + b"\n# BEGIN PM3000 ACME SCHEDULE\n"
                    b"17 3 * * * /mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme-maintenance scheduled\n"
                    b"# END PM3000 ACME SCHEDULE\n")
        self.assertEqual(expected, self.crontab.read_bytes())
        status, child, output, exit_status = self.transact(SCHEDULE_SHOW)
        self.assertEqual((OK, 0, 0), (status, child, exit_status))
        self.assertTrue(json.loads(output)["managed"])

    def test_schedule_parent_fsync_after_rename_is_outcome_unknown(self) -> None:
        control = self.work / "fsync-control"
        for fail_at in (b"1", b"2"):
            with self.subTest(parent_fsync_call=fail_at):
                self.schedule.unlink(missing_ok=True)
                self.crontab.write_bytes(b"# unrelated\n")
                self.crontab.chmod(0o600)
                control.write_bytes(fail_at)
                self.assertEqual((OUTCOME_UNKNOWN, 255, b"", 5),
                                 self.transact(SCHEDULE_CREATE, bytes((1, 3, 17))))
        control.unlink(missing_ok=True)

    def test_schedule_rejects_stale_revision_and_malformed_or_duplicate_markers(self) -> None:
        self.schedule.unlink(missing_ok=True)
        for cron in (
            b"# BEGIN PM3000 ACME SCHEDULE\n",
            b"# BEGIN PM3000 ACME SCHEDULE\n# BEGIN PM3000 ACME SCHEDULE\n# END PM3000 ACME SCHEDULE\n",
        ):
            self.crontab.write_bytes(cron); self.crontab.chmod(0o600)
            self.assertEqual((CHILD_FAILED, 5, b"", 5),
                             self.transact(SCHEDULE_CREATE, bytes((1, 0, 0))))
            self.assertFalse(self.schedule.exists())

        self.crontab.write_bytes(b"unrelated\n"); self.crontab.chmod(0o600)
        self.assertEqual((OK, 0, b"", 0),
                         self.transact(SCHEDULE_CREATE, bytes((1, 0, 0))))
        before = self.crontab.read_bytes()
        self.assertEqual((CHILD_FAILED, 5, b"", 5),
                         self.transact(SCHEDULE_REPLACE, ETAG + bytes((1, 1, 1))))
        self.assertEqual(before, self.crontab.read_bytes())

    def test_renew_returns_only_after_private_startup_acceptance_without_waiting_for_completion(self) -> None:
        self.identity_marker.unlink(missing_ok=True)
        started = time.monotonic()
        status, child_status, output, exit_status = self.transact(RENEW_ASYNC)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual((OK, 0, b"", 0),
                         (status, child_status, output, exit_status))
        self.assertEqual(b"gu", self.identity_marker.read_bytes())

    def test_renew_distinguishes_busy_failure_unknown_and_bounds_startup_wait(self) -> None:
        control = self.work / "startup-control"
        for startup, expected in ((b"B", BUSY), (b"F", STARTUP_FAILED),
                                  (b"U", OUTCOME_UNKNOWN), (b"E", STARTUP_FAILED),
                                  (b"H", OUTCOME_UNKNOWN)):
            with self.subTest(startup=startup):
                control.write_bytes(startup)
                started = time.monotonic()
                status, child_status, output, exit_status = self.transact(RENEW_ASYNC)
                self.assertLess(time.monotonic() - started, 5.75)
                self.assertEqual((expected, 255, b"", 5),
                                 (status, child_status, output, exit_status))
        control.unlink()

    def test_rejects_unknown_opcodes_and_invalid_payload_lengths(self) -> None:
        cases = (
            (RENEW_ASYNC, b"unexpected"),
            (255, b""),
            (CONFIG_SHOW, b"unexpected"),
            (STATUS, b"unexpected"),
            (CONFIG_REVISION, b"unexpected"),
            (BOOTSTRAP_STATUS, b"unexpected"),
            (CONFIG_REPLACE, ETAG + b"x" * 8193),
            (CA_INSTALL, ETAG + b"x" * 65537),
            (CONFIG_CREATE, b"x" * 8193),
            (CA_CREATE, b"x" * 65537),
        )
        for opcode, payload in cases:
            with self.subTest(opcode=opcode, length=len(payload)):
                status, child_status, output, exit_status = self.transact(opcode, payload)
                self.assertEqual((BAD_REQUEST, 255, b"", 3),
                                 (status, child_status, output, exit_status))

    def test_maps_child_failure_without_forwarding_unbounded_output(self) -> None:
        status, child_status, output, exit_status = self.transact(CONFIG_REPLACE, ETAG + b"FAIL")
        self.assertEqual((CHILD_FAILED, 7, 5), (status, child_status, exit_status))
        self.assertLessEqual(len(output), 8448)

        status, child_status, output, exit_status = self.transact(CONFIG_REPLACE, ETAG + b"BIG")
        self.assertEqual((OUTPUT_TOO_LARGE, 0, b"", 5),
                         (status, child_status, output, exit_status))

    def test_production_source_has_fixed_authority_and_no_shell_or_environment_path(self) -> None:
        source = (NATIVE / "pm3000-acme-admin.c").read_text(encoding="utf-8")
        self.assertIn('"/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme-maintenance"', source)
        self.assertIn('caller_user[] = "daemon"', source)
        self.assertIn("geteuid() != 0U", source)
        self.assertIn("SO_PEERCRED_VALUE 21", source)
        self.assertIn("same_channel()", source)
        self.assertIn("close_inherited_descriptors();", source)
        self.assertIn("execve(PM3000_ACME_EXECUTABLE, arguments, environment)", source)
        self.assertNotIn("getenv(", source)
        self.assertNotIn("/bin/sh", source)
        self.assertIn('"force"', source)
        self.assertIn('"--broker-startup-notify"', source)
        makefile = (NATIVE / "Makefile").read_text(encoding="utf-8")
        self.assertIn("pm3000-acme-admin-ppc32", makefile)
        self.assertIn("pm3000-acme-admin.c", makefile)


if __name__ == "__main__":
    unittest.main()
