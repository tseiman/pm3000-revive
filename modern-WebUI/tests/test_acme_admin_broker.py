#!/usr/bin/env python3
"""Host tests for the fixed-purpose privileged ACME administration broker."""

from __future__ import annotations

import os
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
    if (argc == 4 && strcmp(argv[1], "renew") == 0 &&
        strcmp(argv[2], "--foreground") == 0 &&
        strcmp(argv[3], "--broker-startup-notify") == 0) {
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
        wrappers = cls.work / "identity-wrappers.c"
        wrappers.write_text(
            r'''#define _GNU_SOURCE
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
extern int __real_getsockopt(int, int, int, void *, socklen_t *);
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
''',
            encoding="utf-8",
        )
        cls.broker = cls.work / "pm3000-acme-admin"
        subprocess.run(
            ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-DPM3000_TESTING", f'-DPM3000_TEST_EXECUTABLE="{cls.fake}"',
             str(NATIVE / "pm3000-acme-admin.c"), str(wrappers),
             "-Wl,--wrap=getuid", "-Wl,--wrap=geteuid", "-Wl,--wrap=getpwnam",
             "-Wl,--wrap=getsockopt", "-o", str(cls.broker)], check=True
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
        status, child_status, output, exit_status = self.transact(CONFIG_SHOW)
        self.assertEqual((OK, 0, 0), (status, child_status, exit_status))
        self.assertIn(b"argc=3", output)
        self.assertIn(b"argv1=config argv2=show", output)
        self.assertIn(b"input=0 env=empty fd3=closed", output)

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

    def test_renew_returns_only_after_private_startup_acceptance_without_waiting_for_completion(self) -> None:
        started = time.monotonic()
        status, child_status, output, exit_status = self.transact(RENEW_ASYNC)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual((OK, 0, b"", 0),
                         (status, child_status, output, exit_status))

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
        self.assertIn('"/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme"', source)
        self.assertIn('caller_user[] = "daemon"', source)
        self.assertIn("geteuid() != 0U", source)
        self.assertIn("SO_PEERCRED_VALUE 21", source)
        self.assertIn("same_channel()", source)
        self.assertIn("close_inherited_descriptors();", source)
        self.assertIn("execve(PM3000_ACME_EXECUTABLE, arguments, environment)", source)
        self.assertNotIn("getenv(", source)
        self.assertNotIn("/bin/sh", source)
        self.assertIn('"renew"', source)
        self.assertIn('"--broker-startup-notify"', source)
        makefile = (NATIVE / "Makefile").read_text(encoding="utf-8")
        self.assertIn("pm3000-acme-admin-ppc32", makefile)
        self.assertIn("pm3000-acme-admin.c", makefile)


if __name__ == "__main__":
    unittest.main()
