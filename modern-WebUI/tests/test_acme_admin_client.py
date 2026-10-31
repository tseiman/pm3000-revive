#!/usr/bin/env python3
"""Focused host tests for the unprivileged PMA1 broker client."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"

HARNESS_SOURCE = r'''
#include "acme_admin_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    struct pm3000_acme_admin_response response;
    const unsigned char *body = NULL;
    size_t body_length = 0U;
    enum pm3000_acme_admin_result result;
    size_t index;
    const char *revision = NULL;
    if (argc < 3 || argc > 5) return 64;
    if (argc >= 4 && strcmp(argv[3], "-") != 0) revision = argv[3];
    if (argc == 5) {
        body = (const unsigned char *)argv[4];
        body_length = strlen(argv[4]);
    }
    result = pm3000_acme_admin_call(argv[1], (unsigned int)strtoul(argv[2], NULL, 10),
                                    revision, body, body_length, &response);
    printf("result=%u child=%u length=%lu output=", (unsigned int)result,
           response.child_status, (unsigned long)response.output_length);
    for (index = 0U; index < response.output_length; ++index)
        printf("%02x", (unsigned int)response.output[index]);
    putchar('\n');
    return 0;
}
'''

HELPER_SOURCE = r'''
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int write_all(const unsigned char *data, size_t length) {
    while (length != 0U) {
        ssize_t amount = write(1, data, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        data += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}
static void encode(unsigned char *data, uint32_t value) {
    data[0] = (unsigned char)(value >> 24); data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8); data[3] = (unsigned char)value;
}
int main(int argc, char **argv, char **envp) {
    unsigned char request[65615];
    unsigned char response[12 + 8449];
    size_t used = 0U;
    ssize_t amount;
    const char *mode = strrchr(argv[0], '/');
    mode = mode == NULL ? argv[0] : mode + 1;
    if (argc != 1 || envp[0] != NULL || fcntl(3, F_GETFD) != -1) return 90;
    while (used < sizeof(request) && (amount = read(0, request + used, sizeof(request) - used)) > 0)
        used += (size_t)amount;
    if (strcmp(mode, "hang") == 0) { sleep(5); return 0; }
    if (strcmp(mode, "disconnect") == 0) return 0;
    memcpy(response, "PMA1", 4U); response[4] = 0U; response[5] = 0U;
    response[6] = 0U; response[7] = 0U; encode(response + 8U, 2U);
    response[12] = 'o'; response[13] = 'k';
    if (strcmp(mode, "bad-request") == 0) { response[4] = 1U; response[5] = 255U; encode(response + 8U, 0U); }
    if (strcmp(mode, "child-failed") == 0) { response[4] = 3U; response[5] = 5U; }
    if (strcmp(mode, "exec-failed") == 0) { response[4] = 2U; response[5] = 255U; encode(response + 8U, 0U); }
    if (strcmp(mode, "busy") == 0) { response[4] = 5U; response[5] = 255U; encode(response + 8U, 0U); }
    if (strcmp(mode, "startup-failed") == 0) { response[4] = 6U; response[5] = 255U; encode(response + 8U, 0U); }
    if (strcmp(mode, "outcome-unknown") == 0) { response[4] = 7U; response[5] = 255U; encode(response + 8U, 0U); }
    if (strcmp(mode, "bad-magic") == 0) response[0] = 'X';
    if (strcmp(mode, "bad-reserved") == 0) response[6] = 1U;
    if (strcmp(mode, "bad-length") == 0) {
        encode(response + 8U, 3U);
        return write_all(response, 14U) == 0 ? 0 : 91;
    }
    if (strcmp(mode, "oversized") == 0) { encode(response + 8U, 8449U); memset(response + 12U, 'x', 8449U); }
    if (strcmp(mode, "inconsistent-ok") == 0) response[5] = 9U;
    if (strcmp(mode, "trailing") == 0) { response[14] = '!'; return write_all(response, 15U) == 0 ? 0 : 91; }
    if (strcmp(mode, "inspect") == 0) {
        unsigned int length = used >= 12U ? ((unsigned int)request[8] << 24) |
            ((unsigned int)request[9] << 16) | ((unsigned int)request[10] << 8) | request[11] : 999999U;
        int valid = used == 12U + length && used >= 12U && memcmp(request, "PMA1", 4U) == 0 &&
                    request[4] == 2U && request[5] == 0U && request[6] == 0U && request[7] == 0U &&
                    length == 69U && request[12] == '"' && request[77] == '"' &&
                    memcmp(request + 13U, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64U) == 0 &&
                    memcmp(request + 78U, "abc", 3U) == 0;
        response[12] = valid ? 'o' : 'n'; response[13] = valid ? 'k' : 'o';
    }
    if (strcmp(mode, "inspect-renew") == 0) {
        int valid = used == 12U && memcmp(request, "PMA1", 4U) == 0 &&
                    request[4] == 6U && request[5] == 0U && request[6] == 0U &&
                    request[7] == 0U && request[8] == 0U && request[9] == 0U &&
                    request[10] == 0U && request[11] == 0U;
        response[12] = valid ? 'o' : 'n'; response[13] = valid ? 'k' : 'o';
    }
    return write_all(response, 12U + (((unsigned int)response[8] << 24) |
                     ((unsigned int)response[9] << 16) | ((unsigned int)response[10] << 8) |
                     response[11])) == 0 ? 0 : 91;
}
'''


class AcmeAdminClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.work = Path(cls.temporary.name)
        (cls.work / "harness.c").write_text(HARNESS_SOURCE, encoding="ascii")
        (cls.work / "helper.c").write_text(HELPER_SOURCE, encoding="ascii")
        cls.harness = cls.work / "harness"
        cls.helper = cls.work / "helper"
        common = ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic"]
        subprocess.run(common + ["-I", str(NATIVE), "-DPM3000_ACME_ADMIN_TIMEOUT_MS=200",
                       str(cls.work / "harness.c"), str(NATIVE / "acme_admin_client.c"),
                       "-o", str(cls.harness)], check=True)
        subprocess.run(common + [str(cls.work / "helper.c"), "-o", str(cls.helper)], check=True)
        for mode in ("inspect", "inspect-renew", "bad-request", "child-failed", "exec-failed",
                     "busy", "startup-failed", "outcome-unknown", "bad-magic",
                     "bad-reserved", "bad-length", "oversized", "inconsistent-ok", "trailing",
                     "hang", "disconnect"):
            os.link(cls.helper, cls.work / mode)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def call(self, mode: str, opcode: int, revision: str | None = None,
             body: str | None = None) -> dict[str, str]:
        command = [str(self.harness), str(self.work / mode), str(opcode)]
        if revision is not None or body is not None:
            command.append("-" if revision is None else revision)
        if body is not None:
            command.append(body)
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, check=True, timeout=3)
        self.assertEqual("", completed.stderr)
        return dict(item.split("=", 1) for item in completed.stdout.strip().split())

    def test_sends_exact_request_over_single_empty_environment_channel(self) -> None:
        result = self.call("inspect", 2, '"' + "a" * 64 + '"', "abc")
        self.assertEqual({"result": "0", "child": "0", "length": "2", "output": "6f6b"}, result)

    def test_renew_sends_exact_empty_opcode_and_classifies_startup_results(self) -> None:
        self.assertEqual("0", self.call("inspect-renew", 6)["result"])
        self.assertEqual("6", self.call("busy", 6)["result"])
        self.assertEqual("7", self.call("startup-failed", 6)["result"])
        self.assertEqual("5", self.call("outcome-unknown", 6)["result"])
        for mode in ("busy", "startup-failed", "outcome-unknown"):
            self.assertEqual("4", self.call(mode, 1)["result"])

    def test_header_declares_payload_and_wire_limits_separately(self) -> None:
        header = (NATIVE / "acme_admin_client.h").read_text(encoding="ascii")
        self.assertIn("PM3000_ACME_ADMIN_CONFIG_WIRE_LIMIT", header)
        self.assertIn("PM3000_ACME_ADMIN_CA_WIRE_LIMIT", header)

    def test_rejects_invalid_path_opcode_and_body_shape_before_exec(self) -> None:
        valid_etag = '"' + "a" * 64 + '"'
        cases = (("relative", 1, None, None), ("missing", 6, None, "x"),
                 ("missing", 1, None, "x"), ("missing", 2, None, "x"),
                 ("missing", 2, valid_etag, None), ("missing", 4, None, "x"),
                 ("missing", 5, valid_etag, None),
                 ("missing", 2, 'W/' + valid_etag, "x"),
                 ("missing", 2, '"' + "A" * 64 + '"', "x"),
                 ("missing", 2, '"' + "g" * 64 + '"', "x"))
        for path, opcode, revision, body in cases:
            command = [str(self.harness), path, str(opcode)]
            if revision is not None or body is not None:
                command.append("-" if revision is None else revision)
            if body is not None:
                command.append(body)
            output = subprocess.run(command, text=True, stdout=subprocess.PIPE, check=True).stdout
            self.assertIn("result=1", output)

    def test_classifies_broker_results(self) -> None:
        self.assertEqual("1", self.call("bad-request", 1)["result"])
        failed = self.call("child-failed", 1)
        self.assertEqual(("2", "5", "6f6b"), (failed["result"], failed["child"], failed["output"]))
        self.assertEqual("3", self.call("exec-failed", 1)["result"])
        self.assertEqual("3", self.call("does-not-exist", 1)["result"])
        stale = self.call("child-failed", 2, '"' + "a" * 64 + '"', "abc")
        self.assertEqual(("2", "5"), (stale["result"], stale["child"]))

    def test_rejects_every_noncanonical_response_frame(self) -> None:
        for mode in ("bad-magic", "bad-reserved", "bad-length", "oversized",
                     "inconsistent-ok", "trailing"):
            with self.subTest(mode=mode):
                self.assertEqual("4", self.call(mode, 1)["result"])

    def test_deadline_and_disconnect_are_bounded_and_mutations_are_uncertain(self) -> None:
        for mode in ("hang", "disconnect"):
            for opcode, revision, body, expected in (
                (1, None, None, "3"),
                (5, None, None, "3"),
                (2, '"' + "a" * 64 + '"', "abc", "5"),
                (6, None, None, "5"),
            ):
                with self.subTest(mode=mode, opcode=opcode):
                    started = time.monotonic()
                    self.assertEqual(expected, self.call(mode, opcode, revision, body)["result"])
                    self.assertLess(time.monotonic() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
