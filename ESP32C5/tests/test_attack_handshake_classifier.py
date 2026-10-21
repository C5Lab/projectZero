"""Execute the legacy four-way-handshake classifier on real EAPOL bytes."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _function(source: str, name: str) -> str:
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.S,
    )
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked)
    if not match:
        raise ValueError(name)
    begin = source.rfind("\n", 0, match.start()) + 1
    depth = 1
    end = match.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[begin:end]


HARNESS = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "frame_analyzer_parser.h"
static const char *TAG = "test";

FUNCTION_BODY

static data_frame_t *make_frame(uint8_t high, uint8_t low,
                                bool nonce_in_second_half)
{
    const size_t key_length = sizeof(eapol_key_packet_t);
    data_frame_t *frame = calloc(1, sizeof(*frame) + 8U +
                                sizeof(eapol_packet_header_t) + key_length);
    assert(frame != NULL);
    static const uint8_t llc[6] = {0xaa, 0xaa, 0x03, 0, 0, 0};
    memcpy(frame->body, llc, sizeof(llc));
    frame->body[6] = 0x88;
    frame->body[7] = 0x8e;
    eapol_packet_t *eapol = (eapol_packet_t *)(frame->body + 8U);
    eapol->header.packet_type = EAPOL_KEY;
    eapol->header.packet_body_length = htons((uint16_t)key_length);
    eapol_key_packet_t *key = (eapol_key_packet_t *)eapol->packet_body;
    uint8_t *key_info = (uint8_t *)&key->key_information;
    key_info[0] = high;
    key_info[1] = low;
    if (nonce_in_second_half) key->key_nonce[31] = 1U;
    else key->key_nonce[0] = 1U;
    return frame;
}

int main(void)
{
    data_frame_t *m1 = make_frame(0x00U, 0x8aU, false);
    data_frame_t *m2 = make_frame(0x01U, 0x0aU, true);
    data_frame_t *m3 = make_frame(0x01U, 0xcaU, false);
    data_frame_t *m4 = make_frame(0x03U, 0x0aU, false);
    eapol_packet_t *m4_eapol = parse_eapol_packet(m4);
    eapol_key_packet_t *m4_key = parse_eapol_key_packet(m4_eapol);
    memset(m4_key->key_nonce, 0, sizeof(m4_key->key_nonce));
    assert(get_eapol_message_number(m1) == 1U);
    assert(get_eapol_message_number(m2) == 2U);
    assert(get_eapol_message_number(m3) == 3U);
    assert(get_eapol_message_number(m4) == 4U);
    free(m1); free(m2); free(m3); free(m4);
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class AttackHandshakeClassifierTest(unittest.TestCase):
    def test_m1_to_m4_classification_uses_all_nonce_bytes_without_ub(self):
        source = (ROOT / "main" / "attack_handshake.c").read_text(encoding="utf-8")
        body = _function(source, "get_eapol_message_number")
        with tempfile.TemporaryDirectory(prefix="janos-handshake-classifier-") as temporary:
            temporary = Path(temporary)
            generated = temporary / "classifier_test.c"
            generated.write_text(HARNESS.replace("FUNCTION_BODY", body), encoding="utf-8")
            executable = temporary / "classifier_test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "tests" / "host_stubs"),
                "-I", str(ROOT / "components" / "frame_analyzer" / "include"),
                str(generated),
                str(ROOT / "components" / "frame_analyzer" / "frame_analyzer_parser.c"),
                "-o", str(executable),
            ]
            compiled = subprocess.run(command, cwd=ROOT, capture_output=True,
                                      text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT,
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
