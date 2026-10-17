"""Run legacy handshake naming helpers used for SD artifacts."""

from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _function(source: str, name: str) -> str:
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked)
    if not match:
        raise ValueError(name)
    begin = source.rfind("\n", 0, match.start()) + 1
    depth, end = 1, match.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[begin:end]


HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
FUNCTIONS
int main(void) {
    uint8_t full[32]; memset(full, 'X', sizeof(full));
    assert(get_ssid_length(full) == 32U);
    full[7] = 0; assert(get_ssid_length(full) == 7U);
    char safe[12];
    sanitize_ssid_for_filename(safe, "A/B:C*D?E", sizeof(safe));
    assert(strcmp(safe, "A-B-C-D-E") == 0);
    sanitize_ssid_for_filename(safe, "Ab_-. 12", 6U);
    assert(strcmp(safe, "Ab_-.") == 0);
    uint8_t mac[6] = {0x00,1,2,0xab,0xcd,0xef};
    char suffix[7]; format_mac_suffix(mac, suffix);
    assert(strcmp(suffix, "ABCDEF") == 0);
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class AttackHandshakeHelpersTest(unittest.TestCase):
    def test_ssid_length_sanitization_and_mac_suffix(self):
        source = (ROOT / "main/attack_handshake.c").read_text(encoding="utf-8")
        names = ("get_ssid_length", "sanitize_ssid_for_filename", "format_mac_suffix")
        code = HARNESS.replace("FUNCTIONS", "\n".join(_function(source, n) for n in names))
        with tempfile.TemporaryDirectory(prefix="janos-handshake-helpers-") as temporary:
            temporary = Path(temporary)
            generated = temporary / "handshake_helpers_test.c"
            generated.write_text(code, encoding="utf-8")
            executable = temporary / "handshake_helpers_test"
            compiled = subprocess.run([
                os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-fsanitize=address,undefined", str(generated),
                "-o", str(executable),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT,
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
