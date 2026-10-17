"""Run Capture Gateway's real input policy without ESP-IDF networking."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _function(source: str, name: str) -> str:
    masked = re.sub(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*',
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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "capture_gateway.h"
FUNCTION_BODY
int main(void) {
    capture_gateway_config_t config = {.ssid="A", .password=NULL};
    assert(!capture_gateway_valid_config(NULL));
    assert(capture_gateway_valid_config(&config));
    config.ssid = NULL; assert(!capture_gateway_valid_config(&config));
    config.ssid = ""; assert(!capture_gateway_valid_config(&config));
    config.ssid = "12345678901234567890123456789012";
    assert(capture_gateway_valid_config(&config));
    config.ssid = "123456789012345678901234567890123";
    assert(!capture_gateway_valid_config(&config));
    config.ssid = "Lab";
    config.password = ""; assert(capture_gateway_valid_config(&config));
    config.password = "1234567"; assert(!capture_gateway_valid_config(&config));
    config.password = "12345678"; assert(capture_gateway_valid_config(&config));
    config.password = "123456789012345678901234567890123456789012345678901234567890123";
    assert(capture_gateway_valid_config(&config));
    config.password = "1234567890123456789012345678901234567890123456789012345678901234";
    assert(!capture_gateway_valid_config(&config));
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class CaptureGatewayConfigTest(unittest.TestCase):
    def test_open_and_wpa2_length_boundaries(self):
        source = (ROOT / "components/capture_gateway/capture_gateway.c").read_text(
            encoding="utf-8"
        )
        code = HARNESS.replace(
            "FUNCTION_BODY", _function(source, "capture_gateway_valid_config")
        )
        with tempfile.TemporaryDirectory(prefix="janos-cgw-config-") as temporary:
            temporary = Path(temporary)
            generated = temporary / "capture_gateway_config_test.c"
            generated.write_text(code, encoding="utf-8")
            executable = temporary / "capture_gateway_config_test"
            compiled = subprocess.run([
                os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-fsanitize=address,undefined",
                "-I", str(ROOT / "tests/host_stubs"),
                "-I", str(ROOT / "components/capture_gateway/include"),
                str(generated), "-o", str(executable),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT,
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
