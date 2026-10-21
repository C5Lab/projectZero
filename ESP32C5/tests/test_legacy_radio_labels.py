"""Execute legacy Zigbee/nRF label functions consumed by console clients."""

from pathlib import Path
import os
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
#include <string.h>
#include "zig_recon.h"
#include "nrf24_jammer.h"
FUNCTIONS
int main(void) {
    assert(strcmp(zig_recon_proto_name(ZIG_RECON_PROTO_IEEE802154), "802.15.4") == 0);
    assert(strcmp(zig_recon_proto_name(ZIG_RECON_PROTO_MATTER_THREAD), "Matter/Thread") == 0);
    assert(strcmp(zig_recon_proto_token(ZIG_RECON_PROTO_ZIGBEE), "zigbee") == 0);
    assert(strcmp(zig_recon_proto_token((zig_recon_proto_t)99), "unknown") == 0);
    assert(strcmp(zig_recon_confidence_token(ZIG_RECON_CONFIDENCE_CONFIRMED), "confirmed") == 0);
    assert(strcmp(zig_recon_role_name(ZIG_RECON_ROLE_END_DEVICE), "End Device") == 0);
    assert(strcmp(zig_recon_role_token(ZIG_RECON_ROLE_COORDINATOR), "coordinator") == 0);
    assert(strcmp(nrf24_jammer_band_name(JAM_BLE), "ble") == 0);
    assert(strcmp(nrf24_jammer_band_name(JAM_BT), "bt") == 0);
    assert(strcmp(nrf24_jammer_band_name(JAM_WIFI), "wifi") == 0);
    assert(strcmp(nrf24_jammer_band_name(JAM_DRONE), "drone") == 0);
    assert(strcmp(nrf24_jammer_band_name(JAM_ALL), "all") == 0);
    assert(strcmp(nrf24_jammer_band_name((nrf24_jam_band_t)99), "all") == 0);
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class LegacyRadioLabelsTest(unittest.TestCase):
    def test_console_and_protocol_labels_remain_stable(self):
        zig = (ROOT / "components/zig_recon/zig_recon.c").read_text(encoding="utf-8")
        nrf = (ROOT / "components/nrf24_jammer/nrf24_jammer.c").read_text(encoding="utf-8")
        zig_names = (
            "zig_recon_proto_name", "zig_recon_proto_token",
            "zig_recon_confidence_token", "zig_recon_role_name",
            "zig_recon_role_token",
        )
        functions = [_function(zig, name) for name in zig_names]
        functions.append(_function(nrf, "nrf24_jammer_band_name"))
        code = HARNESS.replace("FUNCTIONS", "\n".join(functions))
        with tempfile.TemporaryDirectory(prefix="janos-radio-labels-") as temporary:
            temporary = Path(temporary)
            generated = temporary / "legacy_radio_labels_test.c"
            generated.write_text(code, encoding="utf-8")
            executable = temporary / "legacy_radio_labels_test"
            compiled = subprocess.run([
                os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-fsanitize=address,undefined",
                "-I", str(ROOT / "tests/host_stubs"),
                "-I", str(ROOT / "components/zig_recon/include"),
                "-I", str(ROOT / "components/nrf24_jammer/include"),
                str(generated), "-o", str(executable),
            ], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT,
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
