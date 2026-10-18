"""Host regressions for lifecycle, the ESP adapter, and the stress verdict."""
import json
from pathlib import Path
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "janos_wps"
WPS_TEST = COMPONENT / "test"
ESP_STUBS = ROOT / "tests" / "host_stubs" / "wps_transport"
WPS_PRIVATE = ROOT / "components" / "janos_wps" / "private"
TRANSPORT = WPS_PRIVATE / "transport"


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise unittest.SkipTest("run with a host C compiler, e.g. inside WSL")
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.core = Path(cls.directory.name) / "core"
        cls.adapter = Path(cls.directory.name) / "adapter"
        # Compile the host adapter as the newest verified IDF patch. The
        # separate build-contract test also verifies the lower bound.
        contract = (COMPONENT / "include" / "janos_wps_build.h").read_text()
        version = Path(cls.directory.name) / "esp_idf_version.h"
        version.write_text("".join(
            f"#define ESP_IDF_VERSION_{part} "
            f"{re.search(r'JANOS_WPS_IDF_' + part + r' (\d+)', contract)[1]}\n"
            for part in ("MAJOR", "MINOR")) +
            "#define ESP_IDF_VERSION_PATCH "
            f"{re.search(r'JANOS_WPS_IDF_PATCH_MAX (\d+)', contract)[1]}\n")
        common = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                  *shlex.split(os.environ.get("CFLAGS", "")),
                  "-I", str(COMPONENT / "include"), "-I", str(TRANSPORT)]
        subprocess.run([*common, str(WPS_TEST / "transport_core_test.c"),
                        str(TRANSPORT / "wps_transport_core.c"), "-o", str(cls.core)], check=True)
        subprocess.run([*common, "-I", cls.directory.name, "-I", str(ESP_STUBS),
                        "-I", str(WPS_PRIVATE / "workflow"), "-I", str(ROOT / "main"),
                        str(WPS_TEST / "transport_esp_test.c"),
                        str(TRANSPORT / "wps_transport_core.c"),
                        str(WPS_PRIVATE / "workflow" / "lab_radio.c"),
                        str(WPS_PRIVATE / "workflow" / "lab_platform.c"),
                        str(ROOT / "main" / "sta_mac_policy_core.c"),
                        str(ROOT / "main" / "sta_mac_policy_store.c"),
                        str(COMPONENT / "janos_wps_transport.c"),
                        "-o", str(cls.adapter)], check=True)

    def run_stress(self, scenario):
        output = subprocess.run([str(self.adapter), scenario], check=True,
                                capture_output=True, text=True).stdout
        return [json.loads(line) for line in output.splitlines()]

    def test_public_transport_header_is_self_contained(self):
        """Consumers must not need janos_wps private include directories."""
        compiler = shutil.which(os.environ.get("CC", "cc"))
        self.assertIsNotNone(compiler)
        source = Path(self.directory.name) / "public_transport_header.c"
        object_file = Path(self.directory.name) / "public_transport_header.o"
        source.write_text(
            '#include "janos_wps_transport.h"\n'
            'int public_transport_header_compiles(void) { return 0; }\n',
            encoding="utf-8",
        )
        subprocess.run([
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(COMPONENT / "include"),
            "-I", str(ESP_STUBS),
            "-c", str(source), "-o", str(object_file),
        ], check=True)

    def test_core_unwind_and_cleanup_retry(self):
        subprocess.run([str(self.core)], check=True)

    def test_adapter_partial_init_and_success_counters(self):
        subprocess.run([str(self.adapter)], check=True)

    def test_exact_idle_sta_snapshot_restore(self):
        subprocess.run([str(self.adapter), "exact"], check=True)

    def test_stress_accepts_clean_cycles(self):
        rows = self.run_stress("stress")
        self.assertEqual(rows[-1]["result"], "transport_stress_verified")
        self.assertEqual(rows[0]["cycles"], 50)
        self.assertIs(rows[0].get("mac_restored"), True)

    def test_stress_rejects_progressive_heap_loss(self):
        rows = self.run_stress("stress-leak")
        self.assertEqual(rows[-1]["result"], "transport_stress_failed")
        self.assertGreater(rows[0]["heap_loss"], rows[0]["heap_loss_limit"])

    def test_stress_rejects_cleanup_failure(self):
        rows = self.run_stress("stress-cleanup-error")
        self.assertEqual(rows[-1]["result"], "transport_stress_failed")
        self.assertEqual(rows[0]["cycles"], 0)
        self.assertTrue(rows[0]["cleanup_pending"])

    def test_stress_rejects_incorrect_mac_readback(self):
        rows = self.run_stress("stress-wrong-mac")
        self.assertEqual(rows[-1]["result"], "transport_stress_failed")
        self.assertIs(rows[0].get("mac_restored"), False)

    def test_stress_retries_cleanup_but_reports_the_fault(self):
        rows = self.run_stress("stress-cleanup-retry")
        self.assertEqual(rows[-1]["result"], "transport_stress_failed")
        self.assertEqual(rows[0]["cycles"], 0)
        self.assertFalse(rows[0]["cleanup_pending"])
        self.assertTrue(rows[0]["mac_restored"])


if __name__ == "__main__":
    unittest.main()
