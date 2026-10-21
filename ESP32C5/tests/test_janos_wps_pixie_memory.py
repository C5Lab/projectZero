from pathlib import Path
import unittest

from tests.wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"


class JanosWpsPixieMemoryTest(unittest.TestCase):
    def test_real_pixie_cache_uses_tracked_psram_and_scrubs(self):
        compile_and_run(
            self,
            "janos_wps_pixie_memory_test",
            [WPS / "test/janos_wps_pixie_memory_test.c",
             WPS / "janos_wps_memory.c",
             WPS / "private/pixie/pixie.c",
             WPS / "private/pixie/pixie_prng.c"],
            [WPS / "include", WPS / "private/pixie"],
            extra_flags=("-DWPS_HOST_TEST", "-O2"),
            libraries=("-l:libcrypto.so.3",))


if __name__ == "__main__":
    unittest.main()
