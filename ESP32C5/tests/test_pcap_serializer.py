"""Compile and execute the real legacy PCAP serializer on the host."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class PcapSerializerTest(unittest.TestCase):
    def test_byte_contract_and_lifecycle_under_sanitizers(self):
        with tempfile.TemporaryDirectory(prefix="janos-pcap-") as temporary:
            executable = Path(temporary) / "pcap_serializer_test"
            flags = [
                os.environ.get("CC", "gcc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I", str(ROOT / "tests" / "host_stubs"),
                "-I", str(ROOT / "components" / "pcap_serializer" / "include"),
            ]
            source = ROOT / "components/pcap_serializer/pcap_serializer.c"
            harness = ROOT / "tests/pcap_serializer_test.c"
            if sys.platform == "darwin":
                # Apple ld has no GNU --wrap support. Redirect just the
                # serializer's allocations, preserving the same failure tests.
                obj = Path(temporary) / "serializer.o"
                shim = Path(temporary) / "alloc.c"
                shim.write_text(
                    '#include <stdlib.h>\n'
                    'void *__real_malloc(size_t n) { return malloc(n); }\n'
                    'void *__real_realloc(void *p, size_t n) { return realloc(p, n); }\n'
                )
                subprocess.run(flags + ["-Dmalloc=__wrap_malloc",
                    "-Drealloc=__wrap_realloc", "-c", str(source), "-o", str(obj)],
                    cwd=ROOT, check=True, capture_output=True, text=True)
                command = flags + [str(harness), str(obj), str(shim), "-o", str(executable)]
            else:
                command = flags + [str(harness), str(source), "-Wl,--wrap=malloc",
                    "-Wl,--wrap=realloc", "-o", str(executable)]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            result = subprocess.run([str(executable)], cwd=ROOT, check=True,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotIn("runtime error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
