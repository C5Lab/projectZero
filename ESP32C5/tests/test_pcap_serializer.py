"""Compile and execute the real legacy PCAP serializer on the host."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class PcapSerializerTest(unittest.TestCase):
    def test_byte_contract_and_lifecycle_under_sanitizers(self):
        with tempfile.TemporaryDirectory(prefix="janos-pcap-") as temporary:
            executable = Path(temporary) / "pcap_serializer_test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I", str(ROOT / "tests" / "host_stubs"),
                "-I", str(ROOT / "components" / "pcap_serializer" / "include"),
                str(ROOT / "tests" / "pcap_serializer_test.c"),
                str(ROOT / "components" / "pcap_serializer" / "pcap_serializer.c"),
                "-Wl,--wrap=malloc",
                "-Wl,--wrap=realloc",
                "-o", str(executable),
            ]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(executable)], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
