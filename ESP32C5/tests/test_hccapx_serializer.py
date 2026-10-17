"""Execute the real legacy HCCAPX state machine on host handshake frames."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class HccapxSerializerTest(unittest.TestCase):
    def test_handshake_contract_and_session_isolation_under_sanitizers(self):
        with tempfile.TemporaryDirectory(prefix="janos-hccapx-") as temporary:
            executable = Path(temporary) / "hccapx_serializer_test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "tests" / "host_stubs"),
                "-I", str(ROOT / "components" / "frame_analyzer" / "include"),
                "-I", str(ROOT / "components" / "hccapx_serializer" / "include"),
                str(ROOT / "tests" / "hccapx_serializer_test.c"),
                str(ROOT / "components" / "hccapx_serializer" / "hccapx_serializer.c"),
                str(ROOT / "components" / "frame_analyzer" / "frame_analyzer_parser.c"),
                "-o", str(executable),
            ]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(executable)], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
