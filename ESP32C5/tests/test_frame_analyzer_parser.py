"""Execute the real legacy EAPOL/PMKID parser with byte fixtures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class FrameAnalyzerParserTest(unittest.TestCase):
    def test_parser_paths_under_sanitizers(self):
        with tempfile.TemporaryDirectory(prefix="janos-frame-parser-") as temporary:
            executable = Path(temporary) / "frame_analyzer_parser_test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "tests" / "host_stubs"),
                "-I", str(ROOT / "components" / "frame_analyzer" / "include"),
                str(ROOT / "tests" / "frame_analyzer_parser_test.c"),
                str(ROOT / "components" / "frame_analyzer" / "frame_analyzer_parser.c"),
                "-o", str(executable),
            ]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(executable)], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
