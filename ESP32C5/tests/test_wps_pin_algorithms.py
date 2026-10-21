import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    return f"/mnt/{resolved.drive.rstrip(':').lower()}/{resolved.relative_to(resolved.anchor).as_posix()}"


class WpsPinAlgorithmsCTest(unittest.TestCase):
    def test_known_answers_and_properties(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "wps_pin_algorithms_test"
            requested = os.environ.get("CC")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(c) for c in ("cc", "gcc", "clang") if shutil.which(c)), None)
            sources = [ROOT / "tests" / "wps_pin_algorithms_test.c",
                       ROOT / "main" / "wps_pin_algorithms.c"]
            if compiler:
                command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", str(ROOT / "main"), *(str(p) for p in sources),
                           "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", _wsl_path(ROOT / "main"), *(_wsl_path(p) for p in sources),
                           "-o", _wsl_path(executable)]
                run = ["wsl.exe", _wsl_path(executable)]
            else:
                self.skipTest("no host C compiler available")
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
            subprocess.run(run, cwd=ROOT, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
