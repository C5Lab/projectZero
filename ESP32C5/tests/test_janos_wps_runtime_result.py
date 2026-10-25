from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components" / "janos_wps"


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class JanosWpsRuntimeResultTest(unittest.TestCase):
    def test_verified_callback_result_gate(self):
        sources = [COMPONENT / "test" / "janos_wps_runtime_result_test.c",
                   COMPONENT / "janos_wps_runtime_result.c"]
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
        compiler = next((shutil.which(name) for name in
                         (os.environ.get("CC", ""), "cc", "gcc", "clang")
                         if name and shutil.which(name)), None)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "wps_runtime_result"
            if compiler:
                build = [compiler, *flags, "-I", str(COMPONENT / "include"),
                         *map(str, sources), "-o", str(output)]
                run = [str(output)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required")
                build = ["wsl.exe", "cc", *flags, "-I",
                         wsl_path(COMPONENT / "include"),
                         *map(wsl_path, sources), "-o", wsl_path(output)]
                run = ["wsl.exe", wsl_path(output)]
            result = subprocess.run(build, cwd=ROOT, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: JanOS WPS verified runtime result gate")


if __name__ == "__main__":
    unittest.main()
