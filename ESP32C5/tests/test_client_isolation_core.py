"""Compile and execute the portable JISO/1 codec contract."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class ClientIsolationCoreTest(unittest.TestCase):
    def test_core_source_is_registered_once(self):
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(cmake.count('"client_isolation_core.c"'), 1)

    def test_jiso_wire_validation_and_correlation(self):
        with tempfile.TemporaryDirectory(prefix="janos-jiso-core-") as directory:
            executable = Path(directory) / "client_isolation_core_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/client_isolation_core_test.c",
                       ROOT / "main/client_isolation_core.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags,
                           "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout.strip(),
                "PASS: JISO/1 byte contract, fail-closed validation, correlation")


if __name__ == "__main__":
    unittest.main()
