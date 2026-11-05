"""Run the real fixed-storage policy core with allocation/TX boundary spies."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiShieldCoreTests(unittest.TestCase):
    def test_policy_counters_windows_capacity_status_and_passive_boundary(self):
        self.assertTrue((ROOT / "main/wifi_shield_core.h").is_file(),
                        "missing portable Shield aggregate core header")
        self.assertTrue((ROOT / "main/wifi_shield_core.c").is_file(),
                        "missing portable Shield aggregate core implementation")
        with tempfile.TemporaryDirectory(prefix="janos-shield-core-") as directory:
            executable = Path(directory) / "shield-core-test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            compiler = compiler or next((shutil.which(name) for name in
                                        ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            flags += ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                      "-Wl,--wrap=realloc", "-Wl,--wrap=free"]
            sources = [ROOT / "tests/wifi_shield_core_test.c",
                       ROOT / "main/wifi_shield_core.c",
                       ROOT / "main/wifi_shield_channel.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "", "compiler output must be pristine")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield core: PASS (11 scenarios; TX=0; heap=0)\n")
            self.assertEqual(result.stderr, "", "runtime/sanitizer output must be pristine")


if __name__ == "__main__":
    unittest.main()
