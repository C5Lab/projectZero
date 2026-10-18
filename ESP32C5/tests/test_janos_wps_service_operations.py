from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "components" / "janos_wps"

def wp(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"

class ServiceOperationsTest(unittest.TestCase):
    def test_generalized_offline_and_radio_operations(self):
        sources = [C / "test/janos_wps_service_operations_test.c",
                   C / "janos_wps_service.c", C / "janos_wps_command.c",
                   C / "janos_wps_memory.c",
                   C / "janos_radio_lease.c", C / "private/workflow/lab_secret.c"]
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "service_ops"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            compiler = next((shutil.which(c) for c in (os.environ.get("CC", ""), "cc", "gcc", "clang") if c and shutil.which(c)), None)
            if compiler:
                build = [compiler, *flags, "-I", str(C / "include"), *map(str, sources), "-o", str(exe)]
                run = [str(exe)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"), "host compiler required")
                build = ["wsl.exe", "cc", *flags, "-I", wp(C / "include"), *map(wp, sources), "-o", wp(exe)]
                run = ["wsl.exe", wp(exe)]
            result = subprocess.run(build, cwd=ROOT, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True,
                                    text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), "PASS: JanOS generalized WPS service operations")

if __name__ == "__main__": unittest.main()
