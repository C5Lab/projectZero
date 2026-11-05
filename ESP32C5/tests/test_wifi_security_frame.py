"""Compile the real bounded decoder and exercise hand-checked byte fixtures."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    resolved = Path(path).resolve()
    return (f"/mnt/{resolved.drive.rstrip(':').lower()}/"
            f"{resolved.relative_to(resolved.anchor).as_posix()}")


class WifiSecurityFrameTest(unittest.TestCase):
    def test_byte_level_decoder(self):
        with tempfile.TemporaryDirectory(prefix="janos-security-frame-") as directory:
            executable = Path(directory) / "wifi_security_frame_test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(name) for name in
                                 ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_security_frame_test.c",
                       ROOT / "main/wifi_security_frame.c"]
            if compiler is not None:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            else:
                self.fail("host C compiler required (native or WSL)")
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: bounded Wi-Fi security frame decoder")


if __name__ == "__main__":
    unittest.main()
