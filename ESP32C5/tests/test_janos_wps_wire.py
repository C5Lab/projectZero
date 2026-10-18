from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "components" / "janos_wps"


class JanosWpsWireTest(unittest.TestCase):
    def test_exact_schema_v1_golden_records(self):
        compiler = shutil.which(os.environ.get("CC", "")) or next(
            (shutil.which(c) for c in ("cc", "gcc", "clang") if shutil.which(c)),
            None,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "wire_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [C / "test/janos_wps_wire_test.c", C / "janos_wps_wire.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(C / "include"),
                           *map(str, sources), "-o", str(output)]
                run = [str(output)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"), "host C compiler required")
                def wp(path):
                    path = Path(path).resolve()
                    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
                            f"{path.relative_to(path.anchor).as_posix()}")
                command = ["wsl.exe", "cc", *flags, "-I", wp(C / "include"),
                           *map(wp, sources), "-o", wp(output)]
                run = ["wsl.exe", wp(output)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: JanOS WPS exact wire contract")


if __name__ == "__main__":
    unittest.main()
