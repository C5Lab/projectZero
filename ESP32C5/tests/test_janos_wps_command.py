from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components" / "janos_wps"


class JanosWpsCommandTest(unittest.TestCase):
    def test_production_argc_argv_parser(self):
        compiler = shutil.which(os.environ.get("CC", "")) or next(
            (shutil.which(c) for c in ("cc", "gcc", "clang") if shutil.which(c)),
            None,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "janos_wps_command_test"
            sources = [COMPONENT / "test" / "janos_wps_command_test.c",
                       COMPONENT / "janos_wps_command.c"]
            if compiler:
                command = [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(COMPONENT / "include"), *map(str, sources),
                    "-o", str(output),
                ]
                run_command = [str(output)]
            elif shutil.which("wsl.exe"):
                def wsl_path(path):
                    resolved = Path(path).resolve()
                    return (f"/mnt/{resolved.drive.rstrip(':').lower()}/"
                            f"{resolved.relative_to(resolved.anchor).as_posix()}")
                command = [
                    "wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-I", wsl_path(COMPONENT / "include"),
                    *map(wsl_path, sources), "-o", wsl_path(output),
                ]
                run_command = ["wsl.exe", wsl_path(output)]
            else:
                self.fail("host C compiler required")
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run_command, cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: JanOS WPS production command parser")


if __name__ == "__main__":
    unittest.main()
