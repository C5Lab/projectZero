"""Compile and execute the portable JanOS console admission policy."""
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


class JanosConsoleAdmissionTest(unittest.TestCase):
    def test_owner_command_subcommand_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "janos_console_admission_test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(item) for item in
                                 ("cc", "gcc", "clang")
                                 if shutil.which(item)), None)

            sources = [ROOT / "tests" / "janos_console_admission_test.c",
                       ROOT / "main" / "janos_console_admission.c",
                       ROOT / "components" / "janos_wps" / "janos_wps_command.c",
                       ROOT / "components" / "janos_wps" / "janos_radio_lease.c"]
            includes = [ROOT / "main",
                        ROOT / "components" / "janos_wps" / "include"]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            if compiler is not None:
                command = [compiler, *flags]
                for include in includes:
                    command.extend(("-I", str(include)))
                command.extend((*map(str, sources), "-o", str(executable)))
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", *flags]
                for include in includes:
                    command.extend(("-I", wsl_path(include)))
                command.extend((*map(wsl_path, sources), "-o",
                                wsl_path(executable)))
                run = ["wsl.exe", wsl_path(executable)]
            else:
                self.fail("host C compiler required (native or WSL)")

            built = subprocess.run(command, cwd=ROOT, capture_output=True,
                                   text=True)
            self.assertEqual(built.returncode, 0,
                             built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True,
                                    text=True)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: JanOS console admission policy")


if __name__ == "__main__":
    unittest.main()
