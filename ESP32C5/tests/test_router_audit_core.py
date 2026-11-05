"""Compile and execute bounded, gateway-only router discovery tests."""
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


class RouterAuditCoreTest(unittest.TestCase):
    def test_source_is_registered_once(self):
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(cmake.count('"router_audit_core.c"'), 1)

    def test_gateway_only_discovery_is_bounded(self):
        with tempfile.TemporaryDirectory(prefix="janos-router-audit-") as directory:
            executable = Path(directory) / "router_audit_core_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/router_audit_core_test.c",
                       ROOT / "main/router_audit_core.c",
                       ROOT / "main/router_fingerprint.c"]
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
            stack_object = Path(directory) / "router_audit_core.o"
            if compiler:
                stack_command = [compiler, *flags, "-Wframe-larger-than=2048",
                                 "-I", str(ROOT / "main"), "-c",
                                 str(ROOT / "main/router_audit_core.c"),
                                 "-o", str(stack_object)]
            else:
                stack_command = ["wsl.exe", "cc", *flags,
                                 "-Wframe-larger-than=2048", "-I",
                                 wsl_path(ROOT / "main"), "-c",
                                 wsl_path(ROOT / "main/router_audit_core.c"),
                                 "-o", wsl_path(stack_object)]
            stack_built = subprocess.run(stack_command, cwd=ROOT,
                                         capture_output=True, text=True)
            self.assertEqual(stack_built.returncode, 0,
                             stack_built.stdout + stack_built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: bounded gateway-only router discovery")


if __name__ == "__main__":
    unittest.main()
