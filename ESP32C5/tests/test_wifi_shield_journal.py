"""Compile literal JSONL fixtures against the real bounded encoder."""
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

class WifiShieldJournalTests(unittest.TestCase):
    def test_literal_schema_validation_bounds_and_no_heap(self):
        self.assertTrue((ROOT / "main/wifi_shield_journal.h").is_file(),
                        "missing bounded journal schema")
        self.assertTrue((ROOT / "main/wifi_shield_journal.c").is_file(),
                        "missing bounded journal encoder")
        with tempfile.TemporaryDirectory(prefix="janos-shield-journal-") as directory:
            executable = Path(directory) / "journal-test"
            compiler = shutil.which(os.environ.get("CC", "cc"))
            compiler = compiler or shutil.which("gcc") or shutil.which("clang")
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                     "-Wl,--wrap=realloc", "-Wl,--wrap=free"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_shield_journal_test.c",
                       ROOT / "main/wifi_shield_journal.c",
                       ROOT / "main/wifi_shield_campaign.c",
                       ROOT / "main/wifi_shield_ap_health.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield journal: PASS\n")
            self.assertEqual(result.stderr, "")

if __name__ == "__main__":
    unittest.main()
