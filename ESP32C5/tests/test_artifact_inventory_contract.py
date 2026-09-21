"""Executable host contract for the read-only ARTIFACT/1 inventory."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArtifactInventoryContractTest(unittest.TestCase):
    def test_read_only_inventory_contract(self):
        core = ROOT / "main/artifact_inventory_core.c"
        harness = ROOT / "tests/artifact_inventory_core_test.c"
        self.assertTrue(core.is_file(), "read-only inventory core is missing")
        self.assertTrue(harness.is_file(), "inventory host contract harness is missing")
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        self.assertIsNotNone(compiler, "a host C compiler is required")
        with tempfile.TemporaryDirectory(prefix="artifact-inventory-") as temporary:
            executable = Path(temporary) / "artifact_inventory_core_test.exe"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT / "main"), str(core), str(harness),
                            "-Wl,--wrap=fopen", "-o", str(executable)], check=True)
            subprocess.run([str(executable)], cwd=temporary, check=True)

    def test_console_lifecycle_contract(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        start = "/* ARTIFACT INVENTORY CONSOLE BEGIN */"
        end = "/* ARTIFACT INVENTORY CONSOLE END */"
        self.assertTrue(start in source, "inventory console adapter is missing")
        adapter = source.split(start, 1)[1].split(end, 1)[0]
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        self.assertIsNotNone(compiler, "a host C compiler is required")
        with tempfile.TemporaryDirectory(prefix="artifact-console-") as temporary:
            include = Path(temporary) / "console_adapter.inc"
            include.write_text(adapter, encoding="utf-8")
            executable = Path(temporary) / "artifact_console_test.exe"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            f'-DAI_CONSOLE_SOURCE="{include}"',
                            "-I", str(ROOT / "main"), str(ROOT / "main/artifact_inventory_core.c"),
                            str(ROOT / "tests/artifact_inventory_core_test.c"),
                            "-Wl,--wrap=fopen", "-o", str(executable)], check=True)
            subprocess.run([str(executable)], cwd=temporary, check=True)


if __name__ == "__main__":
    unittest.main()
