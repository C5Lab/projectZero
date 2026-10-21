import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WPS_TEST = ROOT / "components" / "janos_wps" / "test"
WPS_PRIVATE = ROOT / "components" / "janos_wps" / "private"
TRANSPORT = WPS_PRIVATE / "transport"


def _wsl_path(path: Path) -> str:
    p = path.resolve()
    return f"/mnt/{p.drive.rstrip(':').lower()}/{p.relative_to(p.anchor).as_posix()}"


class WpsTransportCoreTest(unittest.TestCase):
    def test_lifecycle_and_failure_unwind(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "wps_transport_core_test"
            requested = os.environ.get("CC")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(c) for c in ("cc", "gcc", "clang") if shutil.which(c)), None)
            sources = [WPS_TEST / "transport_core_test.c",
                       TRANSPORT / "wps_transport_core.c"]
            for source in sources:
                self.assertTrue(source.is_file(), f"missing source: {source}")
            if compiler:
                command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", str(TRANSPORT), *(str(p) for p in sources), "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", _wsl_path(TRANSPORT), *(_wsl_path(p) for p in sources),
                           "-o", _wsl_path(executable)]
                run = ["wsl.exe", _wsl_path(executable)]
            else:
                self.skipTest("no host C compiler available")
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
            subprocess.run(run, cwd=ROOT, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
