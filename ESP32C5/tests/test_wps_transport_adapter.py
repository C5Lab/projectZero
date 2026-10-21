import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "wps_host" / "test_transport.py"


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    return (
        f"/mnt/{resolved.drive.rstrip(':').lower()}/"
        f"{resolved.relative_to(resolved.anchor).as_posix()}"
    )


class WpsTransportAdapterTest(unittest.TestCase):
    def test_adapter_and_stress_fault_matrix(self):
        requested = os.environ.get("CC", "cc")
        if shutil.which(requested):
            command = [sys.executable, str(RUNNER), "-v"]
        elif shutil.which("wsl.exe"):
            command = ["wsl.exe", "python3", _wsl_path(RUNNER), "-v"]
        else:
            self.skipTest("no host C compiler or WSL available")
        subprocess.run(command, cwd=ROOT, check=True,
                       capture_output=True, text=True, timeout=60)


if __name__ == "__main__":
    unittest.main()
