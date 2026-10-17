import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WPS_TEST = ROOT / "components" / "janos_wps" / "test"
WPS_PRIVATE = ROOT / "components" / "janos_wps" / "private"
SESSION = WPS_PRIVATE / "session"


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    return (
        f"/mnt/{resolved.drive.rstrip(':').lower()}/"
        f"{resolved.relative_to(resolved.anchor).as_posix()}"
    )


class WpsSessionPolicyTest(unittest.TestCase):
    def test_retry_identity_and_eap_id_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "session_policy_test"
            requested = os.environ.get("CC")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next(
                    (shutil.which(name) for name in ("cc", "gcc", "clang")
                     if shutil.which(name)),
                    None,
                )
            sources = [
                WPS_TEST / "session_policy_test.c",
                SESSION / "session_policy.c",
            ]
            for source in sources:
                self.assertTrue(source.is_file(), f"missing source: {source}")
            if compiler:
                command = [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(SESSION),
                    *(str(path) for path in sources), "-o", str(executable),
                ]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = [
                    "wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", _wsl_path(SESSION),
                    *(_wsl_path(path) for path in sources),
                    "-o", _wsl_path(executable),
                ]
                run = ["wsl.exe", _wsl_path(executable)]
            else:
                self.skipTest("no host C compiler available")
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
            subprocess.run(run, cwd=ROOT, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
