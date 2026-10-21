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
CAMPAIGN = WPS_PRIVATE / "campaign"


def _wsl(path: Path) -> str:
    resolved = path.resolve()
    return f"/mnt/{resolved.drive.rstrip(':').lower()}/{resolved.relative_to(resolved.anchor).as_posix()}"


class CampaignPolicyTest(unittest.TestCase):
    def test_parser_and_transition_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "campaign_policy_test"
            compiler = next((shutil.which(name) for name in (os.environ.get("CC", ""), "cc", "gcc", "clang") if name and shutil.which(name)), None)
            sources = [WPS_TEST / "campaign_policy_test.c",
                       CAMPAIGN / "campaign_policy.c",
                       SESSION / "session_policy.c"]
            for source in sources:
                self.assertTrue(source.is_file(), f"missing source: {source}")
            if compiler:
                command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", str(CAMPAIGN), "-I", str(SESSION),
                           *(str(path) for path in sources), "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", _wsl(CAMPAIGN), "-I", _wsl(SESSION),
                           *(_wsl(path) for path in sources), "-o", _wsl(executable)]
                run = ["wsl.exe", _wsl(executable)]
            else:
                self.skipTest("no host C compiler available")
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
            subprocess.run(run, cwd=ROOT, check=True, capture_output=True, text=True)

    def test_bounded_runner_and_resume_policy(self):
        from wps_host.host_build import compile_and_run

        compile_and_run(
            self, "campaign_runner_test",
            [WPS_TEST / "campaign_runner_test.c",
             CAMPAIGN / "campaign_runner.c", CAMPAIGN / "campaign_policy.c"],
            [CAMPAIGN, SESSION], expected="PASS: WPS campaign runner")


if __name__ == "__main__":
    unittest.main()
