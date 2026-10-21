"""Host regressions for component-owned WPS workflows and live-session policy."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WPS_TEST = ROOT / "components" / "janos_wps" / "test"
WPS_PRIVATE = ROOT / "components" / "janos_wps" / "private"
PROTOCOL = WPS_PRIVATE / "protocol"
PIN = WPS_PRIVATE / "pin"
PIXIE = WPS_PRIVATE / "pixie"
SESSION = WPS_PRIVATE / "session"
TRANSPORT = WPS_PRIVATE / "transport"
CAMPAIGN = WPS_PRIVATE / "campaign"
WORKFLOW = WPS_PRIVATE / "workflow"


def wsl_path(path: Path) -> str:
    path = path.resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WpsLabSuiteHostTest(unittest.TestCase):
    def compile_and_run(self, name, sources, expected, include_dirs=(),
                        run_args=()):
        for source in sources:
            self.assertTrue(source.is_file(), f"missing source: {source}")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / name
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(c) for c in ("cc", "gcc", "clang")
                                 if shutil.which(c)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            for include_dir in (WORKFLOW, SESSION, *include_dirs):
                flags.extend(["-I", str(include_dir)])
            if compiler:
                command = [compiler, *flags, *map(str, sources), "-o", str(executable)]
                run = [str(executable), *map(str, run_args)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra",
                           "-Werror", "-pedantic",
                           *(item for include_dir in (WORKFLOW, SESSION, *include_dirs)
                             for item in ("-I", wsl_path(include_dir))),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable),
                       *(wsl_path(Path(arg)) for arg in run_args)]
            else:
                self.fail("Host C compiler required (native or WSL)")
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def test_secret_vault(self):
        self.compile_and_run(
            "lab_secret_test",
            [WPS_TEST / "lab_secret_test.c",
             WORKFLOW / "lab_secret.c"],
            "PASS: WPS lab secret vault")

    def test_result_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "wps"
            self.compile_and_run(
                "lab_result_store_test",
                [WPS_TEST / "lab_result_store_test.c",
                 WORKFLOW / "lab_result_store.c"],
                "PASS: WPS lab result store", run_args=[store_root])

    def test_result_store_io_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "wps"
            self.compile_and_run(
                "lab_result_store_io_test",
                [WPS_TEST / "lab_result_store_io_test.c"],
                "PASS: WPS lab result store I/O faults",
                run_args=[store_root])

    def test_radio_owner(self):
        self.compile_and_run(
            "lab_radio_test",
            [WPS_TEST / "lab_radio_test.c",
             WORKFLOW / "lab_platform.c",
             WORKFLOW / "lab_radio.c",
             ROOT / "main" / "sta_mac_policy_core.c",
             ROOT / "main" / "sta_mac_policy_store.c",
             TRANSPORT / "wps_transport_core.c"],
            "PASS: WPS lab radio owner",
            [ROOT / "main", TRANSPORT])

    def test_session_engine(self):
        self.compile_and_run(
            "lab_wps_session_test",
            [WPS_TEST / "lab_wps_session_test.c",
             SESSION / "lab_wps_session.c",
             SESSION / "session_policy.c"],
            "PASS: WPS lab session engine",
            [SESSION, PIXIE])
        adapter = (SESSION / "lab_wps_session_esp.c").read_text(encoding="utf-8")
        header = (SESSION / "lab_wps_session_esp.h").read_text(encoding="utf-8")
        self.assertIn("lab_wps_esp_session_open", header)
        self.assertIn("lab_wps_esp_session_close", header)
        self.assertIn("lab_radio_accept_callback", adapter)
        self.assertIn("wsc_reassembly_accept", adapter)
        self.assertIn("callbacks_inflight", adapter)
        self.assertIn("callback_drain", adapter)
        self.assertNotIn("printf(", adapter)
        self.assertNotRegex(adapter, r'#include\s+["<][^">]+\.c[">]')

    def test_rx_retransmission_gate(self):
        self.compile_and_run(
            "lab_wps_rx_gate_test",
            [WPS_TEST / "lab_wps_rx_gate_test.c",
             SESSION / "lab_wps_rx_gate.c"],
            "PASS: WPS RX retransmission gate")

    def test_workflows(self):
        self.compile_and_run(
            "lab_workflows_test",
            [WPS_TEST / "lab_workflows_test.c",
             WORKFLOW / "lab_workflows.c",
             WORKFLOW / "lab_platform.c",
             WORKFLOW / "lab_radio.c",
             WORKFLOW / "lab_result_store.c",
             WORKFLOW / "lab_secret.c",
             ROOT / "main" / "sta_mac_policy_core.c",
             ROOT / "main" / "sta_mac_policy_store.c",
             CAMPAIGN / "campaign_runner.c",
             CAMPAIGN / "campaign_policy.c",
             SESSION / "session_policy.c",
             TRANSPORT / "wps_transport_core.c",
             ROOT / "main" / "wps_pin_algorithms.c"],
            "PASS: WPS lab workflows",
            [ROOT / "main",
             CAMPAIGN,
             PIXIE,
             SESSION,
             TRANSPORT,
             PROTOCOL])
        source = (WORKFLOW / "lab_workflows.c").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\bprintf\(")
        self.assertNotRegex(source, r"\bputs\(")

if __name__ == "__main__":
    unittest.main()
