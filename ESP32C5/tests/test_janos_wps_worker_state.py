from pathlib import Path
import unittest

from tests.wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"


class JanosWpsWorkerStateTest(unittest.TestCase):
    def test_service_idle_does_not_join_live_runtime_epilogue(self):
        compile_and_run(
            self,
            "janos_wps_worker_state_test",
            [WPS / "test/janos_wps_worker_state_test.c"],
            [WPS / "private"],
            expected="PASS: JanOS WPS runtime worker completion",
            extra_flags=("-pthread",),
        )

        runtime = (WPS / "janos_wps_runtime.c").read_text(encoding="utf-8")
        worker = runtime[runtime.index("static void runtime_worker"):]
        worker = worker[:worker.index("static bool service_start_worker")]
        self.assertLess(worker.index("janos_wps_worker_state_released"),
                        worker.index("state->pending_worker"))
        self.assertIn("vTaskDelay(1);", worker)
        self.assertNotIn("vTaskDelay(pdMS_TO_TICKS(1))", worker)
        self.assertIn("janos_wps_worker_state_finish", worker)
        self.assertLess(worker.index("janos_wps_format_terminal"),
                        worker.index("janos_wps_worker_state_finish"))
        self.assertLess(worker.index("state->pending_worker = NULL"),
                        worker.index("janos_wps_worker_state_finish"))
        stop = runtime[runtime.index("static runtime_stop_attempt_t runtime_stop_attempt"):]
        self.assertIn("janos_wps_worker_stop_action", stop)

        command = runtime[runtime.index("int janos_wps_command"):]
        command = command[:command.index("static int start_parsed_operation")]
        self.assertLess(command.index("janos_wps_format_accepted"),
                        command.index("fflush(stdout)"))
        self.assertLess(command.index("fflush(stdout)"),
                        command.index("janos_wps_worker_state_release"))

        parsed = runtime[runtime.index("static int start_parsed_operation"):]
        parsed = parsed[:parsed.index("int janos_jwps_command")]
        self.assertLess(parsed.index("janos_wps_format_accepted"),
                        parsed.index("fflush(stdout)"))
        self.assertLess(parsed.index("fflush(stdout)"),
                        parsed.index("janos_wps_worker_state_release"))


if __name__ == "__main__":
    unittest.main()
