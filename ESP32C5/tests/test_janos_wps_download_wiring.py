"""Keep the ESP adapter connected to the host-tested download flow."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class JanosWpsDownloadWiringTest(unittest.TestCase):
    def test_download_handler_uses_flow_and_terminal_wipe(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        handler = main[main.index("static int cmd_download(int argc, char **argv)\n{"):]
        handler = handler[:handler.index("static int cmd_reboot(int argc, char **argv)")]
        self.assertIn("janos_download_flow_run(", handler)
        self.assertIn(".terminal_wipe =", handler)
        self.assertIn("janos_wps_runtime_terminal_wipe_quarantined(", main)

    def test_runtime_reset_erases_retained_radio_state(self):
        runtime = (ROOT / "components/janos_wps/janos_wps_runtime.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("janos_wps_download_ready(", runtime)
        self.assertIn("lab_radio_terminal_wipe(", runtime)
        self.assertIn("janos_wps_transport_reset(", runtime)


if __name__ == "__main__":
    unittest.main()
