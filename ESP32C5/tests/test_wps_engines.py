"""Run the retained protocol, PIN, Pixie and session-frame C fixtures."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"
WPS_TEST = WPS / "test"
PRIVATE = WPS / "private"


class WpsEngineTest(unittest.TestCase):
    def run_fixture(self, name, production_sources, include_groups, *, crypto=False):
        compile_and_run(
            self, name, [WPS_TEST / f"{name}.c",
                         *(PRIVATE / source for source in production_sources)],
            [PRIVATE / group for group in include_groups],
            extra_flags=("-DWPS_HOST_TEST", "-O2") if crypto else (),
            libraries=("-l:libcrypto.so.3",) if crypto else ())

    def test_protocol_parsing_and_message_policy(self):
        self.run_fixture("protocol_test", ["protocol/protocol.c"], ["protocol"])

    def test_m3_parsing_and_authenticator_policy(self):
        self.run_fixture("m3_protocol_test", ["protocol/m3_protocol.c"], ["protocol"])

    def test_pin_crypto_known_answers_and_invalid_settings(self):
        self.run_fixture("pin_crypto_test", ["pin/pin_crypto.c"], ["pin"], crypto=True)

    def test_pin_protocol_m1_through_m7(self):
        self.run_fixture("pin_protocol_test", ["pin/pin_protocol.c"], ["pin"])

    def test_pixie_prng_search_boundaries_and_cancellation(self):
        self.run_fixture("pixie_test", ["pixie/pixie.c", "pixie/pixie_prng.c"],
                         ["pixie"], crypto=True)

    def test_session_frames_and_nack_config_errors(self):
        self.run_fixture("session_frames_test", ["session/session_frames.c"], ["session"])


if __name__ == "__main__":
    unittest.main()
