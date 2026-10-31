"""Guard the static Help QR path and the Web plugin's Evil Twin QR."""

from pathlib import Path
import re
import unittest


HOST = Path(__file__).resolve().parents[1] / "Lab_C5.c"
WEB_QR = Path(__file__).resolve().parents[1] / "modules" / "web" / "web_qr.c"


def function_body(source: str, name: str) -> str:
    match = re.search(rf"static void {re.escape(name)}\([^;{{]*\)\s*\{{", source)
    if match is None:
        raise AssertionError(f"Missing {name}")
    start = match.end() - 1
    depth = 1
    end = start + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


class HelpQrHostContract(unittest.TestCase):
    def test_help_uses_static_matrix_and_keeps_navigation(self) -> None:
        source = HOST.read_text(encoding="utf-8")
        self.assertTrue('#include "gfx/help_qr_bitmap.h"' in source, "Missing asset include")
        draw = function_body(source, "simple_app_draw_help_qr")
        self.assertIn("LAB_C5_HELP_QR_SIZE", draw)
        self.assertIn("lab_c5_help_qr_get_module", draw)
        self.assertIn('"Scan to"', draw)
        self.assertIn('"open wiki"', draw)
        self.assertIn('"Back"', draw)
        self.assertNotIn("qrcodegen_", draw)
        navigate = function_body(source, "simple_app_handle_help_qr_input")
        self.assertIn("InputKeyBack", navigate)
        self.assertIn("ScreenMenu", navigate)
        self.assertTrue("ScreenHelpQr" in source, "Help screen missing")

    def test_help_has_no_runtime_qr_allocation(self) -> None:
        source = HOST.read_text(encoding="utf-8")
        for old_name in (
            "simple_app_prepare_help_qr",
            "simple_app_alloc_help_qr_buffers",
            "simple_app_free_help_qr_buffers",
            "help_qr_temp",
            "help_qr_ready",
        ):
            with self.subTest(old_name=old_name):
                self.assertFalse(old_name in source, f"Legacy Help QR path remains: {old_name}")

    def test_evil_twin_qr_remains_available(self) -> None:
        host = HOST.read_text(encoding="utf-8")
        plugin = WEB_QR.read_text(encoding="utf-8")
        self.assertNotIn("qrcodegen_", host, "Runtime QR remains in the host FAP")
        self.assertTrue("qrcodegen_encodeText(" in plugin, "Evil Twin QR encoder missing")
        self.assertTrue(
            "qrcodegen_getModule(" in plugin,
            "Evil Twin QR renderer missing",
        )


if __name__ == "__main__":
    unittest.main()
