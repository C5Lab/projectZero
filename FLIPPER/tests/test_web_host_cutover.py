"""Host-side contract for the single-runtime Web FAL cutover."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "Lab_C5.c"
MANIFEST = ROOT / "application.fam"


def body(source: str, name: str) -> str:
    match = re.search(rf"static\s+(?:bool|void)\s+{re.escape(name)}\([^;{{]*\)\s*\{{", source)
    if not match:
        raise AssertionError(f"Missing host function {name}")
    start = match.end() - 1
    depth = 1
    pos = start + 1
    while depth and pos < len(source):
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    if depth:
        raise AssertionError(f"Unclosed host function {name}")
    return source[start:pos]


class WebHostCutover(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = HOST.read_text(encoding="utf-8")

    def test_all_three_menu_entries_load_web_without_power_cycle(self) -> None:
        menu = body(self.source, "simple_app_handle_menu_input")
        for mode in ("Portal", "EvilTwin", "Karma"):
            with self.subTest(mode=mode):
                self.assertIn(f"simple_app_request_web(app, C5WebMode{mode})", menu)
        opened = body(self.source, "simple_app_open_web")
        self.assertIn('APP_ASSETS_PATH("plugins/lab_c5_web.fal")', opened)
        self.assertIn("&launch, sizeof(launch)", opened)
        self.assertNotIn("furi_hal_power", opened)
        self.assertNotIn('"reboot"', opened)

    def test_module_output_routes_back_to_web_and_toggles_console(self) -> None:
        routed = body(self.source, "simple_app_handle_web_input")
        self.assertIn("c5_module_runtime_input(&app->gps_module, event)", routed)
        for result in ("C5InputSwitchTerminal", "C5InputSwitchModule", "C5InputToggleConsole"):
            self.assertIn(result, routed)
        self.assertIn("ScreenSerial", routed)
        self.assertIn("ScreenWebMenu", routed)
        self.assertIn("C5ModuleRequestUnloadWeb", routed)

    def test_only_active_runtime_consumes_rx_and_web_draws_menu_and_overlay(self) -> None:
        stream = body(self.source, "simple_app_process_stream")
        self.assertEqual(stream.count("c5_module_runtime_feed(&app->gps_module, chunk, received)"), 1)
        append = body(self.source, "simple_app_append_serial_data")
        self.assertNotIn("simple_app_portal_status_feed(app, ch)", append)
        self.assertNotIn("simple_app_evil_twin_status_feed(app, ch)", append)
        self.assertNotIn("simple_app_karma_probe_feed(app, ch)", append)
        draw = body(self.source, "simple_app_draw")
        self.assertIn("case ScreenWebMenu:", draw)
        self.assertIn("c5_module_runtime_draw(&app->gps_module, canvas)", draw)
        self.assertIn("app->web_console_mode", draw)

    def test_web_owns_stop_and_session_save_is_validated(self) -> None:
        stop = body(self.source, "simple_app_send_stop_if_needed")
        self.assertIn("if(app->web_view_active) return", stop)
        save = body(self.source, "simple_app_module_host_save_session")
        self.assertIn("size != sizeof(C5WebSessionPrefs)", save)
        self.assertIn("memchr", save)
        self.assertIn("portal_menu_index", save)
        self.assertIn("evil_menu_index", save)
        self.assertIn("karma_menu_index", save)

    def test_back_through_web_terminal_beats_fullscreen_status_and_double_back(self) -> None:
        dispatch = body(self.source, "simple_app_input")
        self.assertIn("if(!app->web_view_active && event->type == InputTypeShort &&", dispatch)
        web_back = dispatch.index("simple_app_handle_web_input(app, event);")
        fullscreen_branches = [
            match.start()
            for match in re.finditer(
                r"if\(simple_app_status_message_is_active\(app\) && app->status_message_fullscreen\)",
                dispatch,
            )
        ]
        self.assertEqual(len(fullscreen_branches), 2)
        self.assertLess(web_back, fullscreen_branches[1])
        routed = body(self.source, "simple_app_handle_web_input")
        self.assertIn("app->last_back_tick = 0", routed)

    def test_qr_encoder_lives_only_in_web_plugin(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        host_app, plugin_apps = manifest.split('appid="lab_c5_gps"', 1)
        self.assertNotIn('"qrcodegen.c"', host_app)
        self.assertIn('"qrcodegen.c"', plugin_apps)


if __name__ == "__main__":
    unittest.main()
