"""Protect the observable legacy JanOS command registry wiring.

This is deliberately a source-level boundary test: the ESP-IDF console cannot
run on the host, while the final firmware build verifies that the same registry
compiles and links.
"""

from collections import Counter
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main" / "main.c"
LEGACY = ROOT / "tests" / "fixtures" / "legacy_console_commands_v1.txt"


class LegacyConsoleRegistryTest(unittest.TestCase):
    def test_every_legacy_command_remains_declared_and_registered_once(self):
        source = MAIN.read_text(encoding="utf-8")
        definitions = re.findall(
            r"const\s+esp_console_cmd_t\s+(\w+)\s*=\s*\{(.*?)\n\s*\};",
            source,
            flags=re.S,
        )
        commands = {}
        for variable, body in definitions:
            match = re.search(r'\.command\s*=\s*"([^"]+)"', body)
            if match:
                commands[variable] = match.group(1)

        legacy = {
            line for line in LEGACY.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        current = set(commands.values())
        self.assertEqual(legacy - current, set(), "legacy command was removed")
        self.assertEqual(
            [name for name, count in Counter(commands.values()).items() if count != 1],
            [],
            "console command names must be unique",
        )

        registrations = Counter(re.findall(
            r"esp_console_cmd_register\s*\(\s*&([A-Za-z0-9_]+)\s*\)",
            source,
        ))
        missing = sorted(
            name for variable, name in commands.items()
            if name in legacy and registrations[variable] != 1
        )
        self.assertEqual(missing, [], "legacy command is not registered exactly once")

    def test_wifi_shield_is_registered_once_with_exact_help_and_stop_order(self):
        source = MAIN.read_text(encoding="utf-8")
        registration = re.search(
            r"const\s+esp_console_cmd_t\s+wifi_shield_cmd\s*=\s*\{(.*?)\n\s*\};",
            source, flags=re.S)
        self.assertIsNotNone(registration, "wifi_shield command is not declared")
        body = registration.group(1)
        self.assertIn('.command = "wifi_shield"', body)
        self.assertIn('.help = WIFI_SHIELD_HELP_TEXT', body)
        self.assertIn('.func = &wifi_shield_command', body)
        self.assertEqual(source.count("esp_console_cmd_register(&wifi_shield_cmd)"), 1)

        stop = source.split("static int cmd_stop(int argc, char **argv) {", 1)[1].split(
            'MY_LOG_INFO(TAG, "Stop command received', 1)[0]
        self.assertIn("wifi_shield_stop(5000)", stop)
        self.assertLess(stop.index("wifi_shield_stop(5000)"),
                        stop.index("wifi_security_runtime_stop(5000)"))


if __name__ == "__main__":
    unittest.main()
