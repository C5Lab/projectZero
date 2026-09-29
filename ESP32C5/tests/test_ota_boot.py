"""Execute JanOS startup and OTA confirmation production slices on a host.

Run in WSL: python3 -m unittest discover -s tests -p test_ota_boot.py -v
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NONCODE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)


def code_mask(source):
    return NONCODE.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), source)


def function_body(source, name):
    start = re.search(r"^static (?:void|bool|int) " + name + r"\([^;{}]*\) \{", source, re.M)
    if start is None:
        raise RuntimeError(f"missing production function {name}")
    depth = 1
    for pos in range(start.end(), len(source)):
        depth += (source[pos] == "{") - (source[pos] == "}")
        if depth == 0:
            return source[start.start():pos + 1]
    raise RuntimeError(f"unclosed production function {name}")


def startup_slice(source):
    match = re.search(r"^void app_main\(void\)\s*\{", source, re.M)
    if match is None:
        raise RuntimeError("production app_main missing")
    depth = 1
    masked = code_mask(source)
    for pos in range(match.end(), len(masked)):
        depth += (masked[pos] == "{") - (masked[pos] == "}")
        if depth == 0:
            app_main = source[match.end():pos]
            break
    else:
        raise RuntimeError("unclosed production app_main")
    def span(start_anchor, end_anchor):
        start = app_main.index(start_anchor)
        return start, app_main.index(end_anchor, start)

    nvs = span("    ota_load_channel_from_nvs();", '    //printf("NVS initialized OK')
    console = span("    esp_console_repl_t *repl = NULL;",
                   "    if (boot_button_task_handle == NULL)")
    sd_statement = "    esp_err_t sd_init_ret = init_sd_card();"
    sd_start = app_main.index(sd_statement)
    sd = (sd_start, sd_start + len(sd_statement))
    selected = [nvs, console]
    if not any(start <= sd_start < end for start, end in selected):
        selected.append(sd)

    marks = list(re.finditer(r"(?m)^[ \t]*ota_mark_valid_if_pending\(\);[ \t]*$", app_main))
    if not marks:
        raise RuntimeError("production startup confirmation call missing")
    for mark in marks:
        if not any(start <= mark.start() < end for start, end in selected):
            selected.append(mark.span())

    selected.sort()
    for (_, end), (next_start, _) in zip(selected, selected[1:]):
        if end > next_start:
            raise RuntimeError("overlapping startup spans")
    statements = "\n".join(app_main[start:end] for start, end in selected)
    return "static void run_startup_slice(void) {\n" + statements + "\n(void)sd_init_ret;\n}\n"


class OtaBootTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler is None:
            raise RuntimeError("host C compiler required")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-boot-")
        cls.addClassCleanup(cls.temp.cleanup)
        temporary = Path(cls.temp.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        readiness = re.search(r"^static atomic_bool ota_boot_ready[^;]*;", source, re.M)
        if readiness is None:
            raise RuntimeError("production boot readiness state missing")
        (temporary / "ota_boot_production.inc").write_text(
            readiness.group() + "\n"
            + function_body(source, "ota_boot_is_ready") + "\n"
            + function_body(source, "ota_mark_valid_if_pending") + "\n"
            + function_body(source, "cmd_ota_boot") + "\n" + startup_slice(source),
            encoding="utf-8",
        )
        executable = temporary / "ota_boot_host"
        build = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(temporary),
             str(ROOT / "tests/ota_boot_host.c"), "-o", str(executable)],
            capture_output=True, text=True,
        )
        if build.returncode:
            raise RuntimeError(f"host compilation failed:\n{build.stdout}\n{build.stderr}")
        cls.results = {}
        for scenario in ("pending", "valid", "legacy", "no_otadata", "state_fail",
                         "uart_fail", "repl_create_fail", "repl_start_fail", "gpio_fail", "mark_fail",
                         "boot_before_ready", "boot_after_ready", "boot_mark_fail"):
            run = subprocess.run([str(executable), scenario], capture_output=True, text=True, timeout=5)
            if run.returncode:
                raise RuntimeError(f"{scenario} failed ({run.returncode}):\n{run.stdout}\n{run.stderr}")
            cls.results[scenario] = dict(line.split("=", 1) for line in run.stdout.splitlines())

    def test_pending_image_confirmed_after_console_ready(self):
        r = self.results["pending"]
        self.assertEqual(r["mark"], "1")
        self.assertEqual(r["events"], "nvs,boot_info,uart,commands,repl_create,repl_start,gpio,state,mark,sd,")
        self.assertEqual(r["ready"], "1")

    def test_valid_image_does_not_repeat_confirmation(self):
        r = self.results["valid"]
        self.assertEqual(r["mark"], "0")
        self.assertEqual(r["events"], "nvs,boot_info,uart,commands,repl_create,repl_start,gpio,state,sd,")
        self.assertEqual(r["ready"], "1")

    def test_required_console_failure_never_confirms(self):
        for scenario in ("uart_fail", "repl_create_fail", "repl_start_fail", "gpio_fail"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.results[scenario]["mark"], "0")
                self.assertEqual(self.results[scenario]["aborted"], "1")
                self.assertEqual(self.results[scenario]["ready"], "0")

    def test_failed_mark_is_reported_as_unconfirmed(self):
        r = self.results["mark_fail"]
        self.assertEqual(r["mark"], "1")
        self.assertEqual(r["state"], "1")
        self.assertEqual(r["ready"], "0")

    def test_legacy_boot_state_allows_ready_without_mark(self):
        for scenario in ("legacy", "no_otadata"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.results[scenario]["mark"], "0")
                self.assertEqual(self.results[scenario]["ready"], "1")

    def test_unexpected_state_read_error_fails_closed(self):
        self.assertEqual(self.results["state_fail"]["ready"], "0")
        self.assertEqual(self.results["state_fail"]["mark"], "0")

    def test_manual_boot_change_requires_confirmation(self):
        for scenario in ("boot_before_ready", "boot_mark_fail"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.results[scenario]["set_boot"], "0")
                self.assertEqual(self.results[scenario]["restart"], "0")
                self.assertEqual(self.results[scenario]["command"], "1")
        self.assertEqual(self.results["boot_after_ready"]["set_boot"], "1")
        self.assertEqual(self.results["boot_after_ready"]["restart"], "1")
        self.assertEqual(self.results["boot_after_ready"]["command"], "0")


if __name__ == "__main__":
    unittest.main()
