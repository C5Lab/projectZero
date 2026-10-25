"""Run the production boot registration list and wrapper with a fake ESP backend.

The old 128-context limit must reproduce the reported start_blespam abort. The
production limit must register every command, keep contexts alive after returning
from register_commands, and preserve both handler calling conventions.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from test_sniffer_extended import function

ROOT = Path(__file__).resolve().parents[1]

STUBS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
typedef int (*esp_console_cmd_func_t)(int, char **);
typedef int (*esp_console_cmd_func_with_context_t)(void *, int, char **);
typedef struct {
    const char *command, *help, *hint;
    esp_console_cmd_func_t func;
    void *argtable;
    esp_console_cmd_func_with_context_t func_w_context;
    void *context;
} esp_console_cmd_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_NO_MEM 0x101
static esp_console_cmd_t registered[1024];
static size_t registered_count;
static bool backend_failure;
static const char *last_handler;
static esp_err_t esp_console_cmd_register(const esp_console_cmd_t *cmd)
{
    if (backend_failure) return ESP_ERR_NO_MEM;
    assert(registered_count < sizeof(registered)/sizeof(registered[0]));
    registered[registered_count++] = *cmd;
    return ESP_OK;
}
#define ESP_ERROR_CHECK(expr) do { \
    esp_err_t error = (expr); \
    if (error != ESP_OK) { \
        fprintf(stderr, "REGISTRATION_FAILED contexts=%zu error=0x%x expression=%s\n", \
                janos_console_cmd_context_count, error, #expr); exit(42); \
    } \
} while (0)
'''

HARNESS = r'''
#undef esp_console_cmd_register
static int context_handler(void *context, int argc, char **argv)
{
    assert(argc == 2 && argv != NULL);
    return *(int *)context;
}
int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "backend-failure")) {
        esp_console_cmd_t cmd = {.command="retry", .func=cmd_ping};
        assert(janos_console_cmd_register(NULL) == ESP_ERR_INVALID_ARG);
        esp_console_cmd_t invalid = {.command="invalid"};
        assert(janos_console_cmd_register(&invalid) == ESP_ERR_INVALID_ARG);
        invalid.func = cmd_ping; invalid.func_w_context = context_handler;
        assert(janos_console_cmd_register(&invalid) == ESP_ERR_INVALID_ARG);
        backend_failure = true;
        assert(janos_console_cmd_register(&cmd) == ESP_ERR_NO_MEM);
        assert(janos_console_cmd_context_count == 0 && registered_count == 0);
        backend_failure = false;
        assert(janos_console_cmd_register(&cmd) == ESP_OK);
        assert(janos_console_cmd_context_count == 1 && registered_count == 1);
        int result = 73;
        cmd = (esp_console_cmd_t){.command="context", .func_w_context=context_handler, .context=&result};
        assert(janos_console_cmd_register(&cmd) == ESP_OK);
        char *args[] = {"context", "arg"};
        assert(registered[1].func_w_context(registered[1].context, 2, args) == 73);
        puts("PASS: registration rollback and contextual handler");
        return 0;
    }
    register_commands();
    assert(registered_count == EXPECTED_COMMANDS);
    assert(janos_console_cmd_context_count == registered_count);
    for (size_t i=0; i<registered_count; ++i) {
        const esp_console_cmd_t *cmd = &registered[i];
        janos_console_cmd_context_t *context = cmd->context;
        assert(context == &janos_console_cmd_contexts[i]);
        assert(context->command == cmd->command);
        assert(cmd->func == NULL && cmd->func_w_context == janos_console_cmd_dispatch);
        char *args[] = {(char *)cmd->command};
        assert(cmd->func_w_context(cmd->context, 1, args) == 1);
        assert(last_handler != NULL);
    }
    assert(!strcmp(registered[registered_count-1].command, "version"));
    puts("REGISTERED_COMMANDS_BEGIN");
    for (size_t i=0; i<registered_count; ++i) puts(registered[i].command);
    puts("REGISTERED_COMMANDS_END");
    if (argc > 1 && !strcmp(argv[1], "boundary")) {
        static char names[JANOS_CONSOLE_MAX_COMMANDS][32];
        for (size_t i=registered_count; i<JANOS_CONSOLE_MAX_COMMANDS; ++i) {
            snprintf(names[i], sizeof(names[i]), "extra_%zu", i);
            esp_console_cmd_t cmd = {.command=names[i], .func=cmd_ping};
            assert(janos_console_cmd_register(&cmd) == ESP_OK);
        }
        esp_console_cmd_t extra = {.command="overflow", .func=cmd_ping};
        assert(janos_console_cmd_register(&extra) == ESP_ERR_NO_MEM);
        assert(janos_console_cmd_context_count == JANOS_CONSOLE_MAX_COMMANDS);
        assert(registered_count == JANOS_CONSOLE_MAX_COMMANDS);
        puts("PASS: context capacity boundary");
    }
    printf("PASS: full boot registration commands=%u capacity=%u\n", EXPECTED_COMMANDS, JANOS_CONSOLE_MAX_COMMANDS);
    return 0;
}
'''

class ConsoleStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which(os.environ.get("CC", "cc"))
        if cls.compiler is None:
            raise unittest.SkipTest("host C compiler required")
        cls.tmp = tempfile.TemporaryDirectory(prefix="janos-console-startup-")
        cls.directory = Path(cls.tmp.name)
        source = (ROOT / "main/main.c").read_text()
        registration = function(source, "register_commands")
        cls.expected = len(re.findall(r"esp_console_cmd_register\s*\(", registration))
        capacity = re.search(r"^#define JANOS_CONSOLE_MAX_COMMANDS\s+(\d+)U", source, re.M)
        if capacity is None:
            raise AssertionError("production command capacity not found")
        cls.capacity = int(capacity[1])
        contexts = re.search(r"typedef struct \{[^{}]+\} janos_console_cmd_context_t;", source).group()
        locator = re.search(r"static const esp_console_cmd_t ap_locator_cmd\s*=\s*\{[^{}]+\};", source).group()
        handlers = sorted(set(re.findall(r"\.func\s*=\s*&?(\w+)", registration + locator)))
        code = STUBS + contexts + r'''
static janos_console_cmd_context_t janos_console_cmd_contexts[JANOS_CONSOLE_MAX_COMMANDS];
static size_t janos_console_cmd_context_count;
static int janos_console_cmd_dispatch(void *context, int argc, char **argv)
{
    janos_console_cmd_context_t *cmd = context;
    return cmd->func ? cmd->func(argc, argv) : cmd->func_w_context(cmd->context, argc, argv);
}
'''
        code += function(source, "janos_console_cmd_register") + "\n"
        code += "\n".join(
            f'static int {name}(int argc, char **argv) {{ (void)argv; last_handler="{name}"; return argc; }}'
            for name in handlers)
        code += "\n" + locator + "\n#define esp_console_cmd_register(cmd) janos_console_cmd_register(cmd)\n"
        code += registration + "\n" + HARNESS
        path = cls.directory / "startup.c"
        path.write_text(code)
        cls.executables = {}
        for label, limit in (("old", 128), ("current", cls.capacity)):
            exe = cls.directory / label
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", f"-DJANOS_CONSOLE_MAX_COMMANDS={limit}U", f"-DEXPECTED_COMMANDS={cls.expected}U"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            subprocess.run([cls.compiler, *flags, str(path), "-o", str(exe)], check=True)
            cls.executables[label] = exe

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_mode(self, mode=None):
        args = [str(self.executables["current"])]
        if mode:
            args.append(mode)
        return subprocess.check_output(args, text=True)

    def test_old_limit_reproduces_reported_boot_failure(self):
        run = subprocess.run([str(self.executables["old"])], text=True, capture_output=True)
        self.assertEqual(run.returncode, 42)
        self.assertIn("contexts=128 error=0x101", run.stderr)
        self.assertIn("&start_blespam_cmd", run.stderr)

    def test_entire_production_registration_and_legacy_names(self):
        output = self.run_mode()
        self.assertIn(f"PASS: full boot registration commands={self.expected}", output)
        commands = output.split("REGISTERED_COMMANDS_BEGIN\n", 1)[1].split("REGISTERED_COMMANDS_END", 1)[0].splitlines()
        self.assertEqual(len(commands), self.expected)
        legacy = [line.strip() for line in (ROOT / "tests/fixtures/legacy_console_commands_v1.txt").read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        self.assertTrue(set(legacy).issubset(commands))
        for required in ("show_sniffer_clients", "start_deauth_station", "start_blespam", "version", "stop"):
            self.assertIn(required, commands)

    def test_capacity_boundary_without_out_of_bounds_contexts(self):
        self.assertIn("PASS: context capacity boundary", self.run_mode("boundary"))

    def test_backend_failure_does_not_consume_context(self):
        self.assertIn("PASS: registration rollback and contextual handler", self.run_mode("backend-failure"))
