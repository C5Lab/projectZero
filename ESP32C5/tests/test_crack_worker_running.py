"""Execute the real crack-worker LED status functions with host mutex stubs."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "main/crack_worker.c"


def function(source: str, name: str) -> str:
    match = re.search(r"(?:static\s+)?bool\s+" + re.escape(name) +
                      r"\s*\(void\)\s*\{", source)
    if match is None:
        raise ValueError(f"missing C function: {name}")
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>

typedef int *SemaphoreHandle_t;
static int mutex_storage;
static SemaphoreHandle_t cw_mutex;
static int take_calls;
static int give_calls;
#define portMAX_DELAY (-1)
#define CW_JOB_IDLE 0
#define CW_JOB_RUNNING 1
#define CW_JOB_FOUND 2
static struct { int state; } cw_job;
static int xSemaphoreTake(SemaphoreHandle_t mutex, int timeout) {
    assert(mutex == &mutex_storage);
    assert(timeout == portMAX_DELAY);
    ++take_calls;
    return 1;
}
static int xSemaphoreGive(SemaphoreHandle_t mutex) {
    assert(mutex == &mutex_storage);
    ++give_calls;
    return 1;
}

FUNCTIONS

int main(void) {
    assert(!crack_worker_is_running());
    assert(take_calls == 0 && give_calls == 0);
    cw_mutex = &mutex_storage;
    cw_job.state = CW_JOB_IDLE;
    assert(!crack_worker_is_running());
    cw_job.state = CW_JOB_RUNNING;
    assert(crack_worker_is_running());
    cw_job.state = CW_JOB_FOUND;
    assert(!crack_worker_is_running());
    assert(take_calls == 3 && give_calls == 3);
    puts("CRACK_WORKER_RUNNING_PASS");
    return 0;
}
'''


class CrackWorkerRunningTest(unittest.TestCase):
    def test_status_is_safe_before_init_and_reads_locked_job_state(self):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            self.skipTest("host C compiler required")
        source = SOURCE.read_text(encoding="utf-8")
        real_functions = "\n\n".join(
            function(source, name)
            for name in ("cw_job_running", "crack_worker_is_running")
        )
        with tempfile.TemporaryDirectory(prefix="janos-crack-running-") as directory:
            directory = Path(directory)
            test_c = directory / "crack_worker_running_test.c"
            executable = directory / "crack_worker_running_test"
            test_c.write_text(HARNESS.replace("FUNCTIONS", real_functions), encoding="utf-8")
            compiled = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", str(test_c), "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("CRACK_WORKER_RUNNING_PASS", executed.stdout)


if __name__ == "__main__":
    unittest.main()
