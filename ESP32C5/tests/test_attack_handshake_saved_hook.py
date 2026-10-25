"""Exercise the selected/manual handshake save hook with file I/O faults."""

from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _function(source, name):
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()), source, flags=re.S,
    )
    match = re.search(r"^(?:bool|void)\s+" + re.escape(name) +
                      r"\s*\([^;{}]*\)\s*\{", masked, re.M)
    if not match:
        raise ValueError(name)
    begin = source.rfind("\n", 0, match.start()) + 1
    depth, end = 1, match.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[begin:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    int essid_len;
    char essid[33];
    int message_pair;
    int eapol_len;
    uint8_t mac_ap[6];
} hccapx_t;

enum fault { NONE, OPEN, WRITE, FLUSH, SYNC, CLOSE };
static enum fault fault;
static int fault_file;
static int opened;
static int file_stage;
static int flushed;
static int synced;
static int closed;
static int saved_hits;
static bool complete = true;
static bool pcap_available = true;
static bool captured_beacon = true;
static uint8_t handshake_frame_count = 4;
static void (*saved_hook)(void);
static hccapx_t sample = {.essid_len = 4, .essid = "test", .message_pair = 1};
static uint8_t pcap[32] = {0};

static hccapx_t *hccapx_serializer_get(void) { return &sample; }
static bool is_handshake_complete(const hccapx_t *value)
{ (void)value; return complete; }
static uint8_t *pcap_serializer_get_buffer(void)
{ return pcap_available ? pcap : NULL; }
static unsigned pcap_serializer_get_size(void) { return sizeof(pcap); }
static uint64_t esp_timer_get_time(void) { return 123456000ULL; }
static void sd_sync(void) {}
static void sanitize_ssid_for_filename(char *out, const char *in, size_t size)
{ snprintf(out, size, "%s", in); }
static void format_mac_suffix(const uint8_t *mac, char out[7])
{ (void)mac; memcpy(out, "A1B2C3", 7); }
static int fake_mkdir(const char *path, unsigned int mode)
{ (void)path; (void)mode; return 0; }
static FILE *fake_fopen(const char *path, const char *mode)
{
    (void)path; (void)mode;
    file_stage = ++opened;
    if (fault == OPEN && file_stage == fault_file) return NULL;
    return tmpfile();
}
static size_t fake_fwrite(const void *data, size_t size, size_t count, FILE *file)
{
    size_t written = fwrite(data, size, count, file);
    if (fault == WRITE && file_stage == fault_file && written > 0)
        return written - 1;
    return written;
}
static int fake_fflush(FILE *file)
{
    ++flushed;
    if (fault == FLUSH && file_stage == fault_file) return EOF;
    return fflush(file);
}
static int fake_fsync(int fd)
{
    (void)fd;
    ++synced;
    return fault == SYNC && file_stage == fault_file ? -1 : 0;
}
static int fake_fclose(FILE *file)
{
    ++closed;
    int result = fclose(file);
    return fault == CLOSE && file_stage == fault_file ? EOF : result;
}

#define mkdir fake_mkdir
#define fopen fake_fopen
#define fwrite fake_fwrite
#define fflush fake_fflush
#define fileno(file) 42
#define fsync fake_fsync
#define fclose fake_fclose
FUNCTIONS
#undef mkdir
#undef fopen
#undef fwrite
#undef fflush
#undef fileno
#undef fsync
#undef fclose

static void on_saved(void) { ++saved_hits; }
static void reset(enum fault fault_kind, int file_number)
{
    fault = fault_kind;
    fault_file = file_number;
    opened = file_stage = flushed = synced = closed = 0;
}

int main(void)
{
    attack_handshake_set_saved_hook(on_saved);
    reset(NONE, 0);
    assert(attack_handshake_save_to_sd());
    assert(saved_hits == 1);

    const enum fault faults[] = {OPEN, WRITE, FLUSH, SYNC, CLOSE};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
        for (int file_number = 1; file_number <= 2; ++file_number) {
            reset(faults[i], file_number);
            assert(!attack_handshake_save_to_sd());
            assert(saved_hits == 1);
            assert(opened == file_number);
        }
    }

    reset(NONE, 0);
    assert(attack_handshake_save_to_sd());
    assert(saved_hits == 2);
    assert(opened == 2 && flushed == 2 && synced == 2 && closed == 2);

    complete = false;
    assert(!attack_handshake_save_to_sd());
    assert(saved_hits == 2);
    complete = true;
    pcap_available = false;
    assert(!attack_handshake_save_to_sd());
    assert(saved_hits == 2);

    pcap_available = true;
    attack_handshake_set_saved_hook(NULL);
    assert(attack_handshake_save_to_sd());
    assert(saved_hits == 2);
    puts("PASS: handshake saved hook and both-file I/O failures");
    return 0;
}
'''


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class AttackHandshakeSavedHookTest(unittest.TestCase):
    def test_hook_waits_for_both_files_to_flush_sync_and_close(self):
        source = (ROOT / "main/attack_handshake.c").read_text(encoding="utf-8")
        functions = "\n".join(_function(source, name) for name in (
            "attack_handshake_set_saved_hook", "attack_handshake_save_to_sd"))
        code = HARNESS.replace("FUNCTIONS", functions)
        with tempfile.TemporaryDirectory(prefix="janos-handshake-save-") as directory:
            generated = Path(directory) / "saved_hook_test.c"
            executable = Path(directory) / "saved_hook_test"
            generated.write_text(code, encoding="utf-8")
            compiler = os.environ.get("CC", "gcc")
            built = subprocess.run([
                compiler, "-std=c11", "-Wall", "-Wextra", "-pedantic",
                str(generated), "-o", str(executable),
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT,
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(executed.returncode, 0,
                             executed.stdout + executed.stderr)
            self.assertIn("PASS: handshake saved hook and both-file I/O failures",
                          executed.stdout)


if __name__ == "__main__":
    unittest.main()
