#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    IO_FAIL_NONE = 0,
    IO_FAIL_FPRINTF,
    IO_FAIL_FPUTS,
    IO_FAIL_FPUTC,
    IO_FAIL_FGETS,
    IO_FAIL_FFLUSH,
    IO_FAIL_FSYNC,
    IO_FAIL_FCLOSE,
} io_failure_t;

typedef struct {
    FILE *file;
    bool open;
    bool injected_read_error;
} tracked_stream_t;

enum { TRACKED_STREAM_MAX = 32 };
static tracked_stream_t tracked[TRACKED_STREAM_MAX];
static unsigned open_calls;
static unsigned close_calls;
static io_failure_t fail_next;

static FILE *tracked_fopen(const char *path, const char *mode);
static int tracked_fprintf(FILE *file, const char *format, ...);
static int tracked_fputs(const char *text, FILE *file);
static int tracked_fputc(int value, FILE *file);
static char *tracked_fgets(char *text, int capacity, FILE *file);
static int tracked_ferror(FILE *file);
static int tracked_fflush(FILE *file);
static int tracked_fsync(int fd);
static int tracked_fclose(FILE *file);

#define fopen tracked_fopen
#define fprintf tracked_fprintf
#define fputs tracked_fputs
#define fputc tracked_fputc
#define fgets tracked_fgets
#define ferror tracked_ferror
#define fflush tracked_fflush
#define fsync tracked_fsync
#define fclose tracked_fclose
#include "../private/workflow/lab_result_store.c"
#undef fopen
#undef fprintf
#undef fputs
#undef fputc
#undef fgets
#undef ferror
#undef fflush
#undef fsync
#undef fclose

static tracked_stream_t *stream_entry(FILE *file)
{
    for (size_t index = 0; index < TRACKED_STREAM_MAX; ++index)
        if (tracked[index].open && tracked[index].file == file)
            return &tracked[index];
    return NULL;
}

static bool consume_failure(io_failure_t failure)
{
    if (fail_next != failure) return false;
    fail_next = IO_FAIL_NONE;
    return true;
}

static FILE *tracked_fopen(const char *path, const char *mode)
{
    FILE *file = fopen(path, mode);
    if (!file) return NULL;
    for (size_t index = 0; index < TRACKED_STREAM_MAX; ++index) {
        if (tracked[index].open) continue;
        tracked[index] = (tracked_stream_t){.file = file, .open = true};
        ++open_calls;
        return file;
    }
    assert(!"tracked stream table exhausted");
    return NULL;
}

static int tracked_fprintf(FILE *file, const char *format, ...)
{
    if (consume_failure(IO_FAIL_FPRINTF)) return -1;
    va_list args;
    va_start(args, format);
    int result = vfprintf(file, format, args);
    va_end(args);
    return result;
}

static int tracked_fputs(const char *text, FILE *file)
{
    return consume_failure(IO_FAIL_FPUTS) ? EOF : fputs(text, file);
}

static int tracked_fputc(int value, FILE *file)
{
    return consume_failure(IO_FAIL_FPUTC) ? EOF : fputc(value, file);
}

static char *tracked_fgets(char *text, int capacity, FILE *file)
{
    if (consume_failure(IO_FAIL_FGETS)) {
        tracked_stream_t *entry = stream_entry(file);
        assert(entry != NULL);
        entry->injected_read_error = true;
        return NULL;
    }
    return fgets(text, capacity, file);
}

static int tracked_ferror(FILE *file)
{
    tracked_stream_t *entry = stream_entry(file);
    return (entry && entry->injected_read_error) ? 1 : ferror(file);
}

static int tracked_fflush(FILE *file)
{
    return consume_failure(IO_FAIL_FFLUSH) ? EOF : fflush(file);
}

static int tracked_fsync(int fd)
{
    return consume_failure(IO_FAIL_FSYNC) ? -1 : fsync(fd);
}

static int tracked_fclose(FILE *file)
{
    tracked_stream_t *entry = stream_entry(file);
    assert(entry != NULL);
    bool fail = consume_failure(IO_FAIL_FCLOSE);
    int result = fclose(file);
    entry->open = false;
    ++close_calls;
    return fail ? EOF : result;
}

static void assert_balanced_streams(void)
{
    assert(open_calls == close_calls);
    for (size_t index = 0; index < TRACKED_STREAM_MAX; ++index)
        assert(!tracked[index].open);
}

static void force_close_leaks(void)
{
    for (size_t index = 0; index < TRACKED_STREAM_MAX; ++index) {
        if (!tracked[index].open) continue;
        assert(fclose(tracked[index].file) == 0);
        tracked[index].open = false;
    }
}

static void reset_tracking(void)
{
    assert_balanced_streams();
    memset(tracked, 0, sizeof(tracked));
    open_calls = 0;
    close_calls = 0;
    fail_next = IO_FAIL_NONE;
}

static void read_text(const char *path, char *output, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    size_t count = fread(output, 1, capacity - 1U, file);
    assert(!ferror(file));
    output[count] = 0;
    assert(fclose(file) == 0);
}

static size_t substring_count(const char *text, const char *needle)
{
    size_t count = 0;
    size_t needle_length = strlen(needle);
    assert(needle_length != 0U);
    while ((text = strstr(text, needle)) != NULL) {
        ++count;
        text += needle_length;
    }
    return count;
}

typedef struct {
    unsigned calls;
    bool saw_balanced_streams;
} gate_fixture_t;

static bool deny_after_durable_close(void *context, uint32_t operation_id)
{
    gate_fixture_t *fixture = context;
    assert(operation_id == 18U);
    ++fixture->calls;
    fixture->saw_balanced_streams = open_calls == close_calls;
    return false;
}

static void verify_result_failure_preserves_final(
    const char *root, const char *final_path, lab_result_record_t *record,
    io_failure_t failure)
{
    char text[2048];
    reset_tracking();
    fail_next = failure;
    gate_fixture_t gate = {0};
    assert(lab_result_store_success_gated(
        root, record, deny_after_durable_close, &gate, NULL, NULL) ==
        LAB_STORE_IO_ERROR);
    assert(gate.calls == 0U);
    assert_balanced_streams();
    read_text(final_path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);
    assert(strstr(text, "replacement") == NULL);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *root = argv[1];
    assert(mkdir(root, 0700) == 0);

    lab_result_record_t record = {
        .bssid = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        .ssid = "Lab AP",
        .pin = "12345670",
        .network_key = (const uint8_t *)"original",
        .network_key_len = 8U,
        .recovery_source = "pixie_mode_4",
        .manufacturer = "TP-Link",
        .model_name = "TL-WR840N",
        .model_number = "V6",
        .device_name = "Lab Router",
        .operation_id = 17U,
        .authenticated_m7 = true,
    };
    assert(lab_result_store_success(root, &record) == LAB_STORE_OK);
    assert_balanced_streams();

    char final_path[512];
    assert(snprintf(final_path, sizeof(final_path),
                    "%s/results/wps_68-ff-7b-cd-fc-40.json", root) > 0);
    record.operation_id = 18U;
    record.network_key = (const uint8_t *)"replacement";
    record.network_key_len = 11U;

    const io_failure_t result_failures[] = {
        IO_FAIL_FPRINTF, IO_FAIL_FPUTS, IO_FAIL_FPUTC,
        IO_FAIL_FFLUSH, IO_FAIL_FSYNC, IO_FAIL_FCLOSE,
    };
    for (size_t index = 0;
         index < sizeof(result_failures) / sizeof(result_failures[0]);
         ++index) {
        verify_result_failure_preserves_final(
            root, final_path, &record, result_failures[index]);
    }

    reset_tracking();
    gate_fixture_t gate = {0};
    assert(lab_result_store_success_gated(
        root, &record, deny_after_durable_close, &gate, NULL, NULL) ==
        LAB_STORE_CANCELLED);
    assert(gate.calls == 1U);
    assert(gate.saw_balanced_streams);
    assert_balanced_streams();

    lab_device_observation_t observation = {
        .bssid = {0x78, 0x44, 0x76, 0xf1, 0xb0, 0x88},
        .ssid = "Pure Rental Apartments",
        .stage = "adapter_open",
        .reason = "timeout",
        .manufacturer = "Realtek",
        .model_name = "RTL8xxx",
        .device_name = "TOTOLINK",
    };
    reset_tracking();
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_OK);
    assert_balanced_streams();

    reset_tracking();
    observation.reason = "read failure candidate";
    fail_next = IO_FAIL_FGETS;
    assert(lab_result_store_observation(root, &observation) ==
           LAB_STORE_IO_ERROR);
    /* A read error must not short-circuit fclose(existing). */
    assert_balanced_streams();

    /* A failed append must roll back to the previous durable boundary.  In
     * particular, it must not leave the leading fingerprint behind and turn
     * a retry into a false duplicate. */
    char observations_path[512];
    char before_append[4096];
    char after_failure[4096];
    char after_retry[4096];
    assert(snprintf(observations_path, sizeof(observations_path),
                    "%s/unknown_devices.jsonl", root) > 0);
    read_text(observations_path, before_append, sizeof(before_append));

    reset_tracking();
    observation.reason = "partial append retry";
    fail_next = IO_FAIL_FPUTC;
    assert(lab_result_store_observation(root, &observation) ==
           LAB_STORE_IO_ERROR);
    assert_balanced_streams();
    read_text(observations_path, after_failure, sizeof(after_failure));
    assert(strcmp(after_failure, before_append) == 0);

    reset_tracking();
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_OK);
    assert_balanced_streams();
    read_text(observations_path, after_retry, sizeof(after_retry));
    assert(strncmp(after_retry, before_append, strlen(before_append)) == 0);
    assert(strstr(after_retry, "partial append retry") != NULL);
    assert(substring_count(after_retry, "\"reason\":\"partial append retry\"") ==
           1U);

    const io_failure_t observation_failures[] = {
        IO_FAIL_FPRINTF, IO_FAIL_FPUTS, IO_FAIL_FPUTC,
        IO_FAIL_FFLUSH, IO_FAIL_FSYNC, IO_FAIL_FCLOSE,
    };
    const char *observation_reasons[] = {
        "fprintf failure", "fputs failure", "fputc failure",
        "fflush failure", "fsync failure", "fclose failure",
    };
    for (size_t index = 0;
         index < sizeof(observation_failures) / sizeof(observation_failures[0]);
         ++index) {
        char observation_root[512];
        char observation_path[512];
        char observation_text[2048];
        assert(snprintf(observation_root, sizeof(observation_root),
                        "%s/observation_%u", root, (unsigned)index) > 0);
        assert(snprintf(observation_path, sizeof(observation_path),
                        "%s/unknown_devices.jsonl", observation_root) > 0);
        reset_tracking();
        observation.reason = observation_reasons[index];
        fail_next = observation_failures[index];
        assert(lab_result_store_observation(observation_root, &observation) ==
               LAB_STORE_IO_ERROR);
        assert_balanced_streams();

        read_text(observation_path, observation_text, sizeof(observation_text));
        if (observation_failures[index] == IO_FAIL_FCLOSE) {
            /* The injected close error happens after the real close.  The
             * complete durable line is valid and retry deduplication is the
             * safe outcome. */
            assert(strstr(observation_text, observation_reasons[index]) != NULL);
            reset_tracking();
            assert(lab_result_store_observation(observation_root, &observation) ==
                   LAB_STORE_DUPLICATE);
        } else {
            assert(observation_text[0] == 0);
            reset_tracking();
            assert(lab_result_store_observation(observation_root, &observation) ==
                   LAB_STORE_OK);
            read_text(observation_path, observation_text,
                      sizeof(observation_text));
            assert(strstr(observation_text, observation_reasons[index]) != NULL);
        }
        assert_balanced_streams();
    }

    force_close_leaks();
    puts("PASS: WPS lab result store I/O faults");
    return 0;
}
