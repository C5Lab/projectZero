#define _POSIX_C_SOURCE 200809L
#include "artifact_inventory_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>

static ai_inventory_t inventory;
static char output[131072];
static size_t used;
static unsigned yields;
static int cancel_after, change_after, timeout_after, cancel_on_finishing;
static uint64_t clock_ms;
static unsigned char record[393];
static bool inspection_read_only;
static unsigned read_opens;
FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (inspection_read_only) assert(strcmp(mode, "rb") == 0);
    if (mode[0] == 'r') ++read_opens;
    return __real_fopen(path, mode);
}

#ifdef AI_CONSOLE_SOURCE
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
#define pdPASS 1
static void (*queued_task)(void *);
static int fail_task;
static int xTaskCreate(void (*task)(void *), const char *name, unsigned stack,
                       void *argument, unsigned priority, void *handle)
{
    (void)name; (void)stack; (void)argument; (void)priority; (void)handle;
    if (fail_task) return 0;
    queued_task = task;
    return pdPASS;
}
static void vTaskDelete(void *task) { (void)task; }
#define taskYIELD() ((void)0)
static int64_t esp_timer_get_time(void) { return 0; }
static int console_print(const char *format, ...)
{
    va_list args; va_start(args, format);
    int count = vsnprintf(output + used, sizeof(output) - used, format, args);
    va_end(args); assert(count > 0 && (size_t)count < sizeof(output) - used);
    used += (size_t)count; return count;
}
#define printf console_print
#include AI_CONSOLE_SOURCE
#undef printf
#endif

static void write_bytes(const char *name, const void *bytes, size_t size)
{
    FILE *file = fopen(name, "wb");
    assert(file);
    assert(fwrite(bytes, 1, size, file) == size);
    assert(fclose(file) == 0);
}

static void emit(void *user, const char *line)
{
    (void)user;
    assert(strlen(line) < AI_LINE_MAX);
    assert(strncmp(line, "[ARTIFACT/1] ", 13) == 0);
    assert(strchr(line, '\n') == NULL && strchr(line, '\r') == NULL);
    assert(used + strlen(line) + 2 < sizeof(output));
    used += (size_t)sprintf(output + used, "%s\n", line);
}

static bool cancelled(void *user) { (void)user; return cancel_after && yields >= (unsigned)cancel_after; }
static uint64_t now(void *user) { (void)user; return clock_ms; }
static void yield(void *user)
{
    (void)user;
    ++yields;
    if (timeout_after && yields == (unsigned)timeout_after) clock_ms = AI_TIMEOUT_MS;
    if (change_after && yields == (unsigned)change_after) {
        /* Simulate another actor changing the source; bypass the production
         * read-only monitor for this deliberately external mutation only. */
        FILE *file = __real_fopen("handshakes/a.hccapx", "ab");
        assert(file && fputc(1, file) != EOF && fclose(file) == 0);
    }
}

static void finishing(void *user)
{
    (void)user;
    if (cancel_on_finishing) {
        cancel_after = 1;
        yields = 1;
    }
}

static ai_hooks_t hooks = {
    .emit = emit, .cancelled = cancelled, .now_ms = now, .yield = yield,
    .finishing = finishing, .user = NULL,
};

static void reset_output(void) { used = yields = 0; output[0] = 0; cancel_after = change_after = timeout_after = cancel_on_finishing = 0; clock_ms = 0; }
static unsigned occurrences(const char *needle)
{
    unsigned count = 0;
    const char *p = output;
    while ((p = strstr(p, needle)) != NULL) { ++count; p += strlen(needle); }
    return count;
}

static void run(int argc, const char **argv)
{
    ai_request_t request;
    assert(ai_parse_command(argc, argv, &request));
    inspection_read_only = true;
    assert(ai_run(&inventory, &request, &hooks));
    inspection_read_only = false;
    assert(occurrences("[ARTIFACT/1] END ") == 1);
}

static void list(const char *cursor, const char *limit)
{
    const char *args[] = {"artifact_inventory", "list", "request_1", "handshakes", cursor, limit};
    run(6, args);
}

static void inspect(void)
{
    char snapshot[16];
    snprintf(snapshot, sizeof(snapshot), "%u", inventory.snapshot);
    const char *args[] = {"artifact_inventory", "inspect", "inspect_1", snapshot, "1"};
    run(5, args);
}

static void parsing(void)
{
    ai_request_t request;
    const char *args[] = {"artifact_inventory", "list", "req-1", "handshakes", "0", "32"};
    assert(ai_parse_command(6, args, &request));
    const char *bad_scopes[] = {"../handshakes", "/sdcard/lab/handshakes", "handshakes/", "pcaps/../handshakes", "", "wordlists"};
    for (size_t i = 0; i < sizeof(bad_scopes)/sizeof(*bad_scopes); ++i) {
        args[3] = bad_scopes[i]; assert(!ai_parse_command(6, args, &request));
    }
    args[3] = "pcaps";
    const char *bad_numbers[] = {"-1", "+1", " 1", "1x", "4294967296", "9999999999999999999999", ""};
    for (size_t i = 0; i < sizeof(bad_numbers)/sizeof(*bad_numbers); ++i) {
        args[4] = bad_numbers[i]; assert(!ai_parse_command(6, args, &request));
    }
    args[4] = "0"; args[5] = "33"; assert(!ai_parse_command(6, args, &request));
    args[5] = "0"; assert(!ai_parse_command(6, args, &request));
    args[5] = "1"; args[2] = "bad\nreq"; assert(!ai_parse_command(6, args, &request));
    args[2] = "123456789012345678901234567890123"; assert(!ai_parse_command(6, args, &request));
    args[2] = "valid"; assert(!ai_parse_command(5, args, &request));
    assert(!ai_parse_command(7, args, &request));
    assert(!ai_parse_command(0, NULL, &request));
    args[2] = NULL; assert(!ai_parse_command(6, args, &request));
    const char *inspect_args[] = {"artifact_inventory", "inspect", "r", "0", "1"};
    assert(!ai_parse_command(5, inspect_args, &request));
    inspect_args[3] = "1"; inspect_args[4] = "257"; assert(!ai_parse_command(5, inspect_args, &request));
    const char *cancel_args[] = {"artifact_inventory", "cancel", "r"};
    assert(ai_parse_command(3, cancel_args, &request));
}

static void fixture(void)
{
    memset(record, 0, sizeof(record));
    memcpy(record, "HCPX", 4); record[4] = 4; record[9] = 1; record[10] = 'x';
    record[42] = 2; record[135] = 99; record[138] = 3; record[140] = 95; record[143] = 2;
}

static void inventory_and_validation(void)
{
    assert(mkdir("handshakes", 0700) == 0 && mkdir("pcaps", 0700) == 0);
    fixture(); write_bytes("handshakes/a.hccapx", record, sizeof(record));
    write_bytes("handshakes/b space.pcap", "123456789", 9);
    write_bytes("handshakes/z\n\xff.pcap", "raw", 3);
    assert(symlink("../outside.hccapx", "handshakes/link.hccapx") == 0);
    write_bytes("outside.hccapx", "private", 7);
    assert(ai_inventory_init(&inventory, "."));
    read_opens = 0;
    reset_output(); list("0", "1");
    assert(read_opens == 0); /* Listing reads metadata, never source contents. */
    assert(strstr(output, "ITEM req=request_1 snapshot=1 entry=1 name_hex=612e686363617078 size=393"));
    assert(strstr(output, "validation=unknown reason=cache_stale"));
    assert(strstr(output, "status=ok reason=ok next=1 more=1 count=1"));
    reset_output(); list("1", "2");
    assert(occurrences("[ARTIFACT/1] ITEM ") == 2);
    assert(strstr(output, "name_hex=622073706163652e70636170"));
    assert(strstr(output, "name_hex=7a0aff2e70636170"));
    assert(strstr(output, "next=3 more=0 count=2"));
    assert(strstr(output, "entry=4") == NULL);
    reset_output(); inspect();
    assert(strstr(output, "RESULT req=inspect_1 snapshot=1 entry=1 validation=valid reason=ok crc32="));
    reset_output(); cancel_on_finishing = 1; inspect();
    assert(strstr(output, "validation=unknown reason=cancelled crc32=none"));
    assert(strstr(output, "status=cancelled reason=cancelled"));
    unsigned char preserved[393];
    FILE *file = fopen("handshakes/a.hccapx", "rb");
    assert(file && fread(preserved, 1, sizeof(preserved), file) == sizeof(preserved));
    assert(fgetc(file) == EOF && fclose(file) == 0 && memcmp(record, preserved, sizeof(record)) == 0);
    assert(access("handshakes/a.hccapx.verified", F_OK) != 0);
    reset_output();
    const char *pcap[] = {"artifact_inventory", "inspect", "raw", "1", "2"};
    run(5, pcap); assert(strstr(output, "validation=unknown reason=unsupported_validator crc32=cbf43926"));
    reset_output(); list("1", "1"); assert(strstr(output, "validation=unknown reason=unsupported_validator"));
    inventory.entries[1].crc32 ^= 1; /* A corrupt cache must become unknown. */
    reset_output(); list("1", "1"); assert(strstr(output, "validation=unknown reason=cache_stale"));
    reset_output();
    const char *stale[] = {"artifact_inventory", "inspect", "stale", "999", "1"};
    run(5, stale); assert(strstr(output, "validation=unknown reason=cache_stale"));

    /* Corrupt fields are classified without deleting or rewriting source bytes. */
    record[9] = 33; write_bytes("handshakes/a.hccapx", record, sizeof(record));
    reset_output(); list("0", "1"); reset_output(); inspect();
    assert(strstr(output, "validation=invalid reason=invalid_field"));
    assert(access("handshakes/a.hccapx", F_OK) == 0);
    file = fopen("handshakes/a.hccapx", "rb");
    assert(file && fread(preserved, 1, sizeof(preserved), file) == sizeof(preserved));
    assert(fgetc(file) == EOF && fclose(file) == 0 && memcmp(record, preserved, sizeof(record)) == 0);
    fixture(); record[42] = 3; record[143] = 3;
    write_bytes("handshakes/a.hccapx", record, sizeof(record));
    reset_output(); list("0", "1"); reset_output(); inspect();
    assert(strstr(output, "validation=invalid reason=invalid_field"));
    fixture();
    unsigned char too_many[393 * 17];
    for (size_t i = 0; i < 17; ++i) memcpy(too_many + i * 393, record, 393);
    write_bytes("handshakes/a.hccapx", too_many, sizeof(too_many));
    reset_output(); list("0", "1"); reset_output(); inspect();
    assert(strstr(output, "validation=invalid reason=limit_reached"));
    fixture(); record[4] = 5; write_bytes("handshakes/a.hccapx", record, sizeof(record));
    reset_output(); list("0", "1"); reset_output(); inspect();
    assert(strstr(output, "validation=unknown reason=unsupported_format"));
    write_bytes("handshakes/a.hccapx", record, 0);
    reset_output(); list("0", "1"); reset_output(); inspect(); assert(strstr(output, "validation=invalid reason=empty"));
    write_bytes("handshakes/a.hccapx", record, 392);
    reset_output(); list("0", "1"); reset_output(); inspect(); assert(strstr(output, "reason=invalid_length"));
    fixture(); unsigned char long_record[394]; memcpy(long_record, record, 393); long_record[393] = 1;
    write_bytes("handshakes/a.hccapx", long_record, sizeof(long_record));
    reset_output(); list("0", "1"); reset_output(); inspect(); assert(strstr(output, "reason=truncated_record"));

    FILE *large = fopen("handshakes/a.hccapx", "wb"); assert(large);
    for (int i = 0; i < 40; ++i) assert(fwrite(record, 1, sizeof(record), large) == sizeof(record));
    assert(fclose(large) == 0);
    reset_output(); list("0", "1"); reset_output(); timeout_after = 1; inspect();
    assert(strstr(output, "validation=unknown reason=timeout crc32=none"));
    reset_output(); list("0", "1"); reset_output(); cancel_after = 1; inspect();
    assert(strstr(output, "validation=unknown reason=cancelled crc32=none"));
    assert(strstr(output, "status=cancelled reason=cancelled"));
    file = fopen("handshakes/a.hccapx", "rb"); assert(file);
    for (unsigned i = 0; i < 40; ++i) {
        assert(fread(preserved, 1, sizeof(preserved), file) == sizeof(preserved));
        assert(memcmp(record, preserved, sizeof(record)) == 0);
    }
    assert(fgetc(file) == EOF && fclose(file) == 0);
    reset_output(); change_after = 1; inspect(); assert(strstr(output, "validation=unknown reason=changed crc32=none"));
    reset_output(); inspect(); assert(strstr(output, "validation=unknown reason=changed"));

    /* Oversize files are bounded without reading their full content. */
    large = fopen("handshakes/a.hccapx", "wb"); assert(large);
    assert(ftruncate(fileno(large), AI_INSPECT_MAX + 1) == 0 && fclose(large) == 0);
    reset_output(); list("0", "1"); reset_output(); inspect(); assert(strstr(output, "reason=limit_reached crc32=none bytes=0"));
    reset_output(); list("256", "1"); assert(strstr(output, "status=error reason=invalid_field"));
    inventory.snapshot = UINT32_MAX;
    reset_output(); list("0", "1"); assert(strstr(output, "status=error reason=limit_reached"));
}

static void bounds_and_confinement(void)
{
    char path[AI_PATH_MAX], name[AI_NAME_MAX + 1];
    memset(name, 'a', 250); memcpy(name + 250, ".pcap", 6);
    snprintf(path, sizeof(path), "pcaps/%s", name); write_bytes(path, "", 0);
    for (unsigned i = 0; i < AI_ENTRIES_MAX; ++i) {
        snprintf(path, sizeof(path), "pcaps/b%03u.pcap", i); write_bytes(path, "", 0);
    }
    assert(ai_inventory_init(&inventory, "."));
    const char *args[] = {"artifact_inventory", "list", "bounded", "pcaps", "0", "32"};
    reset_output(); read_opens = 0; run(6, args);
    assert(read_opens == 0 && inventory.count == AI_ENTRIES_MAX);
    assert(occurrences("[ARTIFACT/1] ITEM ") == AI_PAGE_MAX);
    assert(strstr(output, "status=error reason=limit_reached next=32 more=1 count=32"));
    args[4] = "255"; reset_output(); run(6, args);
    assert(occurrences("[ARTIFACT/1] ITEM ") == 1 && strstr(output, "next=256 more=0 count=1"));
    assert(mkdir("confined", 0700) == 0 && symlink("../pcaps", "confined/pcaps") == 0);
    assert(ai_inventory_init(&inventory, "confined"));
    args[4] = "0"; reset_output(); run(6, args);
    assert(strstr(output, "status=error reason=io_error") && occurrences("[ARTIFACT/1] ITEM ") == 0);
    memset(path, 'x', sizeof(path)); path[sizeof(path) - 1] = 0;
    assert(!ai_inventory_init(&inventory, path));
}

int main(void)
{
    parsing(); inventory_and_validation(); bounds_and_confinement();
    const char *capabilities[] = {"artifact_inventory", "capabilities"};
    reset_output(); run(2, capabilities);
    assert(strstr(output, "CAPABILITIES req=0 snapshot=0 artifact_inventory=1"));
    assert(strstr(output, "END req=0 snapshot=0 status=ok reason=ok"));
#ifdef AI_CONSOLE_SOURCE
    art_inventory = &inventory;
    inventory.snapshot = 1;
    char *inspect_args[] = {"artifact_inventory", "inspect", "console", "1", "1"};
    char *cancel_args[] = {"artifact_inventory", "cancel", "console"};
    char *busy_args[] = {"artifact_inventory", "list", "other", "handshakes", "0", "1"};
    reset_output();
    assert(cmd_artifact_inventory(5, inspect_args) == 0 && queued_task);
    assert(cmd_artifact_inventory(5, inspect_args) == 0);
    assert(used == 0); /* A repeated live ID must not terminate that live request. */
    assert(cmd_artifact_inventory(6, busy_args) != 0);
    assert(occurrences("END req=other ") == 1 && strstr(output, "reason=busy"));
    assert(cmd_artifact_inventory(3, cancel_args) == 0);
    reset_output();
    queued_task(NULL);
    assert(occurrences("END req=console ") == 1 && strstr(output, "reason=cancelled"));
    used = 0; output[0] = 0;
    assert(cmd_artifact_inventory(3, cancel_args) != 0 && used == 0);
    fail_task = 1;
    assert(cmd_artifact_inventory(5, inspect_args) != 0);
    assert(occurrences("END req=console ") == 1 && strstr(output, "reason=busy"));
    art_inventory = NULL;
#endif
    puts("artifact_inventory_core_test: PASS");
    return 0;
}
