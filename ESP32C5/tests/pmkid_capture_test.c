#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include "pmkid_fixtures.h"

/* Inject failures at each publication boundary in the real writer. */
static unsigned fail_io;
static FILE *test_fopen(const char *path, const char *mode)
{ if (fail_io == 1) return NULL; return fopen(path, mode); }
static size_t test_fwrite(const void *p, size_t size, size_t count, FILE *f)
{ return fwrite(p, size, fail_io == 2 && count ? count - 1 : count, f); }
static int test_fflush(FILE *f) { int rc = fflush(f); return fail_io == 3 ? -1 : rc; }
static int test_fsync(int fd) { return fail_io == 4 ? -1 : fsync(fd); }
static int test_fclose(FILE *f) { int rc = fclose(f); return fail_io == 5 ? -1 : rc; }
static int test_rename(const char *a, const char *b)
{ return fail_io == 6 ? -1 : rename(a, b); }
#define fopen test_fopen
#define fwrite test_fwrite
#define fflush test_fflush
#define fsync test_fsync
#define fclose test_fclose
#define rename test_rename
#define PMKID_CAPTURE_DIRECTORY "captures"
#include "../main/pmkid_capture.c"
#undef fopen
#undef fwrite
#undef fflush
#undef fsync
#undef fclose
#undef rename

static bool exclude_all;
static bool exclude(const uint8_t bssid[6])
{ assert(!memcmp(bssid, test_ap, 6)); return exclude_all; }
static void pump(void)
{ writer(NULL); assert(xSemaphoreTake(done, 0) == pdTRUE); }
static void end_attempt(const char *reason)
{
    pmkid_capture_attempt_end(reason);
    /* The deterministic host worker exits on an empty queue after the fence;
     * production FreeRTOS blocks there. Consume its synthetic completion. */
    assert(xSemaphoreTake(done, 0) == pdTRUE);
}
static unsigned files(void)
{
    DIR *dir = opendir("captures");
    if (!dir) return 0;
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        assert(pmkid_is_capture_filename(entry->d_name)); /* No orphan .part. */
        ++count;
    }
    closedir(dir);
    return count;
}

int main(void)
{
    uint8_t f[512], beacon[512];
    fail_allocation = true;
    assert(!pmkid_capture_start(exclude));
    fail_allocation = false;
    assert(pmkid_capture_start(exclude));
    assert(!pmkid_capture_start(exclude));
    size_t bn = make_beacon(beacon);
    pmkid_capture_observe(beacon, bn, 900, test_ap, NULL);
    size_t n = make_key(f, 0, 2);
    pmkid_capture_observe(f, n, 1000, test_ap, NULL);
    memset(f, 0xff, n); /* RX buffer may be reused immediately. */
    pump();
    assert(saved == 1 && memory->seen_count == 2 && files() == 1);
    assert(atomic_load(&frames_checked) == 1 && atomic_load(&pmkid_frames) == 1);
    /* Verify exact raw bytes and beacon association in the resulting PCAP. */
    DIR *dir = opendir("captures");
    struct dirent *entry;
    char path[320] = {0};
    while ((entry = readdir(dir))) {
        if (pmkid_is_capture_filename(entry->d_name)) {
            snprintf(path, sizeof(path), "captures/%s", entry->d_name); break;
        }
    }
    closedir(dir);
    FILE *pcap = fopen(path, "rb"); assert(pcap);
    pcap_global_header_t gh; pcap_record_header_t rh;
    assert(fread(&gh, 1, sizeof(gh), pcap) == sizeof(gh) && gh.network == 105);
    assert(fread(&rh, 1, sizeof(rh), pcap) == sizeof(rh) && rh.incl_len == bn);
    uint8_t raw[512]; assert(fread(raw, 1, bn, pcap) == bn && !memcmp(raw, beacon, bn));
    assert(fread(&rh, 1, sizeof(rh), pcap) == sizeof(rh) && rh.ts_usec == 1000);
    n = make_key(f, 0, 2);
    assert(fread(raw, 1, n, pcap) == n && !memcmp(raw, f, n));
    assert(fgetc(pcap) == EOF); fclose(pcap);
    pmkid_capture_observe(f, n, 1100, test_ap, "lab"); pump();
    assert(saved == 1); /* Same tuple, including multiple IDs, deduplicated. */
    f[4 + 5]++; /* A different client is a distinct tuple. */
    pmkid_capture_observe(f, n, 1200, test_ap, "lab"); pump();
    assert(saved == 2 && memory->seen_count == 4);
    uint8_t other[6] = {2, 9, 9, 9, 9, 9};
    pmkid_capture_observe(f, n, 1300, other, "lab"); pump();
    assert(saved == 2);
    exclude_all = true;
    pmkid_capture_observe(f, n, 1400, NULL, NULL); pump();
    assert(saved == 2);
    exclude_all = false;
    /* Both RX contention and full queues are nonblocking and counted. */
    xSemaphoreTake(mutex, 0);
    pmkid_capture_observe(f, n, 1400, NULL, NULL);
    xSemaphoreGive(mutex);
    for (unsigned i = 0; i < QUEUE_SIZE + 2; ++i) {
        pmkid_capture_observe(f, n, 1500, NULL, NULL);
    }
    assert(atomic_load(&drops) == 3); pump();
    pmkid_capture_stop(); assert(memory == NULL);
    pmkid_capture_stop();
    /* Stop drains pending frames; starting again resets dedup, not files. */
    assert(pmkid_capture_start(exclude));
    assert(atomic_load(&frames_checked) == 0 && atomic_load(&pmkid_frames) == 0);
    n = make_key(f, 0, 1);
    pmkid_capture_observe(f, n, 1600, NULL, NULL);
    pmkid_capture_stop(); assert(files() == 3);
    /* Every I/O failure leaves the tuple retryable and removes partial files. */
    for (unsigned failure = 1; failure <= 6; ++failure) {
        assert(pmkid_capture_start(exclude));
        fail_io = failure;
        pmkid_capture_observe(f, n, 1700, NULL, "lab"); pump();
        assert(saved == 0 && write_failures == 1 && memory->seen_count == 0);
        assert(files() == failure + 2);
        fail_io = 0;
        pmkid_capture_observe(f, n, 1800, NULL, "lab"); pump();
        assert(saved == 1 && memory->seen_count == 1 && files() == failure + 3);
        pmkid_capture_stop();
    }
    /* Bounded dedup storage never evicts already-committed tuples. */
    assert(pmkid_capture_start(exclude));
    memory->seen_count = SEEN_COUNT;
    pmkid_capture_observe(f, n, 1900, NULL, NULL); pump();
    assert(saved == 0 && capacity_drops == 1);
    pmkid_capture_stop();
    /* RSN-only capture is publishable without any handshake messages. */
    assert(pmkid_capture_start(exclude));
    n = make_assoc(f, 0x20, 2);
    pmkid_capture_observe(f, n, 2000, test_ap, NULL);
    assert(!strcmp(memory->captures[0].ssid, "lab"));
    pmkid_capture_stop(); assert(files() == 10);
    /* A full BSSID is part of the dedup key, even with the same MAC suffix. */
    assert(pmkid_capture_start(NULL));
    n = make_key(f, 0, 2);
    memcpy(f + 32 + 4 + 95 + 22 + 6, f + 32 + 4 + 95 + 6, 16);
    pmkid_capture_observe(f, n, 2100, NULL, NULL); pump();
    assert(saved == 1 && memory->seen_count == 1); /* Repeated ID within a frame. */
    f[11]++; f[17]++;
    pmkid_capture_observe(f, n, 2200, NULL, NULL); pump();
    assert(saved == 2 && memory->seen_count == 2);
    pmkid_capture_stop(); assert(files() == 12);
    /* Per-target attempt results wait for queued writes, not just reception. */
    assert(pmkid_capture_start(NULL));
    pmkid_capture_attempt_begin(test_ap, test_sta, 1);
    n = make_key(f, 0, 0);
    pmkid_capture_observe(f, n, 2300, NULL, NULL);
    end_attempt(NULL);
    assert(memory->attempt.checked == 1 && memory->attempt.received == 0);
    pmkid_capture_attempt_begin(test_ap, test_sta, 2);
    n = make_key(f, 0, 1);
    f[4] = 6; /* Another client's traffic does not determine this attempt. */
    pmkid_capture_observe(f, n, 2400, NULL, NULL);
    f[4] = test_sta[0];
    pmkid_capture_observe(f, n, 2500, NULL, NULL);
    end_attempt(NULL);
    assert(memory->attempt.checked == 1 && memory->attempt.received == 1);
    assert(memory->attempt.saved == 1);
    pmkid_capture_attempt_begin(test_ap, NULL, 1);
    pmkid_capture_observe(f, n, 2600, NULL, NULL);
    end_attempt(NULL);
    assert(memory->attempt.saved == 0 && memory->attempt.duplicates == 1);
    pmkid_capture_attempt_begin(test_ap, NULL, 2);
    f[n - 1]++; /* New PMKID; saving this frame fails. */
    fail_io = 1;
    pmkid_capture_observe(f, n, 2700, NULL, NULL);
    end_attempt(NULL);
    assert(memory->attempt.received == 1 && memory->attempt.write_failures == 1);
    fail_io = 0;
    pmkid_capture_attempt_begin(test_ap, NULL, 1);
    end_attempt("stopped");
    pmkid_capture_stop();
    pmkid_capture_attempt_begin(test_ap, NULL, 1); /* Explicitly unavailable. */
    return 0;
}
