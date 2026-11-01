#include "pmkid_capture.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "pcap_serializer.h"

#ifndef PMKID_CAPTURE_DIRECTORY
#define PMKID_CAPTURE_DIRECTORY "/sdcard/lab/handshakes"
#endif
#define FRAME_MAX 2500
#define QUEUE_SIZE 8
#define BEACON_COUNT 8
#define SEEN_COUNT 256

typedef struct {
    uint8_t frame[FRAME_MAX];
    size_t length;
    uint32_t timestamp;
    uint8_t bssid[6];
    char ssid[33];
} beacon_t;

typedef struct {
    uint8_t frame[FRAME_MAX];
    size_t length;
    uint32_t timestamp;
    pmkid_identity_t identity;
    beacon_t beacon;
    char ssid[33];
    unsigned attempt_id;
} capture_t;

typedef struct {
    unsigned id;
    uint8_t bssid[6], client[6];
    bool active, any_client;
    unsigned active_ordinal;
    unsigned checked, received, saved, duplicates, dropped, write_failures;
} attempt_t;

typedef struct {
    pmkid_identity_t identity;
    uint8_t pmkid[16];
} seen_t;

typedef struct {
    capture_t captures[QUEUE_SIZE];
    beacon_t beacons[BEACON_COUNT];
    seen_t seen[SEEN_COUNT];
    seen_t candidates[FRAME_MAX / 16];
    size_t seen_count;
    unsigned next_beacon;
    capture_t barrier;
    attempt_t attempt;
} capture_memory_t;

static capture_memory_t *memory;
static QueueHandle_t pending, available;
static SemaphoreHandle_t mutex, done, drained;
static bool accepting;
static bool (*is_excluded)(const uint8_t bssid[6]);
static atomic_uint drops;
static atomic_uint frames_checked;
static atomic_uint pmkid_frames;
static unsigned write_failures, saved, capacity_drops;

static void identify(const pmkid_identity_t *id, const uint8_t pmkid[16], void *ctx)
{
    (void)pmkid;
    *(pmkid_identity_t *)ctx = *id;
}

static bool was_saved(const pmkid_identity_t *id, const uint8_t pmkid[16])
{
    for (size_t i = 0; i < memory->seen_count; ++i) {
        const seen_t *s = &memory->seen[i];
        if (!memcmp(s->identity.bssid, id->bssid, 6) &&
            !memcmp(s->identity.client, id->client, 6) &&
            !memcmp(s->pmkid, pmkid, 16)) return true;
    }
    return false;
}

static void count_new(const pmkid_identity_t *id, const uint8_t pmkid[16], void *ctx)
{
    size_t *count = ctx;
    if (was_saved(id, pmkid)) return;
    for (size_t i = 0; i < *count; ++i) {
        if (!memcmp(memory->candidates[i].pmkid, pmkid, 16)) return;
    }
    if (*count == FRAME_MAX / 16) return; /* Impossible for a FRAME_MAX-byte frame. */
    seen_t *s = &memory->candidates[(*count)++];
    s->identity = *id;
    memcpy(s->pmkid, pmkid, 16);
}

static bool write_record(FILE *f, const uint8_t *frame, size_t length, uint32_t ts)
{
    pcap_record_header_t header = {
        .ts_sec = ts / 1000000U, .ts_usec = ts % 1000000U,
        .incl_len = (uint32_t)length, .orig_len = (uint32_t)length,
    };
    return fwrite(&header, 1, sizeof(header), f) == sizeof(header) &&
           fwrite(frame, 1, length, f) == length;
}

static bool save_capture(const capture_t *c)
{
    char safe[33];
    size_t i = 0;
    for (; i < 32 && c->ssid[i]; ++i) {
        unsigned char ch = (unsigned char)c->ssid[i];
        safe[i] = ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') ? ch : '_';
    }
    safe[i] = 0;
    if (!i) strcpy(safe, "hidden");
    if (mkdir(PMKID_CAPTURE_DIRECTORY, 0700) != 0) {
        struct stat st;
        if (stat(PMKID_CAPTURE_DIRECTORY, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    }
    char path[192], part[200];
    /* Microseconds and an existence check also avoid collisions after reboot. */
    unsigned long long stamp = (unsigned long long)esp_timer_get_time();
    for (unsigned attempt = 0;; ++attempt) {
        snprintf(path, sizeof(path), PMKID_CAPTURE_DIRECTORY "/%s_%02X%02X%02X_%llu_pmkid.pcap",
                 safe, c->identity.bssid[3], c->identity.bssid[4], c->identity.bssid[5],
                 stamp + attempt);
        snprintf(part, sizeof(part), "%s.part", path);
        if (access(path, F_OK) != 0 && access(part, F_OK) != 0) break;
        if (attempt == 1000) return false;
    }
    FILE *f = fopen(part, "wb");
    if (!f) return false;
    const pcap_global_header_t header = {
        .magic_number = 0xa1b2c3d4, .version_major = 2, .version_minor = 4,
        .thiszone = 0, .sigfigs = 0, .snaplen = 65535, .network = 105,
    };
    bool ok = fwrite(&header, 1, sizeof(header), f) == sizeof(header);
    if (ok && c->beacon.length) {
        ok = write_record(f, c->beacon.frame, c->beacon.length, c->beacon.timestamp);
    }
    if (ok) ok = write_record(f, c->frame, c->length, c->timestamp);
    if (fflush(f) != 0) ok = false;
    if (ok && fsync(fileno(f)) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (ok && rename(part, path) != 0) ok = false;
    if (!ok) {
        unlink(part);
        return false;
    }
    printf("PMKID saved: %s\n", path);
    if (!c->ssid[0] || !c->beacon.length) {
        printf("[HS-PMKID] missing_ssid=%u missing_beacon=%u path=%s\n",
               !c->ssid[0], !c->beacon.length, path);
    }
    return true;
}

static void writer(void *arg)
{
    (void)arg;
    capture_t *c;
    while (xQueueReceive(pending, &c, portMAX_DELAY) == pdTRUE && c) {
        if (c == &memory->barrier) {
            xSemaphoreGive(drained);
            continue;
        }
        attempt_t *a = c->attempt_id ? &memory->attempt : NULL;
        size_t new_count = 0;
        pmkid_parse_frame(c->frame, c->length, count_new, &new_count);
        if (new_count && new_count <= SEEN_COUNT - memory->seen_count) {
            printf("[HS-PMKID] detected bssid=%02X:%02X:%02X:%02X:%02X:%02X new_pmkids=%u\n",
                   c->identity.bssid[0], c->identity.bssid[1], c->identity.bssid[2],
                   c->identity.bssid[3], c->identity.bssid[4], c->identity.bssid[5],
                   (unsigned)new_count);
            if (save_capture(c)) {
                memcpy(memory->seen + memory->seen_count, memory->candidates,
                       new_count * sizeof(seen_t));
                memory->seen_count += new_count;
                ++saved;
                if (a) ++a->saved;
            } else {
                ++write_failures;
                if (a) ++a->write_failures;
                printf("[HS-PMKID] write_failed; retransmissions may retry\n");
            }
        } else if (new_count) {
            ++capacity_drops;
            if (a) ++a->dropped;
        } else if (a) {
            ++a->duplicates;
        }
        xQueueSend(available, &c, portMAX_DELAY);
    }
    xSemaphoreGive(done);
    vTaskDelete(NULL);
}

static void release_resources(void)
{
    if (pending) vQueueDelete(pending);
    if (available) vQueueDelete(available);
    if (mutex) vSemaphoreDelete(mutex);
    if (done) vSemaphoreDelete(done);
    if (drained) vSemaphoreDelete(drained);
    heap_caps_free(memory);
    memory = NULL;
    pending = available = NULL;
    mutex = done = drained = NULL;
}

bool pmkid_capture_start(bool (*excluded)(const uint8_t bssid[6]))
{
    if (memory) return false;
    memory = heap_caps_calloc(1, sizeof(*memory), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!memory) memory = heap_caps_calloc(1, sizeof(*memory), MALLOC_CAP_8BIT);
    if (!memory) return false;
    pending = xQueueCreate(QUEUE_SIZE, sizeof(capture_t *));
    available = xQueueCreate(QUEUE_SIZE, sizeof(capture_t *));
    mutex = xSemaphoreCreateMutex();
    done = xSemaphoreCreateBinary();
    drained = xSemaphoreCreateBinary();
    if (!pending || !available || !mutex || !done || !drained) {
        release_resources();
        return false;
    }
    for (unsigned i = 0; i < QUEUE_SIZE; ++i) {
        capture_t *c = &memory->captures[i];
        xQueueSend(available, &c, 0);
    }
    atomic_store(&drops, 0);
    atomic_store(&frames_checked, 0);
    atomic_store(&pmkid_frames, 0);
    saved = write_failures = capacity_drops = 0;
    is_excluded = excluded;
    accepting = true;
    if (xTaskCreate(writer, "pmkid_writer", 6144, NULL, 4, NULL) != pdPASS) {
        accepting = false;
        release_resources();
        return false;
    }
    return true;
}

void pmkid_capture_attempt_begin(const uint8_t bssid[6], const uint8_t *client,
                                 unsigned active_ordinal)
{
    if (!memory) {
        printf("[HS-PMKID] active_try=%u result=not_attempted reason=detector_unavailable\n",
               active_ordinal);
        return;
    }
    xSemaphoreTake(mutex, portMAX_DELAY);
    attempt_t *a = &memory->attempt;
    unsigned id = a->id + 1;
    memset(a, 0, sizeof(*a));
    a->id = id ? id : 1;
    memcpy(a->bssid, bssid, 6);
    a->any_client = client == NULL;
    if (client) memcpy(a->client, client, 6);
    a->active = true;
    a->active_ordinal = active_ordinal;
    xSemaphoreGive(mutex);
    printf("[HS-PMKID] attempt=%u active_try=%u/2 bssid=%02X:%02X:%02X:%02X:%02X:%02X stage=start method=sta_auth_assoc\n",
           a->id, active_ordinal, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

void pmkid_capture_attempt_end(const char *failure_reason)
{
    if (!memory) return;
    xSemaphoreTake(mutex, portMAX_DELAY);
    attempt_t *a = &memory->attempt;
    bool active = a->active;
    a->active = false;
    xSemaphoreGive(mutex);
    if (!active) return;
    /* All frames tagged with this attempt were enqueued under the same mutex
     * before active was cleared. This FIFO fence includes their SD outcomes. */
    capture_t *barrier = &memory->barrier;
    xQueueSend(pending, &barrier, portMAX_DELAY);
    xSemaphoreTake(drained, portMAX_DELAY);
    const char *result = "failed", *reason = "no_pmkid_received";
    if (a->saved || a->duplicates) {
        result = "success";
        reason = a->saved ? "pmkid_saved" : "already_saved";
    } else if (a->write_failures) {
        reason = "write_failed";
    } else if (a->dropped) {
        reason = "capture_dropped";
    } else if (failure_reason) {
        reason = failure_reason;
    }
    printf("[HS-PMKID] attempt=%u active_try=%u/2 bssid=%02X:%02X:%02X:%02X:%02X:%02X result=%s reason=%s frames_checked=%u pmkid_frames=%u saved=%u already_saved=%u drops=%u write_failures=%u\n",
           a->id, a->active_ordinal, a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5],
           result, reason, a->checked, a->received, a->saved, a->duplicates,
           a->dropped, a->write_failures);
}

void pmkid_capture_stop(void)
{
    if (!memory) return;
    pmkid_capture_attempt_end("stopped");
    xSemaphoreTake(mutex, portMAX_DELAY);
    accepting = false;
    xSemaphoreGive(mutex);
    capture_t *end = NULL;
    xQueueSend(pending, &end, portMAX_DELAY);
    xSemaphoreTake(done, portMAX_DELAY);
    printf("[HS-PMKID] stopped frames_checked=%u pmkid_frames=%u saved=%u queue_or_rx_drops=%u capacity_drops=%u write_failures=%u\n",
           atomic_load(&frames_checked), atomic_load(&pmkid_frames),
           saved, atomic_load(&drops), capacity_drops, write_failures);
    release_resources();
}

static bool attempt_matches(const uint8_t *f, size_t n)
{
    const attempt_t *a = &memory->attempt;
    if (!a->active || n < 24) return false;
    const uint8_t *bssid, *client;
    unsigned kind = f[0] & 0xfc;
    if ((f[0] & 0x0c) == 0x08 && (f[1] & 3) == 1) {
        bssid = f + 4; client = f + 10;
    } else if ((f[0] & 0x0c) == 0x08 && (f[1] & 3) == 2) {
        bssid = f + 10; client = f + 4;
    } else if (kind == 0 || kind == 0x10 || kind == 0x20 || kind == 0x30) {
        bssid = f + 16; client = f + ((kind == 0 || kind == 0x20) ? 10 : 4);
    } else return false;
    return !memcmp(a->bssid, bssid, 6) &&
           (a->any_client || !memcmp(a->client, client, 6));
}

static void copy_tagged_ssid(char ssid[33], const uint8_t *f, size_t n, size_t offset)
{
    if (offset > n) return;
    for (size_t i = offset; n - i >= 2;) {
        size_t length = f[i + 1];
        if (length > n - i - 2) break;
        if (f[i] == 0 && length <= 32) {
            if (length && f[i + 2]) {
                memset(ssid, 0, 33);
                memcpy(ssid, f + i + 2, length);
            }
            break;
        }
        i += 2 + length;
    }
}

void pmkid_capture_observe(const uint8_t *f, size_t n, uint32_t ts,
                           const uint8_t *target_bssid, const char *ssid)
{
    if (!mutex || !f || n < 24) return;
    if (n > FRAME_MAX || xSemaphoreTake(mutex, 0) != pdTRUE) {
        atomic_fetch_add(&drops, 1);
        return;
    }
    if (!accepting) goto out;
    unsigned kind = f[0] & 0xfc;
    if ((kind == 0x80 || kind == 0x50) && n >= 36 &&
        !(f[1] & 0x43) && !memcmp(f + 10, f + 16, 6)) {
        const uint8_t *bssid = f + 16;
        if ((target_bssid && memcmp(bssid, target_bssid, 6)) ||
            (is_excluded && is_excluded(bssid))) goto out;
        unsigned index = BEACON_COUNT;
        for (unsigned i = 0; i < BEACON_COUNT; ++i) {
            if (memory->beacons[i].length && !memcmp(memory->beacons[i].bssid, bssid, 6)) {
                index = i;
                break;
            }
        }
        if (index == BEACON_COUNT) index = memory->next_beacon++ % BEACON_COUNT;
        beacon_t *b = &memory->beacons[index];
        b->length = n;
        b->timestamp = ts;
        memcpy(b->bssid, bssid, 6);
        memcpy(b->frame, f, n);
        memset(b->ssid, 0, sizeof(b->ssid));
        copy_tagged_ssid(b->ssid, f, n, 36);
        goto out;
    }
    pmkid_identity_t id;
    bool in_attempt = attempt_matches(f, n);
    if (in_attempt) ++memory->attempt.checked;
    atomic_fetch_add(&frames_checked, 1);
    if (!pmkid_parse_frame(f, n, identify, &id)) goto out;
    if ((target_bssid && memcmp(id.bssid, target_bssid, 6)) ||
        (is_excluded && is_excluded(id.bssid))) goto out;
    atomic_fetch_add(&pmkid_frames, 1);
    if (in_attempt) ++memory->attempt.received;
    capture_t *c;
    if (xQueueReceive(available, &c, 0) != pdTRUE) {
        atomic_fetch_add(&drops, 1);
        if (in_attempt) ++memory->attempt.dropped;
        goto out;
    }
    c->identity = id;
    c->attempt_id = in_attempt ? memory->attempt.id : 0;
    c->length = n;
    c->timestamp = ts;
    memcpy(c->frame, f, n);
    c->beacon.length = 0;
    memset(c->ssid, 0, sizeof(c->ssid));
    if (ssid) strncpy(c->ssid, ssid, 32);
    if (kind == 0x00 || kind == 0x20) {
        copy_tagged_ssid(c->ssid, f, n, kind == 0 ? 28 : 34);
    }
    for (unsigned i = 0; i < BEACON_COUNT; ++i) {
        const beacon_t *b = &memory->beacons[i];
        if (b->length && !memcmp(b->bssid, id.bssid, 6)) {
            c->beacon = *b;
            if (b->ssid[0]) memcpy(c->ssid, b->ssid, sizeof(c->ssid));
            break;
        }
    }
    /* At most QUEUE_SIZE-1 other slots can be pending while we own this one. */
    if (xQueueSend(pending, &c, 0) != pdTRUE) {
        atomic_fetch_add(&drops, 1);
        if (in_attempt) ++memory->attempt.dropped;
        xQueueSend(available, &c, 0);
    }
out:
    xSemaphoreGive(mutex);
}
