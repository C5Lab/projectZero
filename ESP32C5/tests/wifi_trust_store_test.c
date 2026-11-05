#include "wifi_trust_store.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool exists;
    uint8_t bytes[WIFI_TRUST_FILE_MAX + 32U];
    size_t length;
} fake_file_t;
typedef struct fake_context fake_context_t;
typedef struct {
    fake_context_t *context;
    fake_file_t *file;
    size_t offset;
    bool writable;
} fake_handle_t;
struct fake_context {
    fake_file_t target, stage, backup;
    fake_handle_t handle;
    bool locked, enter_ok, handle_live, fail_open, open_error_with_handle;
    bool fail_read;
    unsigned fail_write_call, short_write_call;
    bool fail_flush, fail_sync, fail_close, fail_remove, fail_rename;
    bool fail_rollback, volume_sync_ok;
    fs_publish_result_t publish_result;
    fs_recovery_result_t recovery_result;
    unsigned enter_calls, leave_calls, open_calls, read_calls, write_calls;
    unsigned flush_calls, sync_calls, close_calls, remove_calls, rename_calls;
    unsigned publish_calls, recovery_calls, volume_sync_calls;
    char order[256];
    size_t order_length;
};
static fake_context_t fake;

static void step(fake_context_t *c, char value)
{
    if (c->order_length + 1U >= sizeof(c->order)) return;
    c->order[c->order_length++] = value;
    c->order[c->order_length] = '\0';
}
static void reset_fake(void)
{
    memset(&fake, 0, sizeof(fake));
    fake.enter_ok = true;
    fake.volume_sync_ok = true;
    fake.publish_result = FS_PUBLISH_OK;
    fake.recovery_result = FS_RECOVERY_NONE;
}
static fake_file_t *path_file(fake_context_t *c, const char *path)
{
    if (strcmp(path, WIFI_TRUST_STORE_PATH) == 0) return &c->target;
    if (strcmp(path, WIFI_TRUST_STAGE_PATH) == 0) return &c->stage;
    if (strcmp(path, WIFI_TRUST_BACKUP_PATH) == 0) return &c->backup;
    return NULL;
}
static bool fake_enter(void *opaque)
{
    fake_context_t *c = opaque;
    ++c->enter_calls;
    if (!c->enter_ok) return false;
    assert(!c->locked);
    c->locked = true;
    step(c, 'L');
    return true;
}
static void fake_leave(void *opaque)
{
    fake_context_t *c = opaque;
    assert(c->locked && !c->handle_live);
    c->locked = false;
    ++c->leave_calls;
    step(c, 'U');
}
static wifi_trust_io_result_t fake_open(void *opaque, const char *path,
                                        bool truncate, void **handle)
{
    fake_context_t *c = opaque;
    assert(c->locked && !c->handle_live);
    ++c->open_calls;
    step(c, 'O');
    fake_file_t *file = path_file(c, path);
    if (file == NULL) return WIFI_TRUST_IO_ERROR;
    if (c->fail_open && !c->open_error_with_handle)
        return WIFI_TRUST_IO_ERROR;
    if (!truncate && !file->exists) return WIFI_TRUST_IO_MISSING;
    if (truncate) {
        file->exists = true;
        file->length = 0U;
        memset(file->bytes, 0, sizeof(file->bytes));
    }
    c->handle.context = c;
    c->handle.file = file;
    c->handle.offset = 0U;
    c->handle.writable = truncate;
    c->handle_live = true;
    *handle = &c->handle;
    if (c->fail_open) return WIFI_TRUST_IO_ERROR;
    return WIFI_TRUST_IO_OK;
}
static wifi_trust_io_result_t fake_read(void *opaque, uint8_t *out,
                                        size_t capacity, size_t *actual)
{
    fake_handle_t *h = opaque;
    fake_context_t *c = h->context;
    assert(c->locked && c->handle_live && !h->writable);
    ++c->read_calls;
    if (c->fail_read) return WIFI_TRUST_IO_ERROR;
    if (h->offset == h->file->length) {
        *actual = 0U;
        return WIFI_TRUST_IO_EOF;
    }
    size_t available = h->file->length - h->offset;
    size_t take = available < capacity ? available : capacity;
    if (take > 73U) take = 73U;
    memcpy(out, h->file->bytes + h->offset, take);
    h->offset += take;
    *actual = take;
    return WIFI_TRUST_IO_OK;
}
static wifi_trust_io_result_t fake_write(void *opaque, const uint8_t *bytes,
                                         size_t length, size_t *actual)
{
    fake_handle_t *h = opaque;
    fake_context_t *c = h->context;
    assert(c->locked && c->handle_live && h->writable);
    ++c->write_calls;
    step(c, 'W');
    if (c->fail_write_call == c->write_calls) return WIFI_TRUST_IO_ERROR;
    size_t take = c->short_write_call == c->write_calls && length != 0U ?
                  length - 1U : length;
    assert(h->file->length + take <= sizeof(h->file->bytes));
    memcpy(h->file->bytes + h->file->length, bytes, take);
    h->file->length += take;
    *actual = take;
    return WIFI_TRUST_IO_OK;
}
static wifi_trust_io_result_t fake_flush(void *opaque)
{
    fake_handle_t *h = opaque;
    ++h->context->flush_calls;
    step(h->context, 'F');
    return h->context->fail_flush ? WIFI_TRUST_IO_ERROR : WIFI_TRUST_IO_OK;
}
static wifi_trust_io_result_t fake_sync(void *opaque)
{
    fake_handle_t *h = opaque;
    ++h->context->sync_calls;
    step(h->context, 'S');
    return h->context->fail_sync ? WIFI_TRUST_IO_ERROR : WIFI_TRUST_IO_OK;
}
static wifi_trust_io_result_t fake_close(void *opaque)
{
    fake_handle_t *h = opaque;
    fake_context_t *c = h->context;
    assert(c->handle_live);
    c->handle_live = false;
    ++c->close_calls;
    step(c, 'C');
    return c->fail_close ? WIFI_TRUST_IO_ERROR : WIFI_TRUST_IO_OK;
}
static wifi_trust_path_state_t fake_path_state(void *opaque, const char *path)
{
    fake_file_t *file = path_file(opaque, path);
    return file != NULL && file->exists ? WIFI_TRUST_PATH_FILE :
                                         WIFI_TRUST_PATH_MISSING;
}
static bool move_file(fake_context_t *c, const char *from, const char *to)
{
    fake_file_t *source = path_file(c, from);
    fake_file_t *destination = path_file(c, to);
    if (source == NULL || destination == NULL || !source->exists ||
        destination->exists) return false;
    *destination = *source;
    source->exists = false;
    source->length = 0U;
    return true;
}
static bool fake_rename(void *opaque, const char *from, const char *to)
{
    fake_context_t *c = opaque;
    ++c->rename_calls;
    step(c, 'N');
    if (c->fail_rename) return false;
    if (c->fail_rollback && strcmp(from, WIFI_TRUST_BACKUP_PATH) == 0)
        return false;
    return move_file(c, from, to);
}
static bool fake_remove(void *opaque, const char *path)
{
    fake_context_t *c = opaque;
    ++c->remove_calls;
    step(c, 'D');
    if (c->fail_remove) return false;
    fake_file_t *file = path_file(c, path);
    if (file == NULL || !file->exists) return false;
    file->exists = false;
    file->length = 0U;
    return true;
}
static bool fake_sync_volume(void *opaque)
{
    fake_context_t *c = opaque;
    ++c->volume_sync_calls;
    step(c, 'V');
    return c->volume_sync_ok;
}
static fs_publish_result_t fake_publish(void *opaque, const char *stage,
                                        const char *target,
                                        const char *backup, bool replace)
{
    fake_context_t *c = opaque;
    assert(strcmp(stage, WIFI_TRUST_STAGE_PATH) == 0);
    assert(strcmp(target, WIFI_TRUST_STORE_PATH) == 0);
    assert(strcmp(backup, WIFI_TRUST_BACKUP_PATH) == 0 && replace);
    ++c->publish_calls;
    step(c, 'P');
    if (c->publish_result == FS_PUBLISH_OK ||
        c->publish_result == FS_PUBLISH_BACKUP_LEFT) {
        if (c->target.exists) {
            assert(!c->backup.exists);
            c->backup = c->target;
        }
        c->target = c->stage;
        c->stage.exists = false;
        c->stage.length = 0U;
        if (c->publish_result == FS_PUBLISH_OK) {
            c->backup.exists = false;
            c->backup.length = 0U;
        }
    }
    return c->publish_result;
}
static fs_recovery_result_t fake_recover(void *opaque, const char *stage,
                                         const char *target,
                                         const char *backup)
{
    fake_context_t *c = opaque;
    assert(strcmp(stage, WIFI_TRUST_STAGE_PATH) == 0);
    assert(strcmp(target, WIFI_TRUST_STORE_PATH) == 0);
    assert(strcmp(backup, WIFI_TRUST_BACKUP_PATH) == 0);
    ++c->recovery_calls;
    step(c, 'R');
    return c->recovery_result;
}
static wifi_trust_store_ops_t fake_ops(void)
{
    const wifi_trust_store_ops_t ops = {
        .context = &fake, .enter = fake_enter, .leave = fake_leave,
        .open = fake_open, .read = fake_read, .write = fake_write,
        .flush = fake_flush, .sync = fake_sync, .close = fake_close,
        .path_state = fake_path_state, .rename_path = fake_rename,
        .remove_path = fake_remove, .sync_volume = fake_sync_volume,
        .publish_staged = fake_publish, .recover_staged = fake_recover,
    };
    return ops;
}

static wifi_trust_store_meta_t meta_fixture(bool unix_known)
{
    wifi_trust_store_meta_t meta = {0};
    for (size_t i = 0; i < sizeof(meta.boot_id); ++i)
        meta.boot_id[i] = (uint8_t)i;
    meta.created_unix_known = unix_known;
    meta.created_unix = unix_known ? UINT64_C(1793650000) : 0U;
    meta.created_monotonic_us = UINT64_C(987654321);
    return meta;
}
static void fill_selector(uint8_t out[4], uint8_t type)
{
    out[0] = 0x00; out[1] = 0x0f; out[2] = 0xac; out[3] = type;
}
static wifi_trust_profile_t profile_fixture(uint8_t tail)
{
    wifi_trust_profile_t p;
    memset(&p, 0, sizeof(p));
    const uint8_t prefix[5] = {0x02, 0x11, 0x22, 0x33, 0x44};
    memcpy(p.bssid, prefix, sizeof(prefix));
    p.bssid[5] = tail;
    p.ssid_status = SX_VALID;
    p.ssid_len = 4U;
    p.ssid[0] = 'A'; p.ssid[1] = 0x00; p.ssid[2] = 0xff; p.ssid[3] = tail;
    p.source = (tail & 1U) ? SX_PROBE_RESP : SX_BEACON;
    p.privacy = 1;
    p.rsn.status = SX_VALID;
    p.rsn.group_present = true;
    fill_selector(p.rsn.group, 4U);
    p.rsn.pairwise_known = true;
    p.rsn.pairwise_count = 2U;
    fill_selector(p.rsn.pairwise[0], 4U);
    fill_selector(p.rsn.pairwise[1], 8U);
    p.rsn.akm_known = true;
    p.rsn.akm_count = 2U;
    fill_selector(p.rsn.akm[0], 8U);
    fill_selector(p.rsn.akm[1], 2U);
    p.rsn.capabilities_present = true;
    p.rsn.pmf_capable = p.rsn.pmf_required = true;
    p.rsn.management_present = true;
    fill_selector(p.rsn.management, 6U);
    p.wpa.status = SX_ABSENT;
    p.rsnxe.status = SX_VALID;
    p.rsnxe.present = true;
    p.rsnxe.len = 2U;
    p.rsnxe.bytes[0] = 0x21U; p.rsnxe.bytes[1] = tail;
    p.wps.status = SX_VALID;
    p.wps.present = true;
    p.wps.state = 2; p.wps.config_methods = 0x80;
    p.wps.setup_locked = 0; p.wps.selected_registrar = 1;
    p.wps.manufacturer.present = true;
    p.wps.manufacturer.len = 3U;
    memcpy(p.wps.manufacturer.bytes, "LAB", 3U);
    p.wps.model_name.present = true;
    p.wps.model_name.len = 2U;
    p.wps.model_name.bytes[0] = 0x00U; p.wps.model_name.bytes[1] = tail;
    p.country.status = SX_VALID;
    p.country.code[0] = 'P'; p.country.code[1] = 'L'; p.country.code[2] = ' ';
    p.channel = 6U;
    p.observed_us = UINT64_C(123456789) + tail;
    assert(wifi_trust_profile_valid(&p));
    return p;
}
static void file_from_text(fake_file_t *file, const char *text)
{
    size_t length = strlen(text);
    assert(length <= sizeof(file->bytes));
    memset(file, 0, sizeof(*file));
    file->exists = true;
    memcpy(file->bytes, text, length);
    file->length = length;
}
static void assert_profile_equal(const wifi_trust_profile_t *a,
                                 const wifi_trust_profile_t *b)
{
    assert(memcmp(a, b, sizeof(*a)) == 0);
}

static uint32_t independent_crc32(const uint8_t *bytes, size_t length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8U; ++bit)
            crc = (crc & 1U) ? (crc >> 1U) ^ UINT32_C(0xedb88320) :
                              crc >> 1U;
    }
    return crc ^ UINT32_MAX;
}

static wifi_trust_store_result_t load_current(size_t capacity);

static void test_codec_and_strict_schema(void)
{
    wifi_trust_profile_t profile = profile_fixture(0x55U);
    char line[WIFI_TRUST_JSON_LINE_MAX];
    int length = wifi_trust_store_format_ap_line(line, sizeof(line), &profile);
    assert(length > 0 && (size_t)length == strlen(line));
    line[length] = '\n';
    assert(independent_crc32((const uint8_t *)line, (size_t)length + 1U) ==
           UINT32_C(0xD8216EF8));
    line[length] = '\0';
    assert(strstr(line, "\"ssid_hex\":\"4100FF55\"") != NULL);
    assert(strstr(line, "\"rsn_pairwise\":[\"000FAC04\",\"000FAC08\"]") != NULL);
    assert(strstr(line, "\"wpa_pairwise\":null") != NULL);
    assert(strstr(line, "\"rsn_pmf_required\":true") != NULL);
    assert(strstr(line, "\"wps_model_name_hex\":\"0055\"") != NULL);
    wifi_trust_profile_t parsed;
    memset(&parsed, 0xa5, sizeof(parsed));
    assert(wifi_trust_store_parse_ap_line(line, strlen(line), &parsed));
    assert_profile_equal(&profile, &parsed);
    for (size_t capacity = 0; capacity <= (size_t)length; ++capacity) {
        char guarded[WIFI_TRUST_JSON_LINE_MAX];
        memset(guarded, 0xa5, sizeof(guarded));
        assert(wifi_trust_store_format_ap_line(guarded, capacity, &profile) == -1);
        for (size_t i = 0; i < sizeof(guarded); ++i)
            assert((unsigned char)guarded[i] == 0xa5U);
    }
    assert(wifi_trust_store_format_ap_line(line, (size_t)length + 1U,
                                            &profile) == length);
    char corrupt[WIFI_TRUST_JSON_LINE_MAX];
    memcpy(corrupt, line, (size_t)length + 1U);
    char *bssid = strstr(corrupt, "021122334455");
    assert(bssid != NULL);
    bssid[0] = 'A';
    memset(&parsed, 0xa5, sizeof(parsed));
    assert(!wifi_trust_store_parse_ap_line(corrupt, strlen(corrupt), &parsed));
    for (size_t i = 0; i < sizeof(parsed); ++i)
        assert(((const unsigned char *)&parsed)[i] == 0xa5U);
    assert(!wifi_trust_store_parse_ap_line(line, (size_t)length + 1U, &parsed));

    const struct {
        const char *from;
        const char *to;
    } malformed[] = {
        {"\"ssid_hex\":\"4100FF55\"", "\"ssid_hex\":\"4100ff55\""},
        {"\"ssid_status\":\"valid\"", "\"ssid_status\":\"bogus\""},
        {"\"source\":\"probe_response\"", "\"source\":\"invalid_source\""},
        {"\"privacy\":1", "\"privacy\":2"},
        {"\"rsn_pmf_capable\":true", "\"rsn_pmf_capable\":null"},
        {"\"wps_status\":\"valid\"", "\"wps_status\":\"bogus\""},
        {"\"channel\":6", "\"channel\":-"},
        {"\"observed_us\":123456874", "\"observed_us\":-23456874"},
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        memcpy(corrupt, line, (size_t)length + 1U);
        char *at = strstr(corrupt, malformed[i].from);
        assert(at != NULL);
        size_t from_length = strlen(malformed[i].from);
        size_t to_length = strlen(malformed[i].to);
        assert(from_length == to_length);
        memcpy(at, malformed[i].to, to_length);
        memset(&parsed, 0xa5, sizeof(parsed));
        assert(!wifi_trust_store_parse_ap_line(corrupt, (size_t)length,
                                                &parsed));
        for (size_t j = 0; j < sizeof(parsed); ++j)
            assert(((const unsigned char *)&parsed)[j] == 0xa5U);
    }

    memcpy(corrupt, line, (size_t)length + 1U);
    char *ssid_key = strstr(corrupt, "\"ssid_status\":");
    assert(ssid_key != NULL);
    ssid_key[1] = 'X';
    assert(!wifi_trust_store_parse_ap_line(corrupt, (size_t)length, &parsed));

    wifi_trust_profile_t worst = profile_fixture(0x66U);
    worst.ssid_len = 32U;
    memset(worst.ssid, 0xff, sizeof(worst.ssid));
    worst.rsn.pairwise_count = worst.rsn.akm_count = SX_SELECTORS;
    worst.wpa.status = SX_VALID;
    worst.wpa.group_present = worst.wpa.management_present = true;
    fill_selector(worst.wpa.group, 2U);
    fill_selector(worst.wpa.management, 6U);
    worst.wpa.pairwise_known = worst.wpa.akm_known = true;
    worst.wpa.pairwise_count = worst.wpa.akm_count = SX_SELECTORS;
    for (size_t i = 0; i < SX_SELECTORS; ++i) {
        fill_selector(worst.rsn.pairwise[i], (uint8_t)i);
        fill_selector(worst.rsn.akm[i], (uint8_t)(i + 8U));
        fill_selector(worst.wpa.pairwise[i], (uint8_t)(i + 16U));
        fill_selector(worst.wpa.akm[i], (uint8_t)(i + 24U));
    }
    worst.rsnxe.len = SX_RSNXE_BYTES;
    memset(worst.rsnxe.bytes, 0xee, sizeof(worst.rsnxe.bytes));
    sx_text_t *texts[] = {&worst.wps.manufacturer, &worst.wps.model_name,
        &worst.wps.model_number, &worst.wps.device_name};
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); ++i) {
        texts[i]->present = true;
        texts[i]->truncated = false;
        texts[i]->len = SX_TEXT_BYTES;
        memset(texts[i]->bytes, (int)(0xa0U + i), SX_TEXT_BYTES);
    }
    assert(wifi_trust_profile_valid(&worst));
    length = wifi_trust_store_format_ap_line(line, sizeof(line), &worst);
    assert(length > 0 && length < (int)WIFI_TRUST_JSON_LINE_MAX - 1);
    assert(wifi_trust_store_parse_ap_line(line, (size_t)length, &parsed));
    assert_profile_equal(&worst, &parsed);
}

static void assert_lock_balanced(void)
{
    assert(!fake.locked && !fake.handle_live);
    assert(fake.enter_calls == fake.leave_calls);
}
static void assert_target_matches_fixture(const char *path)
{
    FILE *fixture = fopen(path, "rb");
    assert(fixture != NULL);
    uint8_t chunk[256];
    size_t offset = 0U;
    for (;;) {
        size_t length = fread(chunk, 1U, sizeof(chunk), fixture);
        assert(offset + length <= fake.target.length);
        assert(memcmp(fake.target.bytes + offset, chunk, length) == 0);
        offset += length;
        if (length != sizeof(chunk)) {
            assert(feof(fixture) && !ferror(fixture));
            break;
        }
    }
    assert(fclose(fixture) == 0);
    assert(offset == fake.target.length);
}
static void test_publish_load_roundtrip_and_sorting(void)
{
    reset_fake();
    wifi_trust_store_ops_t ops = fake_ops();
    wifi_trust_profile_t input[2] = {
        profile_fixture(0x20U), profile_fixture(0x10U)};
    wifi_trust_profile_t unchanged[2];
    memcpy(unchanged, input, sizeof(input));
    wifi_trust_store_meta_t meta = meta_fixture(true);
    assert(wifi_trust_store_publish(input, 2U, &meta, &ops) ==
           WIFI_TRUST_STORE_OK);
    assert_profile_equal(&input[0], &unchanged[0]);
    assert_profile_equal(&input[1], &unchanged[1]);
    assert(fake.target.exists && !fake.stage.exists && !fake.backup.exists);
    fake.target.bytes[fake.target.length] = '\0';
    const char *header_end = strchr((const char *)fake.target.bytes, '\n');
    assert(header_end != NULL);
    const char *ap_end = strchr(header_end + 1, '\n');
    assert(ap_end != NULL);
    const char *second_ap_end = strchr(ap_end + 1, '\n');
    assert(second_ap_end != NULL);
    uint32_t expected_crc = independent_crc32(
        (const uint8_t *)(header_end + 1),
        (size_t)(second_ap_end - (header_end + 1) + 1));
    char crc_token[32];
    snprintf(crc_token, sizeof(crc_token), "\"crc32\":\"%08X\"",
             (unsigned)expected_crc);
    assert(strstr(second_ap_end + 1, crc_token) != NULL);
    assert(expected_crc != independent_crc32((const uint8_t *)(header_end + 1),
        (size_t)(second_ap_end - (header_end + 1))));
    const char *flush = strchr(fake.order, 'F'), *sync = strchr(fake.order, 'S');
    const char *close = strchr(fake.order, 'C'), *publish = strchr(fake.order, 'P');
    assert(flush && sync && close && publish &&
           flush < sync && sync < close && close < publish);
    assert_lock_balanced();
    wifi_trust_profile_t loaded[2];
    memset(loaded, 0xa5, sizeof(loaded));
    size_t count = 99U;
    wifi_trust_store_meta_t loaded_meta;
    wifi_trust_recovery_action_t recovery = WIFI_TRUST_RECOVERY_KEPT_TARGET;
    assert(wifi_trust_store_load(WIFI_TRUST_STORE_PATH, loaded, 2U, &count,
        &loaded_meta, &recovery, &ops) == WIFI_TRUST_STORE_OK);
    assert(count == 2U && recovery == WIFI_TRUST_RECOVERY_NONE);
    assert(memcmp(&meta, &loaded_meta, sizeof(meta)) == 0);
    assert_profile_equal(&loaded[0], &input[1]);
    assert_profile_equal(&loaded[1], &input[0]);
    assert_lock_balanced();

    fake.target.bytes[fake.target.length] = '\0';
    char *second_bssid = strstr((char *)fake.target.bytes,
                                "\"bssid\":\"021122334420\"");
    assert(second_bssid != NULL);
    char *tail = strstr(second_bssid, "4420");
    assert(tail != NULL);
    tail[2] = '1';
    tail[3] = '0';
    assert(load_current(2U) == WIFI_TRUST_STORE_FORMAT);
}

static const char zero_fixture[] =
    "{\"v\":1,\"type\":\"header\",\"count\":0,\"boot\":\"0001020304050607\","
    "\"created_unix\":null,\"created_us\":987654321}\n"
    "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000000\"}\n";
static void test_zero_128_capacity_and_canonical_bytes(void)
{
    reset_fake();
    wifi_trust_store_ops_t ops = fake_ops();
    wifi_trust_store_meta_t meta = meta_fixture(false);
    assert(wifi_trust_store_publish(NULL, 0U, &meta, &ops) ==
           WIFI_TRUST_STORE_OK);
    assert(fake.target.length == strlen(zero_fixture));
    assert(memcmp(fake.target.bytes, zero_fixture, strlen(zero_fixture)) == 0);
    assert_target_matches_fixture(
        "tests/fixtures/wifi_trust_baseline_v1.jsonl");
    reset_fake();
    ops = fake_ops();
    wifi_trust_profile_t one = profile_fixture(0x55U);
    meta = meta_fixture(true);
    assert(wifi_trust_store_publish(&one, 1U, &meta, &ops) ==
           WIFI_TRUST_STORE_OK);
    assert_target_matches_fixture(
        "tests/fixtures/wifi_trust_baseline_v1_one_profile.jsonl");
    reset_fake();
    ops = fake_ops();
    static wifi_trust_profile_t profiles[WIFI_TRUST_MAX_PROFILES];
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i)
        profiles[i] = profile_fixture((uint8_t)(i + 1U));
    assert(wifi_trust_store_publish(profiles, WIFI_TRUST_MAX_PROFILES,
                                    &meta, &ops) == WIFI_TRUST_STORE_OK);
    assert(fake.target.length < WIFI_TRUST_FILE_MAX);
    static wifi_trust_profile_t loaded[WIFI_TRUST_MAX_PROFILES];
    size_t count;
    wifi_trust_store_meta_t loaded_meta;
    wifi_trust_recovery_action_t recovery;
    assert(wifi_trust_store_load(WIFI_TRUST_STORE_PATH, loaded,
        WIFI_TRUST_MAX_PROFILES, &count, &loaded_meta, &recovery, &ops) ==
        WIFI_TRUST_STORE_OK);
    assert(count == WIFI_TRUST_MAX_PROFILES);
    wifi_trust_profile_t duplicate[2] = {
        profile_fixture(4U), profile_fixture(4U)};
    assert(wifi_trust_store_publish(duplicate, 2U, &meta, &ops) ==
           WIFI_TRUST_STORE_FORMAT);
    assert(wifi_trust_store_publish(profiles, WIFI_TRUST_MAX_PROFILES + 1U,
                                    &meta, &ops) == WIFI_TRUST_STORE_CAPACITY);
}

static void assert_cleared(const wifi_trust_profile_t *profiles,
                           size_t profile_count,
                           const wifi_trust_store_meta_t *meta, size_t count)
{
    assert(count == 0U);
    for (size_t i = 0; i < profile_count * sizeof(*profiles); ++i)
        assert(((const uint8_t *)profiles)[i] == 0U);
    for (size_t i = 0; i < sizeof(*meta); ++i)
        assert(((const uint8_t *)meta)[i] == 0U);
}
static wifi_trust_store_result_t load_current(size_t capacity)
{
    wifi_trust_store_ops_t ops = fake_ops();
    wifi_trust_profile_t profiles[2];
    memset(profiles, 0xa5, sizeof(profiles));
    wifi_trust_store_meta_t meta;
    memset(&meta, 0xa5, sizeof(meta));
    size_t count = 88U;
    wifi_trust_recovery_action_t recovery;
    wifi_trust_store_result_t result = wifi_trust_store_load(
        WIFI_TRUST_STORE_PATH, profiles, capacity, &count, &meta, &recovery,
        &ops);
    if (result != WIFI_TRUST_STORE_OK)
        assert_cleared(profiles, capacity, &meta, count);
    return result;
}
static void test_load_rejects_noncanonical_paths_before_side_effects(void)
{
    const char *paths[] = {WIFI_TRUST_STAGE_PATH, WIFI_TRUST_BACKUP_PATH};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        reset_fake();
        wifi_trust_store_ops_t ops = fake_ops();
        wifi_trust_profile_t profiles[2];
        memset(profiles, 0xa5, sizeof(profiles));
        wifi_trust_store_meta_t meta;
        memset(&meta, 0xa5, sizeof(meta));
        size_t count = 88U;
        wifi_trust_recovery_action_t recovery =
            WIFI_TRUST_RECOVERY_KEPT_TARGET;
        assert(wifi_trust_store_load(paths[i], profiles, 2U, &count, &meta,
            &recovery, &ops) == WIFI_TRUST_STORE_IO);
        assert_cleared(profiles, 2U, &meta, count);
        assert(recovery == WIFI_TRUST_RECOVERY_NONE);
        assert(fake.enter_calls == 0U && fake.recovery_calls == 0U &&
               fake.open_calls == 0U);
    }
}
static void test_load_rejections_and_recovery(void)
{
    reset_fake();
    assert(load_current(2U) == WIFI_TRUST_STORE_NOT_FOUND);
    reset_fake();
    fake.recovery_result = FS_RECOVERY_FAILED;
    assert(load_current(2U) == WIFI_TRUST_STORE_RECOVERY);
    assert(fake.open_calls == 0U);
    reset_fake();
    file_from_text(&fake.target, zero_fixture);
    fake.recovery_result = FS_RECOVERY_RESTORED_BACKUP;
    wifi_trust_store_ops_t ops = fake_ops();
    wifi_trust_profile_t profiles[1];
    size_t count;
    wifi_trust_store_meta_t meta;
    wifi_trust_recovery_action_t recovery;
    assert(wifi_trust_store_load(WIFI_TRUST_STORE_PATH, profiles, 1U, &count,
        &meta, &recovery, &ops) == WIFI_TRUST_STORE_OK);
    assert(recovery == WIFI_TRUST_RECOVERY_RESTORED_BACKUP);
    const char *bad[] = {
        "{\"v\":1,\"type\":\"header\",\"count\":0,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\r\n"
        "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000000\"}\r\n",
        "{\"v\":1,\"type\":\"header\",\"count\":0,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n"
        "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000001\"}\n",
        "{\"v\":1,\"type\":\"header\",\"count\":0,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n",
        "{\"v\":1,\"type\":\"header\",\"count\":0,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n"
        "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000000\"}\nX",
        "{\"type\":\"header\",\"v\":1,\"count\":0,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n"
        "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000000\"}\n",
        "{\"v\":1,\"type\":\"header\",\"count\":00,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n"
        "{\"v\":1,\"type\":\"end\",\"count\":0,\"crc32\":\"00000000\"}\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        reset_fake();
        file_from_text(&fake.target, bad[i]);
        assert(load_current(2U) == WIFI_TRUST_STORE_FORMAT);
        assert_lock_balanced();
    }
    reset_fake();
    char oversized[WIFI_TRUST_JSON_LINE_MAX + 2U];
    memset(oversized, 'A', sizeof(oversized));
    oversized[sizeof(oversized) - 1U] = '\n';
    fake.target.exists = true;
    memcpy(fake.target.bytes, oversized, sizeof(oversized));
    fake.target.length = sizeof(oversized);
    assert(load_current(2U) == WIFI_TRUST_STORE_CAPACITY);
    reset_fake();
    file_from_text(&fake.target,
        "{\"v\":1,\"type\":\"header\",\"count\":1,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n"
        "{\"v\":1,\"type\":\"end\",\"count\":1,\"crc32\":\"00000000\"}\n");
    assert(load_current(0U) == WIFI_TRUST_STORE_CAPACITY);
    reset_fake();
    file_from_text(&fake.target, zero_fixture);
    fake.fail_read = true;
    assert(load_current(1U) == WIFI_TRUST_STORE_IO);
    reset_fake();
    file_from_text(&fake.target, zero_fixture);
    fake.fail_close = true;
    assert(load_current(1U) == WIFI_TRUST_STORE_IO);

    reset_fake();
    file_from_text(&fake.target,
        "{\"v\":1,\"type\":\"header\",\"count\":129,\"boot\":\"0001020304050607\","
        "\"created_unix\":null,\"created_us\":987654321}\n");
    assert(load_current(2U) == WIFI_TRUST_STORE_CAPACITY);
}

static void test_readonly_load_never_recovers_or_mutates(void)
{
    reset_fake();
    file_from_text(&fake.target, zero_fixture);
    file_from_text(&fake.stage, "uncommitted-stage");
    file_from_text(&fake.backup, "old-backup");
    fake.recovery_result = FS_RECOVERY_RESTORED_BACKUP;
    wifi_trust_store_ops_t ops = fake_ops();
    wifi_trust_profile_t profiles[1];
    memset(profiles, 0xa5, sizeof(profiles));
    wifi_trust_store_meta_t meta;
    memset(&meta, 0xa5, sizeof(meta));
    size_t count = 99U;
    assert(wifi_trust_store_load_readonly(
        WIFI_TRUST_STORE_PATH, profiles, 1U, &count, &meta, &ops) ==
        WIFI_TRUST_STORE_OK);
    assert(count == 0U);
    assert(strcmp(fake.order, "LOCCU") == 0 || strcmp(fake.order, "LOCU") == 0);
    assert(fake.recovery_calls == 0U && fake.write_calls == 0U &&
           fake.flush_calls == 0U && fake.sync_calls == 0U &&
           fake.remove_calls == 0U && fake.rename_calls == 0U &&
           fake.publish_calls == 0U && fake.volume_sync_calls == 0U);
    assert(fake.stage.exists && fake.backup.exists);
    assert_lock_balanced();

    reset_fake();
    ops = fake_ops();
    count = 99U;
    memset(profiles, 0xa5, sizeof(profiles));
    memset(&meta, 0xa5, sizeof(meta));
    assert(wifi_trust_store_load_readonly(
        WIFI_TRUST_STORE_PATH, profiles, 1U, &count, &meta, &ops) ==
        WIFI_TRUST_STORE_NOT_FOUND);
    assert_cleared(profiles, 1U, &meta, count);
    assert(fake.recovery_calls == 0U && fake.open_calls == 1U);
    assert_lock_balanced();
}

static wifi_trust_store_result_t publish_one(void)
{
    wifi_trust_profile_t p = profile_fixture(0x42U);
    wifi_trust_store_meta_t meta = meta_fixture(true);
    wifi_trust_store_ops_t ops = fake_ops();
    return wifi_trust_store_publish(&p, 1U, &meta, &ops);
}
static void test_publish_fault_and_result_matrix(void)
{
    reset_fake();
    fake.recovery_result = FS_RECOVERY_CLEARED_STAGE;
    assert(publish_one() == WIFI_TRUST_STORE_RECOVERED_RETRY);
    assert(fake.open_calls == 0U);
    reset_fake();
    fake.recovery_result = FS_RECOVERY_FAILED;
    assert(publish_one() == WIFI_TRUST_STORE_RECOVERY);
    for (unsigned fault = 0; fault < 6U; ++fault) {
        reset_fake();
        if (fault == 0U) fake.fail_open = true;
        if (fault == 1U) fake.fail_write_call = 1U;
        if (fault == 2U) fake.short_write_call = 1U;
        if (fault == 3U) fake.fail_flush = true;
        if (fault == 4U) fake.fail_sync = true;
        if (fault == 5U) fake.fail_close = true;
        assert(publish_one() == WIFI_TRUST_STORE_IO);
        assert(fake.publish_calls == 0U);
        assert(fake.close_calls == (fault == 0U ? 0U : 1U));
        assert_lock_balanced();
    }
    reset_fake();
    fake.fail_open = true;
    fake.open_error_with_handle = true;
    assert(publish_one() == WIFI_TRUST_STORE_IO);
    assert(fake.close_calls == 1U);
    assert(fake.remove_calls == 1U);
    assert(!fake.stage.exists);
    assert(strcmp(fake.order, "LROCDU") == 0);
    assert_lock_balanced();
    reset_fake();
    fake.fail_open = true;
    fake.open_error_with_handle = true;
    fake.fail_close = true;
    assert(publish_one() == WIFI_TRUST_STORE_IO);
    assert(fake.close_calls == 1U && fake.remove_calls == 1U);
    assert(!fake.stage.exists);
    assert(strcmp(fake.order, "LROCDU") == 0);
    assert_lock_balanced();
    reset_fake();
    fake.fail_open = true;
    fake.open_error_with_handle = true;
    fake.fail_remove = true;
    assert(publish_one() == WIFI_TRUST_STORE_RECOVERY);
    assert(fake.close_calls == 1U && fake.remove_calls == 1U);
    assert(fake.stage.exists);
    assert(strcmp(fake.order, "LROCDU") == 0);
    assert_lock_balanced();
    reset_fake();
    fake.fail_write_call = 1U;
    fake.fail_remove = true;
    assert(publish_one() == WIFI_TRUST_STORE_RECOVERY);
    assert(fake.stage.exists);
    const struct {
        fs_publish_result_t input;
        wifi_trust_store_result_t output;
    } mappings[] = {
        {FS_PUBLISH_OK, WIFI_TRUST_STORE_OK},
        {FS_PUBLISH_BACKUP_LEFT, WIFI_TRUST_STORE_OK_BACKUP_PENDING},
        {FS_PUBLISH_ROLLBACK_FAILED, WIFI_TRUST_STORE_RECOVERY},
        {FS_PUBLISH_EXISTS, WIFI_TRUST_STORE_PUBLISH},
        {FS_PUBLISH_BAD_STAGE, WIFI_TRUST_STORE_PUBLISH},
        {FS_PUBLISH_BAD_TARGET, WIFI_TRUST_STORE_PUBLISH},
        {FS_PUBLISH_BACKUP_EXISTS, WIFI_TRUST_STORE_PUBLISH},
        {FS_PUBLISH_RENAME_FAILED, WIFI_TRUST_STORE_PUBLISH},
        {FS_PUBLISH_IO_ERROR, WIFI_TRUST_STORE_PUBLISH},
    };
    for (size_t i = 0; i < sizeof(mappings) / sizeof(mappings[0]); ++i) {
        reset_fake();
        fake.publish_result = mappings[i].input;
        assert(publish_one() == mappings[i].output);
        assert_lock_balanced();
    }
    reset_fake();
    fake.volume_sync_ok = false;
    assert(publish_one() == WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN);
    assert(fake.target.exists);

    reset_fake();
    wifi_trust_store_ops_t ops = fake_ops();
    ops.read = NULL;
    wifi_trust_profile_t p = profile_fixture(0x31U);
    wifi_trust_store_meta_t meta = meta_fixture(true);
    assert(wifi_trust_store_publish(&p, 1U, &meta, &ops) ==
           WIFI_TRUST_STORE_OK);
    meta.created_unix_known = false;
    assert(wifi_trust_store_publish(&p, 1U, &meta, &ops) ==
           WIFI_TRUST_STORE_IO);
}

static void test_clear_matrix(void)
{
    reset_fake();
    wifi_trust_store_ops_t ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_OK);
    reset_fake();
    fake.recovery_result = FS_RECOVERY_KEPT_TARGET;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_RECOVERED_RETRY);
    assert(fake.rename_calls == 0U);
    reset_fake();
    fake.target.exists = true;
    fake.target.length = 1U;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_OK);
    assert(!fake.target.exists && !fake.backup.exists);
    reset_fake();
    fake.target.exists = true;
    fake.fail_rename = true;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_PUBLISH);
    reset_fake();
    fake.target.exists = true;
    fake.fail_remove = true;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_PUBLISH);
    assert(fake.target.exists && !fake.backup.exists);
    assert(fake.volume_sync_calls == 1U);
    assert(strcmp(fake.order, "LRNDNVU") == 0);
    reset_fake();
    fake.target.exists = true;
    fake.fail_remove = true;
    fake.volume_sync_ok = false;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) ==
           WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN);
    assert(fake.target.exists && !fake.backup.exists);
    assert(fake.volume_sync_calls == 1U);
    assert(strcmp(fake.order, "LRNDNVU") == 0);
    reset_fake();
    fake.target.exists = true;
    fake.fail_remove = true;
    fake.fail_rollback = true;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) == WIFI_TRUST_STORE_RECOVERY);
    assert(!fake.target.exists && fake.backup.exists);
    reset_fake();
    fake.target.exists = true;
    fake.volume_sync_ok = false;
    ops = fake_ops();
    assert(wifi_trust_store_clear(&ops) ==
           WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN);
}

static uint32_t fuzz_state = UINT32_C(0x12345678);
static uint32_t fuzz_next(void)
{
    fuzz_state ^= fuzz_state << 13;
    fuzz_state ^= fuzz_state >> 17;
    fuzz_state ^= fuzz_state << 5;
    return fuzz_state;
}
static void test_malformed_corpus_is_bounded(void)
{
    wifi_trust_profile_t p = profile_fixture(0x77U);
    char canonical[WIFI_TRUST_JSON_LINE_MAX];
    int length = wifi_trust_store_format_ap_line(canonical,
                                                  sizeof(canonical), &p);
    assert(length > 0);
    char mutated[WIFI_TRUST_JSON_LINE_MAX];
    struct {
        uint8_t before[16];
        wifi_trust_profile_t profile;
        uint8_t after[16];
    } guarded;
    for (uint32_t i = 0; i < 100000U; ++i) {
        memcpy(mutated, canonical, (size_t)length + 1U);
        size_t at = fuzz_next() % (size_t)length;
        mutated[at] = (char)(fuzz_next() & 0x7fU);
        memset(&guarded, 0xa5, sizeof(guarded));
        bool parsed = wifi_trust_store_parse_ap_line(mutated, (size_t)length,
                                                     &guarded.profile);
        for (size_t j = 0; j < sizeof(guarded.before); ++j)
            assert(guarded.before[j] == 0xa5U && guarded.after[j] == 0xa5U);
        if (!parsed) {
            for (size_t j = 0; j < sizeof(guarded.profile); ++j)
                assert(((const uint8_t *)&guarded.profile)[j] == 0xa5U);
        } else assert(wifi_trust_profile_valid(&guarded.profile));
    }
}

int main(void)
{
    assert(WIFI_TRUST_JSON_LINE_MAX == 2048U);
    test_codec_and_strict_schema();
    test_publish_load_roundtrip_and_sorting();
    test_zero_128_capacity_and_canonical_bytes();
    test_load_rejects_noncanonical_paths_before_side_effects();
    test_load_rejections_and_recovery();
    test_readonly_load_never_recovers_or_mutates();
    test_publish_fault_and_result_matrix();
    test_clear_matrix();
    test_malformed_corpus_is_bounded();
    puts("PASS: Wi-Fi Trust canonical JSONL store, recovery and faults");
    return 0;
}
