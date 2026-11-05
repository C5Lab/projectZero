#include "router_cve_db.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *deny_cache(void *context, size_t size)
{
    (void)context;
    (void)size;
    return NULL;
}

static void deny_release(void *context, void *memory, size_t size)
{
    (void)context;
    (void)memory;
    (void)size;
    assert(false);
}

static void *count_deny_cache(void *context, size_t size)
{
    unsigned *calls = context;
    (void)size;
    ++*calls;
    return NULL;
}

typedef struct {
    unsigned allocations;
    unsigned releases;
    unsigned fail_after;
} cache_state_t;

static void *cache_allocate(void *context, size_t size)
{
    cache_state_t *state = context;
    ++state->allocations;
    if (state->fail_after != 0U && state->allocations > state->fail_after)
        return NULL;
    return malloc(size);
}

static void cache_release(void *context, void *memory, size_t size)
{
    cache_state_t *state = context;
    (void)size;
    ++state->releases;
    free(memory);
}

static void expect_open_failure(const char *path, router_cve_db_result_t expected)
{
    router_cve_db_result_t result = ROUTER_CVE_DB_OK;
    router_cve_db_t *db = router_cve_db_open(path, NULL, &result);
    assert(db == NULL);
    assert(result == expected);
}

static void copy_with_mutation(const char *source, const char *target,
                               size_t offset, uint8_t value)
{
    FILE *input = fopen(source, "rb");
    FILE *output = fopen(target, "wb");
    uint8_t buffer[1024];
    size_t position = 0U;
    assert(input != NULL && output != NULL);
    for (;;) {
        size_t got = fread(buffer, 1U, sizeof(buffer), input);
        if (got == 0U) break;
        if (offset >= position && offset < position + got)
            buffer[offset - position] = value;
        assert(fwrite(buffer, 1U, got, output) == got);
        position += got;
    }
    assert(!ferror(input));
    assert(fclose(input) == 0);
    assert(fclose(output) == 0);
}

static router_fingerprint_t fingerprint(const char *model, const char *firmware,
                                        router_confidence_t confidence)
{
    router_fingerprint_t value;
    memset(&value, 0, sizeof(value));
    memcpy(value.vendor, "fixture networks", sizeof("fixture networks"));
    memcpy(value.model, model, strlen(model) + 1U);
    if (firmware != NULL)
        memcpy(value.firmware, firmware, strlen(firmware) + 1U);
    value.confidence = confidence;
    return value;
}

typedef struct {
    uint8_t *bytes;
    uint32_t size;
    bool missing;
    bool open_error;
    bool fail_size;
    unsigned fail_read_call;
    unsigned read_calls;
    unsigned close_calls;
} fake_io_t;

static router_cve_io_result_t fake_open(void *opaque, const char *path, void **handle)
{
    fake_io_t *fake = opaque;
    (void)path;
    if (fake->missing) return ROUTER_CVE_IO_MISSING;
    if (fake->open_error) return ROUTER_CVE_IO_ERROR;
    *handle = fake;
    return ROUTER_CVE_IO_OK;
}

static bool fake_size(void *opaque, void *handle, uint32_t *size)
{
    fake_io_t *fake = opaque;
    assert(handle == fake);
    if (fake->fail_size) return false;
    *size = fake->size;
    return true;
}

static bool fake_read(void *opaque, void *handle, uint32_t offset,
                      void *buffer, size_t size)
{
    fake_io_t *fake = opaque;
    assert(handle == fake);
    ++fake->read_calls;
    if (fake->fail_read_call == fake->read_calls || size > fake->size ||
        offset > fake->size - size) return false;
    memcpy(buffer, fake->bytes + offset, size);
    return true;
}

static bool fake_close(void *opaque, void *handle)
{
    fake_io_t *fake = opaque;
    assert(handle == fake);
    ++fake->close_calls;
    return true;
}

static void load_fixture(const char *path, fake_io_t *fake)
{
    FILE *file = fopen(path, "rb");
    long size;
    assert(file != NULL && fseek(file, 0L, SEEK_END) == 0);
    size = ftell(file);
    assert(size > 0L && size <= (long)UINT32_MAX);
    assert(fseek(file, 0L, SEEK_SET) == 0);
    fake->size = (uint32_t)size;
    fake->bytes = malloc(fake->size);
    assert(fake->bytes != NULL && fread(fake->bytes, 1U, fake->size, file) == fake->size);
    assert(fclose(file) == 0);
}

static void test_injected_io_failures(const char *fixture)
{
    fake_io_t fake;
    router_cve_db_io_t io;
    router_cve_db_result_t result;
    router_cve_db_t *db;
    memset(&fake, 0, sizeof(fake));
    load_fixture(fixture, &fake);
    io.open = fake_open;
    io.size = fake_size;
    io.read_at = fake_read;
    io.close = fake_close;
    io.context = &fake;

    fake.open_error = true;
    db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
    assert(db == NULL && result == ROUTER_CVE_DB_IO && fake.close_calls == 0U);
    fake.open_error = false;

    fake.fail_size = true;
    db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
    assert(db == NULL && result == ROUTER_CVE_DB_IO && fake.close_calls == 1U);
    fake.fail_size = false;
    fake.close_calls = 0U;
    fake.fail_read_call = 1U;
    db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
    assert(db == NULL && result == ROUTER_CVE_DB_IO && fake.close_calls == 1U);

    fake.read_calls = 0U;
    fake.close_calls = 0U;
    fake.fail_read_call = 2U;
    db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
    assert(db == NULL && result == ROUTER_CVE_DB_IO && fake.close_calls == 1U);

    fake.fail_read_call = 0U;
    fake.read_calls = 0U;
    fake.close_calls = 0U;
    db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
    assert(db != NULL && result == ROUTER_CVE_DB_OK);
    router_cve_db_close(db);
    assert(fake.close_calls == 1U);

    {
        cache_state_t cache = {0U, 0U, 0U};
        const router_cve_db_alloc_t allocator = {
            .allocate = cache_allocate,
            .release = cache_release,
            .context = &cache,
        };
        unsigned reads_after_open;
        router_cve_result_t output[2];
        router_fingerprint_t value = fingerprint(
            "router one", "1 0 0", ROUTER_CONFIDENCE_CONFIRMED);
        size_t required = 0U;
        fake.read_calls = 0U;
        fake.close_calls = 0U;
        db = router_cve_db_open_with_io("ignored", &allocator, &io, &result);
        assert(db != NULL && cache.allocations == 3U);
        reads_after_open = fake.read_calls;
        fake.bytes[200U] ^= 0x5AU;
        fake.fail_read_call = reads_after_open + 1U;
        assert(router_cve_db_lookup(db, &value, output, 2U, &required) ==
               ROUTER_CVE_DB_OK && required == 2U);
        assert(fake.read_calls == reads_after_open);
        router_cve_db_close(db);
        assert(cache.allocations == 4U && cache.releases == 4U &&
               fake.close_calls == 1U);
        fake.bytes[200U] ^= 0x5AU;
        fake.fail_read_call = 0U;
    }

    {
        unsigned allocation_calls = 0U;
        const router_cve_db_alloc_t allocator = {
            .allocate = count_deny_cache,
            .release = deny_release,
            .context = &allocation_calls,
        };
        fake.size = ROUTER_CVE_DB_MAX_BYTES + 1U;
        fake.read_calls = 0U;
        fake.close_calls = 0U;
        db = router_cve_db_open_with_io("ignored", &allocator, &io, &result);
        assert(db == NULL && result == ROUTER_CVE_DB_FORMAT);
        assert(allocation_calls == 0U && fake.read_calls == 0U &&
               fake.close_calls == 1U);
    }
    free(fake.bytes);
}

static void test_atomic_materialization_failure(const char *fixture)
{
    cache_state_t cache = {0U, 0U, 3U};
    const router_cve_db_alloc_t allocator = {
        .allocate = cache_allocate,
        .release = cache_release,
        .context = &cache,
    };
    router_cve_db_result_t result = ROUTER_CVE_DB_IO;
    router_cve_db_t *db = router_cve_db_open(fixture, &allocator, &result);
    router_cve_result_t output[2], before[2];
    router_fingerprint_t value = fingerprint(
        "router one", "1 0 0", ROUTER_CONFIDENCE_CONFIRMED);
    size_t required = 99U;
    assert(db != NULL && result == ROUTER_CVE_DB_OK);
    memset(output, 0x6B, sizeof(output));
    memcpy(before, output, sizeof(output));
    assert(router_cve_db_lookup(db, &value, output, 2U, &required) ==
           ROUTER_CVE_DB_CAPACITY);
    assert(required == 2U && memcmp(output, before, sizeof(output)) == 0);
    router_cve_db_close(db);
    assert(cache.allocations == 4U && cache.releases == 3U);
}

static void test_lookup_and_capacity(const char *fixture)
{
    router_cve_db_result_t opened = ROUTER_CVE_DB_IO;
    router_cve_db_t *db = router_cve_db_open(fixture, NULL, &opened);
    assert(db != NULL && opened == ROUTER_CVE_DB_OK);

    router_cve_db_metadata_t metadata;
    assert(router_cve_db_metadata(db, &metadata) == ROUTER_CVE_DB_OK);
    assert(metadata.serial == UINT64_C(7));
    assert(metadata.file_size == 854U);
    assert(metadata.model_count == 2U && metadata.advisory_count == 2U);

    router_cve_result_t results[2];
    memset(results, 0xA5, sizeof(results));
    size_t required = 99U;
    router_fingerprint_t value = fingerprint("router one", "1 0 0",
                                             ROUTER_CONFIDENCE_CONFIRMED);
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK);
    assert(required == 2U);
    assert(results[0].match == ROUTER_CVE_EXACT_FIRMWARE);
    assert(results[1].match == ROUTER_CVE_EXACT_FIRMWARE);
    assert(strcmp(results[0].cve, "CVE-2099-0001") == 0);
    assert(strcmp(results[1].cve, "CVE-2099-0002") == 0);
    assert(strstr(results[0].advisory_url, "example.invalid") != NULL);
    assert(strcmp(results[0].severity, "high") == 0);
    assert(!results[0].eol);
    assert(results[1].eol && results[1].kev);

    router_cve_result_t sentinel;
    memset(&sentinel, 0x5A, sizeof(sentinel));
    router_cve_result_t before = sentinel;
    required = 0U;
    assert(router_cve_db_lookup(db, &value, &sentinel, 1U, &required) ==
           ROUTER_CVE_DB_CAPACITY);
    assert(required == 2U);
    assert(memcmp(&sentinel, &before, sizeof(sentinel)) == 0);

    value = fingerprint("router one", "9 9", ROUTER_CONFIDENCE_CONFIRMED);
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK);
    assert(required == 2U && results[0].match == ROUTER_CVE_MODEL_CANDIDATE);

    value = fingerprint("router one", NULL, ROUTER_CONFIDENCE_CONFIRMED);
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK);
    assert(required == 2U && results[0].match == ROUTER_CVE_MODEL_CANDIDATE);

    value = fingerprint("router absent", "1 0 0", ROUTER_CONFIDENCE_CONFIRMED);
    memset(results, 0x44, sizeof(results));
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK && required == 0U);
    value = fingerprint("router one", "1 0 0", ROUTER_CONFIDENCE_CONFIRMED);
    memcpy(value.vendor, "other networks", sizeof("other networks"));
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK && required == 0U);

    value = fingerprint("r1 test", "1 1 0", ROUTER_CONFIDENCE_CONFIRMED);
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK);
    assert(required == 1U && results[0].match == ROUTER_CVE_EXACT_FIRMWARE);

    value = fingerprint("router one", "1 0 0", ROUTER_CONFIDENCE_PROBABLE);
    memset(results, 0x33, sizeof(results));
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK);
    assert(required == 0U);
    value.confidence = ROUTER_CONFIDENCE_CONFIRMED;
    value.conflict = true;
    assert(router_cve_db_lookup(db, &value, results, 2U, &required) ==
           ROUTER_CVE_DB_OK && required == 0U);

    router_cve_db_close(db);
}

static void test_cache_refusal_fails_closed(const char *fixture)
{
    const router_cve_db_alloc_t allocator = {
        .allocate = deny_cache,
        .release = deny_release,
        .context = NULL,
    };
    router_cve_db_result_t result = ROUTER_CVE_DB_IO;
    router_cve_db_t *db = router_cve_db_open(fixture, &allocator, &result);
    assert(db == NULL && result == ROUTER_CVE_DB_CAPACITY);
}

static void test_file_and_integrity_failures(const char *fixture, const char *directory)
{
    char path[512];
    static const char *const format_cases[] = {
        "reserved.bin", "overlap.bin", "bad_string_offset.bin",
        "alias_primary_collision.bin", "advisory_reserved.bin",
        "bad_published.bin", "zero_year.bin", "invalid_utf8.bin", "trailing.bin",
        "nonascii_punct_identity.bin", "nonascii_identity.bin",
        "bad_url_0.bin", "bad_url_1.bin", "bad_url_2.bin",
        "bad_url_3.bin", "bad_url_4.bin", "bad_url_5.bin",
        "oversize.bin",
    };
    size_t case_index;
    snprintf(path, sizeof(path), "%s/missing.bin", directory);
    expect_open_failure(path, ROUTER_CVE_DB_NOT_FOUND);

    snprintf(path, sizeof(path), "%s/short.bin", directory);
    FILE *file = fopen(path, "wb");
    assert(file != NULL && fwrite("JCVE", 1U, 4U, file) == 4U);
    assert(fclose(file) == 0);
    expect_open_failure(path, ROUTER_CVE_DB_FORMAT);

    snprintf(path, sizeof(path), "%s/magic.bin", directory);
    copy_with_mutation(fixture, path, 0U, (uint8_t)'X');
    expect_open_failure(path, ROUTER_CVE_DB_FORMAT);

    snprintf(path, sizeof(path), "%s/crc.bin", directory);
    copy_with_mutation(fixture, path, 200U, 0xFFU);
    expect_open_failure(path, ROUTER_CVE_DB_CRC);

    /* Header payload hash corruption leaves the payload CRC valid. */
    snprintf(path, sizeof(path), "%s/hash.bin", directory);
    copy_with_mutation(fixture, path, 48U, 0xFFU);
    expect_open_failure(path, ROUTER_CVE_DB_HASH);

    snprintf(path, sizeof(path), "%s/bad_retrieved.bin", directory);
    expect_open_failure(path, ROUTER_CVE_DB_FORMAT);
    snprintf(path, sizeof(path), "%s/bad_port.bin", directory);
    expect_open_failure(path, ROUTER_CVE_DB_FORMAT);
    for (case_index = 0U;
         case_index < sizeof(format_cases) / sizeof(format_cases[0]);
         ++case_index) {
        snprintf(path, sizeof(path), "%s/%s", directory,
                 format_cases[case_index]);
        expect_open_failure(path, ROUTER_CVE_DB_FORMAT);
    }
    snprintf(path, sizeof(path), "%s/provenance_hash.bin", directory);
    expect_open_failure(path, ROUTER_CVE_DB_HASH);
    for (case_index = 2U; case_index < 4U; ++case_index) {
        router_cve_db_result_t result = ROUTER_CVE_DB_IO;
        router_cve_db_t *db;
        snprintf(path, sizeof(path), "%s/accepted_url_%u.bin", directory,
                 (unsigned)case_index);
        db = router_cve_db_open(path, NULL, &result);
        assert(db != NULL && result == ROUTER_CVE_DB_OK);
        router_cve_db_close(db);
    }
}

static void test_near_limit_work_is_bounded(const char *directory)
{
    char path[512];
    router_cve_db_result_t result = ROUTER_CVE_DB_IO;
    router_cve_db_metadata_t metadata;
    snprintf(path, sizeof(path), "%s/near_limit.bin", directory);
    router_cve_db_t *db = router_cve_db_open(path, NULL, &result);
    assert(db != NULL && result == ROUTER_CVE_DB_OK);
    assert(router_cve_db_metadata(db, &metadata) == ROUTER_CVE_DB_OK);
    assert(metadata.model_count == 128U && metadata.alias_count == 256U);
    assert(metadata.advisory_count == 256U &&
           metadata.firmware_rule_count == 1024U);
    assert(metadata.file_size == 55112U && metadata.string_count == 1930U);
    assert(metadata.validation_work == 927032U &&
           metadata.validation_work <= ROUTER_CVE_DB_MAX_VALIDATION_WORK);
    assert(metadata.string_hash_bytes == 28390U &&
           metadata.string_sort_comparisons == 19866U &&
           metadata.string_compare_bytes == 0U);
    assert(metadata.snapshot_read_ops == 108U &&
           metadata.snapshot_read_ops ==
           (metadata.file_size + ROUTER_CVE_DB_SNAPSHOT_CHUNK - 1U) /
           ROUTER_CVE_DB_SNAPSHOT_CHUNK);
    router_cve_db_close(db);
}

static void test_near_limit_snapshot_fault_positions(const char *directory)
{
    char path[512];
    fake_io_t fake;
    router_cve_db_io_t io;
    router_cve_db_result_t result;
    router_cve_db_t *db;
    unsigned total_calls, cases[3], index;
    memset(&fake, 0, sizeof(fake));
    snprintf(path, sizeof(path), "%s/near_limit.bin", directory);
    load_fixture(path, &fake);
    io.open = fake_open;
    io.size = fake_size;
    io.read_at = fake_read;
    io.close = fake_close;
    io.context = &fake;
    total_calls = (fake.size + ROUTER_CVE_DB_SNAPSHOT_CHUNK - 1U) /
                  ROUTER_CVE_DB_SNAPSHOT_CHUNK;
    assert(total_calls > 3U);
    cases[0] = 1U;
    cases[1] = total_calls / 2U;
    cases[2] = total_calls;
    for (index = 0U; index < 3U; ++index) {
        fake.read_calls = 0U;
        fake.close_calls = 0U;
        fake.fail_read_call = cases[index];
        db = router_cve_db_open_with_io("ignored", NULL, &io, &result);
        assert(db == NULL && result == ROUTER_CVE_DB_IO);
        assert(fake.close_calls == 1U && fake.read_calls == cases[index]);
    }
    free(fake.bytes);
}

static void test_adversarial_string_index_is_bounded(const char *directory)
{
    char path[512];
    router_cve_db_result_t result = ROUTER_CVE_DB_IO;
    router_cve_db_metadata_t metadata;
    router_cve_db_t *db;
    snprintf(path, sizeof(path), "%s/adversarial_strings.bin", directory);
    db = router_cve_db_open(path, NULL, &result);
    assert(db != NULL && result == ROUTER_CVE_DB_OK);
    assert(router_cve_db_metadata(db, &metadata) == ROUTER_CVE_DB_OK);
    assert(metadata.string_count == ROUTER_CVE_DB_MAX_STRING_ENTRIES);
    assert(metadata.file_size == 449044U && metadata.snapshot_read_ops == 878U);
    assert(metadata.string_hash_bytes == 422204U);
    assert(metadata.string_sort_comparisons == 21333U);
    assert(metadata.string_compare_bytes == 0U);
    assert(metadata.validation_work == 1324654U &&
           metadata.validation_work <= ROUTER_CVE_DB_MAX_VALIDATION_WORK);
    router_cve_db_close(db);

    snprintf(path, sizeof(path), "%s/adversarial_duplicate.bin", directory);
    expect_open_failure(path, ROUTER_CVE_DB_FORMAT);
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    test_lookup_and_capacity(argv[1]);
    test_cache_refusal_fails_closed(argv[1]);
    test_file_and_integrity_failures(argv[1], argv[2]);
    test_injected_io_failures(argv[1]);
    test_atomic_materialization_failure(argv[1]);
    test_near_limit_work_is_bounded(argv[2]);
    test_near_limit_snapshot_fault_positions(argv[2]);
    test_adversarial_string_index_is_bounded(argv[2]);
    puts("PASS: bounded JCVE/1 validation and evidence-only exact lookup");
    return 0;
}
