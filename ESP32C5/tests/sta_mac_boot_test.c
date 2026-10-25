#include "sta_mac_boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) do { \
    if (!(expr)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); exit(1); } \
} while (0)

static const uint8_t factory_mac[STA_MAC_SIZE] = {0x34, 0x85, 0x18, 0x10, 0x20, 0x30};
static const uint8_t fixed_mac[STA_MAC_SIZE] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t fixed_record[STA_MAC_POLICY_RECORD_SIZE] =
    {1, 2, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t random_record[STA_MAC_POLICY_RECORD_SIZE] =
    {1, 1, 0, 0, 0, 0, 0, 0};

typedef struct {
    sta_mac_io_status_t open_read_status;
    sta_mac_io_status_t open_write_status;
    sta_mac_io_status_t read_status;
    sta_mac_io_status_t write_status;
    sta_mac_io_status_t commit_status;
    uint8_t bytes[STA_MAC_POLICY_RECORD_SIZE];
    uint8_t pending[STA_MAC_POLICY_RECORD_SIZE];
    size_t length;
    unsigned reads;
    unsigned writes;
    unsigned commits;
    unsigned closes;
} memory_store_t;

static void reset_store(memory_store_t *memory)
{
    memset(memory, 0, sizeof(*memory));
    memory->read_status = STA_MAC_IO_MISSING;
    memory->length = STA_MAC_POLICY_RECORD_SIZE;
}

static void record(memory_store_t *memory, const uint8_t bytes[STA_MAC_POLICY_RECORD_SIZE])
{
    memcpy(memory->bytes, bytes, STA_MAC_POLICY_RECORD_SIZE);
    memory->read_status = STA_MAC_IO_OK;
}

static sta_mac_io_status_t store_open(void *context, sta_mac_store_access_t access, void **handle)
{
    memory_store_t *memory = context;
    *handle = memory;
    return access == STA_MAC_STORE_READ_ONLY ? memory->open_read_status : memory->open_write_status;
}

static sta_mac_io_status_t store_read(void *handle, uint8_t *out, size_t capacity,
                                      size_t *actual_length)
{
    memory_store_t *memory = handle;
    ++memory->reads;
    *actual_length = memory->length;
    if (memory->read_status != STA_MAC_IO_OK) return memory->read_status;
    if (capacity < memory->length) return STA_MAC_IO_BUFFER_TOO_SMALL;
    memcpy(out, memory->bytes, memory->length);
    return STA_MAC_IO_OK;
}

static sta_mac_io_status_t store_write(void *handle, const uint8_t *bytes, size_t length)
{
    memory_store_t *memory = handle;
    ++memory->writes;
    CHECK(length == STA_MAC_POLICY_RECORD_SIZE);
    if (memory->write_status == STA_MAC_IO_OK) memcpy(memory->pending, bytes, length);
    return memory->write_status;
}

static sta_mac_io_status_t store_commit(void *handle)
{
    memory_store_t *memory = handle;
    ++memory->commits;
    if (memory->commit_status == STA_MAC_IO_OK) {
        memcpy(memory->bytes, memory->pending, STA_MAC_POLICY_RECORD_SIZE);
        memory->read_status = STA_MAC_IO_OK;
        memory->length = STA_MAC_POLICY_RECORD_SIZE;
    }
    return memory->commit_status;
}

static void store_close(void *handle) { ++((memory_store_t *)handle)->closes; }

static sta_mac_policy_store_t make_store(memory_store_t *memory)
{
    sta_mac_policy_store_t store =
        {memory, store_open, store_read, store_write, store_commit, store_close};
    return store;
}

typedef struct {
    unsigned calls;
    bool fail;
} entropy_source_t;

static bool next_entropy(void *context, uint8_t out[STA_MAC_SIZE])
{
    entropy_source_t *source = context;
    ++source->calls;
    if (source->fail) return false;
    const uint8_t first[STA_MAC_SIZE] = {0x01, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5};
    const uint8_t second[STA_MAC_SIZE] = {0xfc, 0x10, 0x20, 0x30, 0x40, 0x50};
    memcpy(out, source->calls == 1 ? first : second, STA_MAC_SIZE);
    return true;
}

typedef struct {
    bool fail_set;
    bool fail_get;
    bool mismatch;
    unsigned sets;
    unsigned gets;
    uint8_t current[STA_MAC_SIZE];
} fake_driver_t;

static bool driver_set(void *context, const uint8_t mac[STA_MAC_SIZE])
{
    fake_driver_t *driver = context;
    ++driver->sets;
    if (driver->fail_set) return false;
    memcpy(driver->current, mac, STA_MAC_SIZE);
    return true;
}

static bool driver_get(void *context, uint8_t mac[STA_MAC_SIZE])
{
    fake_driver_t *driver = context;
    ++driver->gets;
    if (driver->fail_get) return false;
    memcpy(mac, driver->current, STA_MAC_SIZE);
    if (driver->mismatch) mac[5] ^= 1u;
    return true;
}

static sta_mac_boot_driver_t make_driver(fake_driver_t *driver)
{
    sta_mac_boot_driver_t callbacks = {driver, driver_set, driver_get};
    return callbacks;
}

/* Removing the missing-record fallback or accidentally writing on load fails here. */
static void test_factory_default(void)
{
    memory_store_t memory;
    reset_store(&memory);
    sta_mac_policy_store_t store = make_store(&memory);
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, NULL, NULL) == STA_MAC_BOOT_OK);
    CHECK(state.ready && state.configured_known && !state.pending_reboot);
    CHECK(state.record_health == STA_MAC_BOOT_RECORD_MISSING);
    CHECK(state.load_result.status == STA_MAC_STORE_MISSING_KEY);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_FACTORY);
    CHECK(state.boot_policy.mode == STA_MAC_MODE_FACTORY);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    CHECK(memory.reads == 1 && memory.writes == 0 && memory.commits == 0);
    fake_driver_t driver = {0};
    sta_mac_boot_driver_t callbacks = make_driver(&driver);
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_OK);
    CHECK(driver.sets == 1 && driver.gets == 1);
    CHECK(memcmp(driver.current, factory_mac, STA_MAC_SIZE) == 0);
    memory_store_t missing_namespace;
    reset_store(&missing_namespace);
    missing_namespace.open_read_status = STA_MAC_IO_MISSING;
    sta_mac_policy_store_t namespace_store = make_store(&missing_namespace);
    CHECK(sta_mac_boot_init(&state, &namespace_store, factory_mac, NULL, NULL) == STA_MAC_BOOT_OK);
    CHECK(state.record_health == STA_MAC_BOOT_RECORD_MISSING && state.ready);
    CHECK(state.configured_known);
    CHECK(state.load_result.status == STA_MAC_STORE_MISSING_NAMESPACE);
    CHECK(missing_namespace.reads == 0 && missing_namespace.writes == 0);
}

/* A persisted fixed policy controls boot MAC without entropy or rewrite. */
static void test_fixed_record(void)
{
    memory_store_t memory;
    reset_store(&memory);
    record(&memory, fixed_record);
    sta_mac_policy_store_t store = make_store(&memory);
    entropy_source_t entropy = {0};
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_OK);
    CHECK(state.record_health == STA_MAC_BOOT_RECORD_VALID);
    CHECK(state.configured_known);
    CHECK(state.boot_policy.mode == STA_MAC_MODE_FIXED);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_FIXED);
    CHECK(memcmp(state.effective_mac, fixed_mac, STA_MAC_SIZE) == 0);
    CHECK(entropy.calls == 0 && memory.writes == 0);
}

/* Invalid/future records may boot factory but cannot be silently repaired. */
static void test_invalid_record(void)
{
    memory_store_t memory;
    reset_store(&memory);
    const uint8_t future[STA_MAC_POLICY_RECORD_SIZE] = {2, 0, 0, 0, 0, 0, 0, 0};
    record(&memory, future);
    sta_mac_policy_store_t store = make_store(&memory);
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, NULL, NULL) == STA_MAC_BOOT_OK);
    CHECK(state.ready && !state.configured_known && state.record_health == STA_MAC_BOOT_RECORD_INVALID);
    CHECK(state.load_result.status == STA_MAC_STORE_INVALID_RECORD);
    CHECK(state.load_result.policy_status == STA_MAC_POLICY_UNSUPPORTED_VERSION);
    CHECK(state.boot_policy.mode == STA_MAC_MODE_FACTORY);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    CHECK(memory.writes == 0 && memory.commits == 0);
    CHECK(memcmp(memory.bytes, future, STA_MAC_POLICY_RECORD_SIZE) == 0);
}

/* A storage read error must stop application even though status has factory MAC. */
static void test_read_error_gate(void)
{
    memory_store_t memory;
    reset_store(&memory);
    memory.read_status = STA_MAC_IO_ERROR;
    sta_mac_policy_store_t store = make_store(&memory);
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, NULL, NULL) == STA_MAC_BOOT_STORE_ERROR);
    CHECK(!state.ready && !state.configured_known && state.record_health == STA_MAC_BOOT_RECORD_READ_ERROR);
    CHECK(state.load_result.status == STA_MAC_STORE_READ_FAILED);
    CHECK(state.boot_policy.mode == STA_MAC_MODE_FACTORY);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    fake_driver_t driver = {0};
    sta_mac_boot_driver_t callbacks = make_driver(&driver);
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_NOT_READY);
    CHECK(driver.sets == 0 && driver.gets == 0);
    memory.open_read_status = STA_MAC_IO_ERROR;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, NULL, NULL) == STA_MAC_BOOT_STORE_ERROR);
    CHECK(state.load_result.status == STA_MAC_STORE_OPEN_FAILED && !state.ready);
    CHECK(!state.configured_known);
    sta_mac_policy_record_t fixed = {STA_MAC_POLICY_VERSION, STA_MAC_MODE_FIXED,
                                     {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    memory.commit_status = STA_MAC_IO_ERROR;
    CHECK(sta_mac_boot_save(&state, &fixed).status == STA_MAC_STORE_COMMIT_FAILED);
    CHECK(!state.configured_known && !state.ready);
    memory.commit_status = STA_MAC_IO_OK;
    CHECK(sta_mac_boot_save(&state, &fixed).status == STA_MAC_STORE_OK);
    CHECK(state.configured_known && !state.ready && state.pending_reboot);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_FIXED);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_NOT_READY);
    CHECK(driver.sets == 0 && driver.gets == 0);
}

/* Random MAC is generated once for this boot and reused across driver init. */
static void test_random_per_boot(void)
{
    memory_store_t memory;
    reset_store(&memory);
    record(&memory, random_record);
    sta_mac_policy_store_t store = make_store(&memory);
    entropy_source_t entropy = {0};
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_OK);
    const uint8_t expected_first[STA_MAC_SIZE] = {0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5};
    CHECK(state.ready && state.boot_policy.mode == STA_MAC_MODE_RANDOM_PER_BOOT);
    CHECK(memcmp(state.effective_mac, expected_first, STA_MAC_SIZE) == 0);
    CHECK(entropy.calls == 1);
    fake_driver_t driver = {0};
    sta_mac_boot_driver_t callbacks = make_driver(&driver);
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_OK);
    memset(&driver, 0, sizeof(driver)); /* simulated Wi-Fi deinit/reinit */
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_OK);
    CHECK(memcmp(driver.current, expected_first, STA_MAC_SIZE) == 0);
    CHECK(entropy.calls == 1);
    sta_mac_boot_state_t next_boot;
    CHECK(sta_mac_boot_init(&next_boot, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_OK);
    const uint8_t expected_second[STA_MAC_SIZE] = {0xfe, 0x10, 0x20, 0x30, 0x40, 0x50};
    CHECK(memcmp(next_boot.effective_mac, expected_second, STA_MAC_SIZE) == 0);
    CHECK(entropy.calls == 2);
    CHECK(memcmp(state.effective_mac, expected_first, STA_MAC_SIZE) == 0);
}

/* Failed entropy cannot authorize radio start with the factory placeholder. */
static void test_entropy_failure(void)
{
    memory_store_t memory;
    reset_store(&memory);
    record(&memory, random_record);
    sta_mac_policy_store_t store = make_store(&memory);
    entropy_source_t entropy = {0};
    entropy.fail = true;
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_ENTROPY_ERROR);
    CHECK(!state.ready && state.configured_known && state.record_health == STA_MAC_BOOT_RECORD_VALID);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    CHECK(entropy.calls == 1);
    fake_driver_t driver = {0};
    sta_mac_boot_driver_t callbacks = make_driver(&driver);
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_NOT_READY);
    CHECK(driver.sets == 0);
}

/* Save updates configured state only after commit; boot identity is immutable. */
static void test_set_next_boot(void)
{
    memory_store_t memory;
    reset_store(&memory);
    record(&memory, fixed_record);
    sta_mac_policy_store_t store = make_store(&memory);
    entropy_source_t entropy = {0};
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_OK);
    sta_mac_policy_record_t random = {STA_MAC_POLICY_VERSION, STA_MAC_MODE_RANDOM_PER_BOOT, {0}};
    memory.write_status = STA_MAC_IO_ERROR;
    CHECK(sta_mac_boot_save(&state, &random).status == STA_MAC_STORE_WRITE_FAILED);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_FIXED && state.configured_known && !state.pending_reboot);
    memory.write_status = STA_MAC_IO_OK;
    memory.commit_status = STA_MAC_IO_ERROR;
    CHECK(sta_mac_boot_save(&state, &random).status == STA_MAC_STORE_COMMIT_FAILED);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_FIXED && !state.pending_reboot);
    memory.commit_status = STA_MAC_IO_OK;
    CHECK(sta_mac_boot_save(&state, &random).status == STA_MAC_STORE_OK);
    CHECK(state.configured_policy.mode == STA_MAC_MODE_RANDOM_PER_BOOT && state.pending_reboot);
    CHECK(state.boot_policy.mode == STA_MAC_MODE_FIXED);
    CHECK(memcmp(state.effective_mac, fixed_mac, STA_MAC_SIZE) == 0);
    CHECK(memcmp(memory.bytes, random_record, STA_MAC_POLICY_RECORD_SIZE) == 0);
    CHECK(entropy.calls == 0); /* a set must not consume this boot's entropy */
    sta_mac_boot_state_t next_boot;
    CHECK(sta_mac_boot_init(&next_boot, &store, factory_mac, next_entropy, &entropy) == STA_MAC_BOOT_OK);
    CHECK(next_boot.boot_policy.mode == STA_MAC_MODE_RANDOM_PER_BOOT);
    CHECK(next_boot.ready && !next_boot.pending_reboot && entropy.calls == 1);
    sta_mac_policy_record_t fixed = {STA_MAC_POLICY_VERSION, STA_MAC_MODE_FIXED,
                                     {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
    CHECK(sta_mac_boot_save(&state, &fixed).status == STA_MAC_STORE_OK);
    CHECK(!state.pending_reboot && state.boot_policy.mode == STA_MAC_MODE_FIXED);
    CHECK(memcmp(state.effective_mac, fixed_mac, STA_MAC_SIZE) == 0);
}

/* Exact readback is required; every failure leaves boot identity intact. */
static void test_driver_failures(void)
{
    memory_store_t memory;
    reset_store(&memory);
    sta_mac_policy_store_t store = make_store(&memory);
    sta_mac_boot_state_t state;
    CHECK(sta_mac_boot_init(&state, &store, factory_mac, NULL, NULL) == STA_MAC_BOOT_OK);
    fake_driver_t driver = {0};
    sta_mac_boot_driver_t callbacks = make_driver(&driver);
    driver.fail_set = true;
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_SET_FAILED);
    CHECK(driver.sets == 1 && driver.gets == 0);
    driver.fail_set = false; driver.fail_get = true;
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_READ_FAILED);
    CHECK(driver.sets == 2 && driver.gets == 1);
    driver.fail_get = false; driver.mismatch = true;
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_MISMATCH);
    CHECK(driver.sets == 3 && driver.gets == 2);
    CHECK(memcmp(state.effective_mac, factory_mac, STA_MAC_SIZE) == 0);
    CHECK(sta_mac_boot_apply(&state, NULL) == STA_MAC_BOOT_APPLY_INVALID_ARGUMENT);
    callbacks.get_sta_mac = NULL;
    CHECK(sta_mac_boot_apply(&state, &callbacks) == STA_MAC_BOOT_APPLY_INVALID_ARGUMENT);
}

int main(void)
{
    test_factory_default();
    test_fixed_record();
    test_invalid_record();
    test_read_error_gate();
    test_random_per_boot();
    test_entropy_failure();
    test_set_next_boot();
    test_driver_failures();
    puts("PASS: STA MAC boot");
    return 0;
}
