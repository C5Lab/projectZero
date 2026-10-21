#include "sta_mac_policy_store.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static const uint8_t fixed_mac[6] = {0x02, 0xab, 0xcd, 0xef, 0x01, 0x23};

/* Catches mode/schema drift, struct serialization, and partial output on errors. */
static void test_records(void)
{
    const uint8_t expected[3][8] = {
        {1, 0, 0, 0, 0, 0, 0, 0},
        {1, 1, 0, 0, 0, 0, 0, 0},
        {1, 2, 2, 0xab, 0xcd, 0xef, 1, 0x23}
    };
    for (unsigned mode = 0; mode < 3; ++mode) {
        sta_mac_policy_record_t record = {1, (sta_mac_policy_mode_t)mode, {0}};
        memcpy(record.mac, fixed_mac, 6); /* unused MAC must be normalized */
        uint8_t bytes[8];
        CHECK(sta_mac_policy_validate(&record) == STA_MAC_POLICY_OK);
        CHECK(sta_mac_policy_encode(&record, bytes, sizeof(bytes)) == STA_MAC_POLICY_OK);
        CHECK(memcmp(bytes, expected[mode], 8) == 0);
        sta_mac_policy_record_t decoded = {0};
        CHECK(sta_mac_policy_decode(bytes, 8, &decoded) == STA_MAC_POLICY_OK);
        CHECK(decoded.version == 1 && decoded.mode == (sta_mac_policy_mode_t)mode);
        CHECK(memcmp(decoded.mac, expected[mode] + 2, 6) == 0);
        CHECK(sta_mac_policy_encode(&decoded, bytes, 8) == STA_MAC_POLICY_OK);
        CHECK(memcmp(bytes, expected[mode], 8) == 0);
    }
    uint8_t bytes[9] = {1, 0};
    sta_mac_policy_record_t out = {77, STA_MAC_MODE_FIXED, {9}};
    for (size_t length = 0; length < 10; ++length) {
        if (length == 8) continue;
        CHECK(sta_mac_policy_decode(bytes, length, &out) == STA_MAC_POLICY_WRONG_LENGTH);
        CHECK(out.version == 77 && out.mac[0] == 9);
    }
    bytes[0] = 2;
    CHECK(sta_mac_policy_decode(bytes, 8, &out) == STA_MAC_POLICY_UNSUPPORTED_VERSION);
    bytes[0] = 1; bytes[1] = 99;
    CHECK(sta_mac_policy_decode(bytes, 8, &out) == STA_MAC_POLICY_INVALID_MODE);
    bytes[1] = 2;
    CHECK(sta_mac_policy_decode(bytes, 8, &out) == STA_MAC_POLICY_INVALID_FIXED_MAC);
    bytes[1] = 0; bytes[2] = 2;
    CHECK(sta_mac_policy_decode(bytes, 8, &out) == STA_MAC_POLICY_INVALID_PAYLOAD);
    bytes[1] = 1;
    CHECK(sta_mac_policy_decode(bytes, 8, &out) == STA_MAC_POLICY_INVALID_PAYLOAD);
    CHECK(out.version == 77 && out.mac[0] == 9);
    CHECK(sta_mac_policy_decode(NULL, 8, &out) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_decode(bytes, 8, NULL) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_validate(NULL) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_encode(NULL, bytes, 8) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_encode(&out, NULL, 8) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_encode(&out, bytes, 7) == STA_MAC_POLICY_WRONG_LENGTH);
    CHECK(sta_mac_policy_validate(&out) == STA_MAC_POLICY_UNSUPPORTED_VERSION);
    out.version = 1; out.mode = (sta_mac_policy_mode_t)-1;
    CHECK(sta_mac_policy_validate(&out) == STA_MAC_POLICY_INVALID_MODE);
}

/* Catches permissive sscanf parsing and missing local/unicast validation. */
static void test_fixed(void)
{
    const char *bad[] = {"", "02", "2:ab:cd:ef:01:23", "002:ab:cd:ef:01:23",
        "02-ab-cd-ef-01-23", "02:ab-cd:ef:01:23", "02:ab:cd:ef:01:23 ",
        " 02:ab:cd:ef:01:23", "02:ab:cd:ef:01:23x", "0x02:ab:cd:ef:01:23",
        "02:ab:cd:ef:01", "02:ab:cd:ef:01:2g", "02:ab:cd:ef:01:23\n",
        "+2:ab:cd:ef:01:23", "02::ab:cd:ef:01:23"};
    uint8_t out[6] = {9,9,9,9,9,9};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        CHECK(sta_mac_fixed_parse(bad[i], out) == STA_MAC_POLICY_INVALID_TEXT);
        CHECK(out[0] == 9 && out[5] == 9);
    }
    CHECK(sta_mac_fixed_parse("02:aB:Cd:EF:01:23", out) == STA_MAC_POLICY_OK);
    CHECK(memcmp(out, fixed_mac, 6) == 0);
    const uint8_t invalid[][6] = {{0}, {255,255,255,255,255,255},
        {3,0,0,0,0,1}, {0,1,2,3,4,5}, {1,0,0,0,0,1}};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        CHECK(sta_mac_fixed_validate(invalid[i]) == STA_MAC_POLICY_INVALID_FIXED_MAC);
    CHECK(sta_mac_fixed_parse("00:01:02:03:04:05", out) == STA_MAC_POLICY_INVALID_FIXED_MAC);
    CHECK(memcmp(out, fixed_mac, 6) == 0);
    CHECK(sta_mac_fixed_validate(fixed_mac) == STA_MAC_POLICY_OK);
    CHECK(sta_mac_fixed_validate(NULL) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_fixed_parse(NULL, out) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_fixed_parse("02:ab:cd:ef:01:23", NULL) == STA_MAC_POLICY_INVALID_ARGUMENT);
}

static void test_random(void)
{
    uint8_t entropy[6] = {0,1,2,3,4,5}, out[6];
    static const uint8_t fixture_a[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fixture_b[6] = {0xfd, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    static const uint8_t expected_a[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t expected_b[6] = {0xfe, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint8_t deterministic_a[6], deterministic_b[6];
    CHECK(sta_mac_random_from_entropy(fixture_a, 6, deterministic_a) ==
          STA_MAC_POLICY_OK);
    CHECK(sta_mac_random_from_entropy(fixture_b, 6, deterministic_b) ==
          STA_MAC_POLICY_OK);
    CHECK(memcmp(deterministic_a, expected_a, 6) == 0);
    CHECK(memcmp(deterministic_b, expected_b, 6) == 0);
    CHECK(memcmp(deterministic_a, deterministic_b, 6) != 0);
    for (unsigned first = 0; first < 256; ++first) {
        entropy[0] = (uint8_t)first;
        CHECK(sta_mac_random_from_entropy(entropy, 6, out) == STA_MAC_POLICY_OK);
        CHECK((out[0] & 3u) == 2u);
        CHECK((out[0] & 0xfcu) == (first & 0xfcu));
        CHECK(memcmp(out+1, entropy+1, 5) == 0);
    }
    memset(entropy, 0, 6);
    CHECK(sta_mac_random_from_entropy(entropy, 6, entropy) == STA_MAC_POLICY_OK);
    CHECK(entropy[0] == 2 && entropy[5] == 0);
    memset(out, 9, 6);
    CHECK(sta_mac_random_from_entropy(NULL, 6, out) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_random_from_entropy(entropy, 6, NULL) == STA_MAC_POLICY_INVALID_ARGUMENT);
    CHECK(sta_mac_random_from_entropy(entropy, 5, out) == STA_MAC_POLICY_WRONG_LENGTH);
    CHECK(sta_mac_random_from_entropy(entropy, 7, out) == STA_MAC_POLICY_WRONG_LENGTH);
    CHECK(out[0] == 9 && out[5] == 9);
}

/* Real core is exercised through an injected I/O boundary. Trace assertions
 * protect actual core lifecycle/call ordering, including failure unwind. */
typedef struct {
    sta_mac_io_status_t opened, read, written, committed;
    sta_mac_store_access_t access;
    uint8_t bytes[16];
    size_t length;
    char trace[16];
    size_t calls;
} memory_store_t;

static void trace(memory_store_t *s, char c) { CHECK(s->calls < 15); s->trace[s->calls++] = c; s->trace[s->calls] = 0; }
static sta_mac_io_status_t open_store(void *context, sta_mac_store_access_t access, void **handle)
{ memory_store_t *s = context; trace(s, 'O'); s->access = access; *handle = s; return s->opened; }
static sta_mac_io_status_t read_store(void *handle, uint8_t *out, size_t capacity, size_t *length)
{ memory_store_t *s = handle; trace(s, 'R'); CHECK(capacity == 8); *length = s->length;
  if (s->read != STA_MAC_IO_OK) return s->read;
  if (s->length > capacity) return STA_MAC_IO_BUFFER_TOO_SMALL;
  memcpy(out, s->bytes, s->length); return STA_MAC_IO_OK; }
static sta_mac_io_status_t write_store(void *handle, const uint8_t *data, size_t length)
{ memory_store_t *s = handle; trace(s, 'W'); CHECK(length == 8);
  if (s->written == STA_MAC_IO_OK) { memcpy(s->bytes, data, length); s->length = length; }
  return s->written; }
static sta_mac_io_status_t commit_store(void *handle)
{ memory_store_t *s = handle; trace(s, 'C'); return s->committed; }
static void close_store(void *handle) { trace(handle, 'X'); }
static void reset(memory_store_t *s) { memset(s, 0, sizeof(*s)); s->length = 8; s->bytes[0] = 1; }

static void test_store(void)
{
    memory_store_t memory;
    sta_mac_policy_store_t store = {&memory, open_store, read_store, write_store, commit_store, close_store};
    sta_mac_policy_record_t record = {1, STA_MAC_MODE_FIXED, {2,0xab,0xcd,0xef,1,0x23}};
    sta_mac_policy_record_t out = {77, STA_MAC_MODE_FIXED, {9}};
    reset(&memory);
    CHECK(sta_mac_policy_load(&store, &out).status == STA_MAC_STORE_OK);
    CHECK(strcmp(memory.trace, "ORX") == 0 && memory.access == STA_MAC_STORE_READ_ONLY);
    CHECK(out.mode == STA_MAC_MODE_FACTORY);
    reset(&memory);
    CHECK(sta_mac_policy_save(&store, &record).status == STA_MAC_STORE_OK);
    CHECK(strcmp(memory.trace, "OWCX") == 0 && memory.access == STA_MAC_STORE_READ_WRITE);
    const uint8_t encoded[8] = {1,2,2,0xab,0xcd,0xef,1,0x23};
    CHECK(memcmp(memory.bytes, encoded, 8) == 0);
    memory.calls = 0; memory.trace[0] = 0;
    CHECK(sta_mac_policy_load(&store, &out).status == STA_MAC_STORE_OK);
    CHECK(out.mode == STA_MAC_MODE_FIXED && memcmp(out.mac, fixed_mac, 6) == 0);
    for (unsigned op = 0; op < 2; ++op) {
        reset(&memory); memory.opened = STA_MAC_IO_ERROR;
        CHECK((op ? sta_mac_policy_save(&store, &record) : sta_mac_policy_load(&store, &out)).status == STA_MAC_STORE_OPEN_FAILED);
        CHECK(strcmp(memory.trace, "O") == 0);
        reset(&memory); memory.opened = STA_MAC_IO_MISSING;
        CHECK((op ? sta_mac_policy_save(&store, &record) : sta_mac_policy_load(&store, &out)).status == STA_MAC_STORE_MISSING_NAMESPACE);
        CHECK(strcmp(memory.trace, "O") == 0);
    }
    reset(&memory); memory.read = STA_MAC_IO_ERROR;
    CHECK(sta_mac_policy_load(&store, &out).status == STA_MAC_STORE_READ_FAILED);
    CHECK(strcmp(memory.trace, "ORX") == 0);
    reset(&memory); memory.read = STA_MAC_IO_MISSING;
    CHECK(sta_mac_policy_load(&store, &out).status == STA_MAC_STORE_MISSING_KEY);
    CHECK(strcmp(memory.trace, "ORX") == 0);
    reset(&memory); memory.written = STA_MAC_IO_ERROR;
    CHECK(sta_mac_policy_save(&store, &record).status == STA_MAC_STORE_WRITE_FAILED);
    CHECK(strcmp(memory.trace, "OWX") == 0);
    reset(&memory); memory.committed = STA_MAC_IO_ERROR;
    CHECK(sta_mac_policy_save(&store, &record).status == STA_MAC_STORE_COMMIT_FAILED);
    CHECK(strcmp(memory.trace, "OWCX") == 0);
    for (size_t length = 0; length < 17; ++length) {
        if (length == 8) continue;
        reset(&memory); memory.length = length;
        out.version = 77;
        sta_mac_store_result_t result = sta_mac_policy_load(&store, &out);
        CHECK(result.status == STA_MAC_STORE_INVALID_RECORD && result.policy_status == STA_MAC_POLICY_WRONG_LENGTH);
        CHECK(strcmp(memory.trace, "ORX") == 0 && out.version == 77);
    }
    const uint8_t corrupt[][8] = {{2,0}, {1,99}, {1,2}, {1,1,2}};
    const sta_mac_policy_status_t errors[] = {STA_MAC_POLICY_UNSUPPORTED_VERSION, STA_MAC_POLICY_INVALID_MODE,
        STA_MAC_POLICY_INVALID_FIXED_MAC, STA_MAC_POLICY_INVALID_PAYLOAD};
    for (size_t i = 0; i < 4; ++i) {
        reset(&memory); memcpy(memory.bytes, corrupt[i], 8);
        sta_mac_store_result_t result = sta_mac_policy_load(&store, &out);
        CHECK(result.status == STA_MAC_STORE_INVALID_RECORD && result.policy_status == errors[i]);
        CHECK(strcmp(memory.trace, "ORX") == 0 && out.version == 77);
    }
    for (unsigned i = 0; i < 3; ++i) {
        reset(&memory);
        sta_mac_policy_record_t invalid = record;
        if (i == 0) invalid.version = 2;
        if (i == 1) invalid.mode = (sta_mac_policy_mode_t)99;
        if (i == 2) invalid.mac[0] = 0;
        CHECK(sta_mac_policy_save(&store, &invalid).status == STA_MAC_STORE_INVALID_RECORD);
        CHECK(memory.calls == 0);
    }
    reset(&memory);
    CHECK(sta_mac_policy_load(NULL, &out).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_save(NULL, &record).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_load(&store, NULL).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_save(&store, NULL).status == STA_MAC_STORE_INVALID_ARGUMENT);
    sta_mac_policy_store_t invalid = store;
    invalid.close = NULL;
    CHECK(sta_mac_policy_load(&invalid, &out).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_save(&invalid, &record).status == STA_MAC_STORE_INVALID_ARGUMENT);
    invalid = store; invalid.open = NULL;
    CHECK(sta_mac_policy_load(&invalid, &out).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(sta_mac_policy_save(&invalid, &record).status == STA_MAC_STORE_INVALID_ARGUMENT);
    invalid = store; invalid.read = NULL;
    CHECK(sta_mac_policy_load(&invalid, &out).status == STA_MAC_STORE_INVALID_ARGUMENT);
    invalid = store; invalid.write = NULL;
    CHECK(sta_mac_policy_save(&invalid, &record).status == STA_MAC_STORE_INVALID_ARGUMENT);
    invalid = store; invalid.commit = NULL;
    CHECK(sta_mac_policy_save(&invalid, &record).status == STA_MAC_STORE_INVALID_ARGUMENT);
    CHECK(memory.calls == 0);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (strcmp(argv[1], "records") == 0) test_records();
    else if (strcmp(argv[1], "fixed") == 0) test_fixed();
    else if (strcmp(argv[1], "random") == 0) test_random();
    else if (strcmp(argv[1], "store") == 0) test_store();
    else CHECK(0);
    puts("PASS: STA MAC policy/storage");
    return 0;
}
