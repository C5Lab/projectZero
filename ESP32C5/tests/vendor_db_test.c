#include "vendor_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int allocations;
    int frees;
    int fail_after;
} alloc_state_t;

static void *test_alloc(size_t bytes, void *opaque)
{
    alloc_state_t *state = (alloc_state_t *)opaque;
    if (state->fail_after >= 0 && state->allocations >= state->fail_after) {
        return NULL;
    }
    void *pointer = malloc(bytes);
    if (pointer != NULL) {
        state->allocations++;
    }
    return pointer;
}

static void test_free(void *pointer, void *opaque)
{
    alloc_state_t *state = (alloc_state_t *)opaque;
    if (pointer != NULL) {
        state->frees++;
        free(pointer);
    }
}

static int fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    return 1;
}

static vendor_db_t *open_db(const char *path, alloc_state_t *state)
{
    vendor_db_result_t result = VENDOR_DB_FORMAT_ERROR;
    vendor_db_t *db = vendor_db_open(path, test_alloc, test_free, state, &result);
    if (db == NULL || result != VENDOR_DB_OK) {
        fprintf(stderr, "open failed: %d\n", (int)result);
        return NULL;
    }
    return db;
}

static int expect_lookup(vendor_db_t *db, const uint8_t mac[6],
                         vendor_db_result_t expected_result,
                         const char *expected_name, uint8_t expected_bits)
{
    char name[64] = "unchanged";
    uint8_t bits = 0xff;
    vendor_db_result_t result = vendor_db_lookup(db, mac, name, sizeof(name), &bits);
    if (result != expected_result) {
        fprintf(stderr, "lookup result %d != %d\n", (int)result, (int)expected_result);
        return 1;
    }
    if (result == VENDOR_DB_OK &&
        (strcmp(name, expected_name) != 0 || bits != expected_bits)) {
        fprintf(stderr, "lookup got name='%s' bits=%u\n", name, (unsigned)bits);
        return 1;
    }
    return 0;
}

static int lookup_case(const char *path, int fail_after)
{
    alloc_state_t state = { .allocations = 0, .frees = 0, .fail_after = fail_after };
    vendor_db_t *db = open_db(path, &state);
    if (db == NULL) {
        return 1;
    }
    if (fail_after < 0 && state.allocations < 2) {
        vendor_db_close(db);
        return fail("index cache was not allocated");
    }
    if (fail_after == 1 && state.allocations != 1) {
        vendor_db_close(db);
        return fail("direct-file fallback did not follow cache allocation failure");
    }
    const uint8_t exact36[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const uint8_t exact28[6] = { 0x00, 0x11, 0x22, 0x3f, 0x44, 0x55 };
    const uint8_t exact24[6] = { 0x00, 0x11, 0x22, 0xaf, 0x44, 0x55 };
    const uint8_t missing[6] = { 0x00, 0x11, 0x23, 0x00, 0x00, 0x00 };
    const uint8_t random_mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    int status = 0;
    status |= expect_lookup(db, exact36, VENDOR_DB_OK, "Vendor Thirty Six", 36);
    status |= expect_lookup(db, exact28, VENDOR_DB_OK, "Vendor Twenty Eight", 28);
    status |= expect_lookup(db, exact24, VENDOR_DB_OK, "Vendor Twenty Four", 24);
    status |= expect_lookup(db, missing, VENDOR_DB_NOT_FOUND, "", 0);
    status |= expect_lookup(db, random_mac, VENDOR_DB_RANDOM_MAC, "", 0);
    if (vendor_db_lookup(db, exact24, NULL, 0, NULL) != VENDOR_DB_FORMAT_ERROR) {
        status |= fail("zero-sized output was not rejected");
    }
    vendor_db_close(db);
    if (state.allocations != state.frees) {
        status |= fail("allocation/free mismatch");
    }
    return status;
}

static int open_result_case(const char *path, vendor_db_result_t expected)
{
    alloc_state_t state = { .allocations = 0, .frees = 0, .fail_after = -1 };
    vendor_db_result_t result = VENDOR_DB_OK;
    vendor_db_t *db = vendor_db_open(path, test_alloc, test_free, &state, &result);
    if (db != NULL) {
        vendor_db_close(db);
    }
    if (result != expected) {
        fprintf(stderr, "open result %d != %d\n", (int)result, (int)expected);
        return 1;
    }
    if (state.allocations != state.frees) {
        return fail("partial open leaked memory");
    }
    return 0;
}

static int reopen_case(const char *path)
{
    alloc_state_t state = { .allocations = 0, .frees = 0, .fail_after = -1 };
    for (int index = 0; index < 2; index++) {
        vendor_db_t *db = open_db(path, &state);
        if (db == NULL) {
            return 1;
        }
        vendor_db_close(db);
    }
    return state.allocations == state.frees ? 0 : fail("reopen leaked memory");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        return fail("usage: vendor_db_test CASE PATH [EXPECTED]");
    }
    if (strcmp(argv[1], "cached") == 0) {
        return lookup_case(argv[2], -1);
    }
    if (strcmp(argv[1], "fallback") == 0) {
        return lookup_case(argv[2], 1);
    }
    if (strcmp(argv[1], "reopen") == 0) {
        return reopen_case(argv[2]);
    }
    if (strcmp(argv[1], "no_memory") == 0) {
        alloc_state_t state = { .allocations = 0, .frees = 0, .fail_after = 0 };
        vendor_db_result_t result = VENDOR_DB_OK;
        vendor_db_t *db = vendor_db_open(argv[2], test_alloc, test_free, &state, &result);
        if (db != NULL || result != VENDOR_DB_NO_MEMORY) {
            return fail("handle allocation failure was not reported");
        }
        return 0;
    }
    if (strcmp(argv[1], "open_result") == 0 && argc == 4) {
        return open_result_case(argv[2], (vendor_db_result_t)atoi(argv[3]));
    }
    return fail("unknown case");
}
