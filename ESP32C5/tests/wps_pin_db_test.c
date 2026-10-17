#include "wps_pin_db.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int allocations; int frees; int fail_after; } alloc_state_t;

static void *test_alloc(size_t size, void *opaque)
{
    alloc_state_t *state = opaque;
    if (state->fail_after >= 0 && state->allocations >= state->fail_after) return NULL;
    void *pointer = malloc(size);
    if (pointer != NULL) state->allocations++;
    return pointer;
}

static void test_free(void *pointer, void *opaque)
{
    alloc_state_t *state = opaque;
    if (pointer != NULL) { state->frees++; free(pointer); }
}

static wps_pin_db_t *open_db(const char *path, alloc_state_t *state)
{
    wps_pin_db_result_t result = WPS_PIN_DB_FORMAT_ERROR;
    wps_pin_db_t *db = wps_pin_db_open(path, test_alloc, test_free, state, &result);
    assert(db != NULL && result == WPS_PIN_DB_OK);
    return db;
}

static void test_rank(const char *path, int fail_after, bool expect_literal_invalid)
{
    alloc_state_t state = {0, 0, fail_after};
    wps_pin_db_t *db = open_db(path, &state);
    const uint8_t bssid[6] = {0x00, 0xaa, 0xbb, 0x33, 0x44, 0x55};
    wps_pin_candidate_t output[128];
    wps_pin_query_stats_t stats;
    size_t count = wps_pin_db_candidates(db, bssid, "WLAN_ABCD", "TP-Link",
                                         "DIR-TEST", "00000000", output, 128, &stats);
    assert(count > 5);
    assert(output[0].pin8 == 0U && output[0].source == WPS_PIN_SOURCE_EXPLICIT);
    assert(output[1].pin8 == 12345670U && output[1].source == WPS_PIN_SOURCE_MODEL);
    assert(stats.duplicates_removed >= 2);
    assert(stats.unsupported_algorithms == 0);
    assert(!stats.truncated);
    bool found_literal_invalid = false;
    bool found_leading_zero_invalid = false;
    bool found_upper_bound_invalid = false;
    bool found_model_invalid = false, found_vendor_invalid = false;
    bool found_ssid_invalid = false;
    for (size_t left = 0; left < count; left++) {
        if (output[left].pin8 == 12345678U &&
            output[left].source == WPS_PIN_SOURCE_OUI_STATIC)
            found_literal_invalid = true;
        if (output[left].pin8 == 1U &&
            output[left].source == WPS_PIN_SOURCE_COMMON)
            found_leading_zero_invalid = true;
        if (output[left].pin8 == 99999999U &&
            output[left].source == WPS_PIN_SOURCE_COMMON)
            found_upper_bound_invalid = true;
        if (output[left].pin8 == 11111111U &&
            output[left].source == WPS_PIN_SOURCE_MODEL)
            found_model_invalid = true;
        if (output[left].pin8 == 22222222U &&
            output[left].source == WPS_PIN_SOURCE_VENDOR)
            found_vendor_invalid = true;
        if (output[left].pin8 == 33333333U &&
            output[left].source == WPS_PIN_SOURCE_SSID)
            found_ssid_invalid = true;
        for (size_t right = left + 1; right < count; right++) {
            assert(output[left].pin8 != output[right].pin8);
        }
    }
    assert(found_literal_invalid == expect_literal_invalid);
    assert(found_leading_zero_invalid == expect_literal_invalid);
    assert(found_upper_bound_invalid == expect_literal_invalid);
    assert(found_model_invalid == expect_literal_invalid);
    assert(found_vendor_invalid == expect_literal_invalid);
    assert(found_ssid_invalid == expect_literal_invalid);
    wps_pin_db_close(db);
    assert(state.allocations == state.frees);
}

static void test_ssid_rules(const char *path)
{
    const char *ssids[] = {"WLAN_ABCD", "JAZZTEL_AB", "MOVISTAR_12AF",
                           "Dlink_BEEF", "Vodafone1234", "Orange-CAFE"};
    const uint8_t bssid[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    alloc_state_t state = {0, 0, -1};
    wps_pin_db_t *db = open_db(path, &state);
    for (size_t index = 0; index < 6; index++) {
        wps_pin_candidate_t output[128];
        size_t count = wps_pin_db_candidates(db, bssid, ssids[index], NULL, NULL,
                                             NULL, output, 128, NULL);
        assert(count > 0);
        assert(output[0].source == WPS_PIN_SOURCE_SSID);
        assert(output[0].detail_id == index + 1);
    }
    wps_pin_db_close(db);
    assert(state.allocations == state.frees);
}

static void test_explicit_without_database(void)
{
    const uint8_t bssid[6] = {0};
    wps_pin_candidate_t output[1];
    size_t count = wps_pin_db_candidates(NULL, bssid, NULL, NULL, NULL,
                                         "00000000", output, 1, NULL);
    assert(count == 1 && output[0].pin8 == 0U && output[0].source == WPS_PIN_SOURCE_EXPLICIT);
    assert(wps_pin_db_candidates(NULL, bssid, NULL, NULL, NULL,
                                 "12345678", output, 1, NULL) == 0);
}

int main(int argc, char **argv)
{
    assert(argc >= 3);
    if (strcmp(argv[1], "rank-v1") == 0 || strcmp(argv[1], "rank-v2") == 0) {
        bool expect_literal_invalid = strcmp(argv[1], "rank-v2") == 0;
        test_rank(argv[2], -1, expect_literal_invalid);
        test_rank(argv[2], 1, expect_literal_invalid);
        test_ssid_rules(argv[2]);
        test_explicit_without_database();
        return 0;
    }
    if (strcmp(argv[1], "open") == 0) {
        assert(argc == 4);
        alloc_state_t state = {0, 0, -1};
        wps_pin_db_result_t result = WPS_PIN_DB_OK;
        wps_pin_db_t *db = wps_pin_db_open(argv[2], test_alloc, test_free, &state, &result);
        if (db != NULL) wps_pin_db_close(db);
        int expected = atoi(argv[3]);
        assert((int)result == expected);
        assert(state.allocations == state.frees);
        return 0;
    }
    return 2;
}
