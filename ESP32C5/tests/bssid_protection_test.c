#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bssid_protection.h"

static void test_contains_exact_bssid(void)
{
    const uint8_t protected_bssids[][6] = {
        {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90},
    };
    const uint8_t protected_target[6] = {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90};
    const uint8_t unknown_target[6] = {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x91};

    assert(bssid_protection_contains(&protected_bssids[0][0], 2, protected_target));
    assert(!bssid_protection_contains(&protected_bssids[0][0], 2, unknown_target));
    assert(!bssid_protection_contains(NULL, 2, protected_target));
    assert(!bssid_protection_contains(&protected_bssids[0][0], 2, NULL));
}

static void test_filter_keeps_only_unprotected_candidates(void)
{
    const uint8_t protected_bssids[][6] = {
        {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
    };
    const uint8_t candidates[][6] = {
        {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90},
        {0x78, 0x44, 0x76, 0xf1, 0xb0, 0x88},
    };
    size_t accepted[3] = {99, 99, 99};

    size_t count = bssid_protection_filter(&protected_bssids[0][0], 1,
                                           &candidates[0][0], 3,
                                           accepted, 3);

    assert(count == 2);
    assert(accepted[0] == 1);
    assert(accepted[1] == 2);
}

static void test_filter_returns_zero_when_every_candidate_is_protected(void)
{
    const uint8_t protected_bssids[][6] = {
        {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90},
    };
    const uint8_t candidates[][6] = {
        {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90},
        {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
    };
    size_t accepted[2] = {99, 99};

    size_t count = bssid_protection_filter(&protected_bssids[0][0], 2,
                                           &candidates[0][0], 2,
                                           accepted, 2);

    assert(count == 0);
}

static void test_parse_requires_one_complete_mac_address(void)
{
    uint8_t parsed[6] = {0};
    const uint8_t expected[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    assert(bssid_protection_parse("AA:BB:CC:DD:EE:FF", parsed));
    assert(memcmp(parsed, expected, sizeof(expected)) == 0);
    assert(bssid_protection_parse("aa-bb-cc-dd-ee-ff", parsed));
    assert(memcmp(parsed, expected, sizeof(expected)) == 0);
    assert(!bssid_protection_parse("AA:BB:CC:DD:EE", parsed));
    assert(!bssid_protection_parse("AA:BB:CC:DD:EE:FF trailing", parsed));
    assert(!bssid_protection_parse("01:00:5e:00:00:01", parsed));
    assert(!bssid_protection_parse("FF:FF:FF:FF:FF:FF", parsed));
}

static void test_add_deduplicates_and_remove_compacts(void)
{
    uint8_t entries[3][6] = {0};
    size_t count = 0;
    const uint8_t first[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    const uint8_t second[6] = {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90};

    assert(bssid_protection_add(&entries[0][0], &count, 3, first) ==
           BSSID_PROTECTION_ADDED);
    assert(count == 1);
    assert(bssid_protection_add(&entries[0][0], &count, 3, first) ==
           BSSID_PROTECTION_EXISTS);
    assert(count == 1);
    assert(bssid_protection_add(&entries[0][0], &count, 3, second) ==
           BSSID_PROTECTION_ADDED);
    assert(count == 2);

    assert(bssid_protection_remove(&entries[0][0], &count, first));
    assert(count == 1);
    assert(memcmp(entries[0], second, 6) == 0);
    assert(!bssid_protection_remove(&entries[0][0], &count, first));
    assert(count == 1);
}

static void test_add_refuses_capacity_overflow(void)
{
    uint8_t entries[1][6] = {0};
    size_t count = 0;
    const uint8_t first[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    const uint8_t second[6] = {0xb0, 0xbe, 0x76, 0x70, 0x0e, 0x90};

    assert(bssid_protection_add(&entries[0][0], &count, 1, first) ==
           BSSID_PROTECTION_ADDED);
    assert(bssid_protection_add(&entries[0][0], &count, 1, second) ==
           BSSID_PROTECTION_FULL);
    assert(count == 1);
}

int main(void)
{
    test_contains_exact_bssid();
    test_filter_keeps_only_unprotected_candidates();
    test_filter_returns_zero_when_every_candidate_is_protected();
    test_parse_requires_one_complete_mac_address();
    test_add_deduplicates_and_remove_compacts();
    test_add_refuses_capacity_overflow();
    puts("PASS: BSSID protection policy");
    return 0;
}
