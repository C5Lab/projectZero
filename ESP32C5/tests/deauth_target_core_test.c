#include "deauth_target_core.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_indices(void)
{
    size_t index = 99;
    assert(deauth_target_parse_index("1", 64, &index) && index == 0);
    assert(deauth_target_parse_index("64", 64, &index) && index == 63);
    assert(deauth_target_parse_index("001", 64, &index) && index == 0);
    assert(!deauth_target_parse_index("65", 64, &index));
    assert(!deauth_target_parse_index("1", 0, &index));
    assert(!deauth_target_parse_index("0", 64, &index));
    assert(!deauth_target_parse_index("", 64, &index));
    assert(!deauth_target_parse_index("+1", 64, &index));
    assert(!deauth_target_parse_index("-1", 64, &index));
    assert(!deauth_target_parse_index(" 1", 64, &index));
    assert(!deauth_target_parse_index("1 ", 64, &index));
    assert(!deauth_target_parse_index("1x", 64, &index));
    assert(!deauth_target_parse_index("999999999999999999999999999999999", 64, &index));
    assert(!deauth_target_parse_index(NULL, 64, &index));
    assert(!deauth_target_parse_index("1", 64, NULL));
}

static void test_multiple_exact_bssids(void)
{
    const uint8_t first[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t second[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x56};
    const uint8_t unrelated[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x57};
    deauth_target_filter_t filter = {0};
    assert(!deauth_target_contains(&filter, first));
    assert(deauth_target_add(&filter, first));
    assert(filter.count == 1);
    assert(deauth_target_contains(&filter, first));
    assert(!deauth_target_contains(&filter, second));
    assert(deauth_target_add(&filter, second));
    assert(filter.count == 2);
    assert(deauth_target_contains(&filter, second));
    assert(!deauth_target_contains(&filter, unrelated));
    assert(deauth_target_add(&filter, first));
    assert(filter.count == 2);
    assert(!deauth_target_add(NULL, first));
    assert(!deauth_target_add(&filter, NULL));
    assert(!deauth_target_contains(NULL, first));
    assert(!deauth_target_contains(&filter, NULL));
}

static void test_capacity_and_duplicate_at_capacity(void)
{
    deauth_target_filter_t filter = {0};
    for (size_t i = 0; i < DEAUTH_TARGET_MAX; ++i) {
        uint8_t bssid[6] = {0x02, 0, 0, 0, 0, (uint8_t)i};
        assert(deauth_target_add(&filter, bssid));
    }
    assert(filter.count == DEAUTH_TARGET_MAX);
    const uint8_t existing[6] = {0x02, 0, 0, 0, 0, 0};
    const uint8_t extra[6] = {0x02, 0, 0, 0, 0, 64};
    assert(deauth_target_add(&filter, existing));
    assert(filter.count == DEAUTH_TARGET_MAX);
    assert(!deauth_target_add(&filter, extra));
    assert(!deauth_target_contains(&filter, extra));
}

int main(void)
{
    test_indices();
    test_multiple_exact_bssids();
    test_capacity_and_duplicate_at_capacity();
    puts("deauth target core: PASS");
    return 0;
}
