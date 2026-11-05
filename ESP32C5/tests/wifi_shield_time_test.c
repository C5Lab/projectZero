#include "wifi_shield_time.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t bssid[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t other[6] = {0x02, 1, 2, 3, 4, 6};

static void assert_none(const wifi_shield_time_stamp_t *stamp, uint64_t boot_us)
{
    assert(stamp->boot_us == boot_us);
    assert(stamp->quality == WIFI_SHIELD_TIME_NONE);
    assert(stamp->ap_tsf_us == 0);
    assert(stamp->ap_epoch == 0);
    assert(stamp->uncertainty_us == 0);
}

/* Catches wrong interpolation, stale reuse and failure to start a reset epoch. */
static void test_required_scenario(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    bool reset = true;
    wifi_shield_time_init(&core, UINT64_C(2000000));
    assert(wifi_shield_time_observe_anchor(&core, bssid, 1000000, 5000000, &reset));
    assert(!reset);
    assert(wifi_shield_time_resolve(&core, bssid, 5000100, &stamp));
    assert(stamp.quality == WIFI_SHIELD_TIME_ESTIMATED);
    assert(stamp.ap_tsf_us == 1000100 && stamp.uncertainty_us == 100);
    assert(stamp.boot_us == 5000100 && stamp.ap_epoch == 1);
    assert(wifi_shield_time_resolve(&core, bssid, 7000000, &stamp));
    assert(stamp.ap_tsf_us == 3000000 && stamp.uncertainty_us == 2000000);
    assert(!wifi_shield_time_resolve(&core, bssid, 8000001, &stamp));
    assert_none(&stamp, 8000001);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 50, 8000100, &reset));
    assert(reset);
    assert(wifi_shield_time_exact(&core, bssid, 50, 8000100, &stamp));
    assert(stamp.ap_epoch == 2 && stamp.quality == WIFI_SHIELD_TIME_EXACT);
    assert(stamp.boot_us == 8000100 && stamp.ap_tsf_us == 50);
    assert(stamp.uncertainty_us == 0);
}

/* Catches an exact path that forgets to refresh or mixes separate AP anchors. */
static void test_exact_refresh_and_independence(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    wifi_shield_time_init(&core, 100);
    assert(wifi_shield_time_exact(&core, bssid, 0, 500, &stamp));
    assert(stamp.quality == WIFI_SHIELD_TIME_EXACT && stamp.ap_epoch == 1);
    assert(stamp.ap_tsf_us == 0 && stamp.boot_us == 500 && stamp.uncertainty_us == 0);
    assert(wifi_shield_time_exact(&core, other, 9000, 500, &stamp));
    assert(wifi_shield_time_exact(&core, bssid, 150, 650, &stamp));
    assert(stamp.ap_epoch == 1 && stamp.ap_tsf_us == 150);
    assert(wifi_shield_time_resolve(&core, bssid, 750, &stamp));
    assert(stamp.ap_tsf_us == 250 && stamp.uncertainty_us == 100);
    assert(wifi_shield_time_resolve(&core, other, 600, &stamp));
    assert(stamp.ap_tsf_us == 9100 && stamp.ap_epoch == 1);
}

/* Catches underflow on backward boot time and mutation by rejected input. */
static void test_unknown_and_backward_boot(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    bool reset = true;
    wifi_shield_time_init(&core, 1000);
    memset(&stamp, 0xff, sizeof(stamp));
    assert(!wifi_shield_time_resolve(&core, bssid, 900, &stamp));
    assert_none(&stamp, 900);
    assert(wifi_shield_time_exact(&core, bssid, 100, 1000, &stamp));
    assert(!wifi_shield_time_resolve(&core, bssid, 999, &stamp));
    assert_none(&stamp, 999);
    assert(!wifi_shield_time_observe_anchor(&core, bssid, 1, 999, &reset));
    assert(!reset);
    assert(!wifi_shield_time_exact(&core, bssid, 200, 999, &stamp));
    assert_none(&stamp, 999);
    assert(wifi_shield_time_resolve(&core, bssid, 1001, &stamp));
    assert(stamp.ap_tsf_us == 101 && stamp.ap_epoch == 1);
    assert(!wifi_shield_time_resolve(&core, other, 1001, &stamp));
    assert_none(&stamp, 1001);
}

/* Catches wrapping TSF addition and unsafe signed discontinuity arithmetic. */
static void test_saturation_and_extreme_deltas(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    bool reset;
    wifi_shield_time_init(&core, UINT64_MAX);
    assert(wifi_shield_time_exact(&core, bssid, UINT64_MAX - 5, 10, &stamp));
    assert(wifi_shield_time_resolve(&core, bssid, 16, &stamp));
    assert(stamp.ap_tsf_us == UINT64_MAX && stamp.uncertainty_us == 6);
    assert(wifi_shield_time_resolve(&core, bssid, UINT64_MAX, &stamp));
    assert(stamp.ap_tsf_us == UINT64_MAX && stamp.uncertainty_us == UINT64_MAX - 10);
    wifi_shield_time_init(&core, UINT64_MAX);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 0, 0, &reset));
    assert(wifi_shield_time_observe_anchor(&core, bssid, UINT64_MAX, 1, &reset));
    assert(reset);
    assert(wifi_shield_time_exact(&core, bssid, UINT64_MAX, 1, &stamp));
    assert(stamp.ap_epoch == 2);
    wifi_shield_time_init(&core, UINT64_MAX);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 0, 0, &reset));
    assert(wifi_shield_time_observe_anchor(&core, bssid, 1, UINT64_MAX, &reset));
    assert(reset);
}

/* Catches >= instead of > at 5 s, either drift direction and TSF reset. */
static void test_discontinuities(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    bool reset;
    wifi_shield_time_init(&core, UINT64_MAX);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 100, 100, &reset));
    assert(wifi_shield_time_observe_anchor(&core, bssid, 5000200, 200, &reset));
    assert(!reset);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 10000301, 300, &reset));
    assert(reset);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 10000401, 5000400, &reset));
    assert(!reset);
    assert(wifi_shield_time_observe_anchor(&core, bssid, 10000501, 10000501, &reset));
    assert(reset);
    assert(wifi_shield_time_exact(&core, bssid, 1, 10000501, &stamp));
    assert(stamp.ap_epoch == 4 && stamp.quality == WIFI_SHIELD_TIME_EXACT);
    assert(stamp.ap_tsf_us == 1 && stamp.uncertainty_us == 0);
}

/* Catches eviction, off-by-one capacity and inability to refresh a full table. */
static void test_fixed_capacity(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    uint8_t address[6] = {0x02, 0, 0, 0, 0, 0};
    bool reset = true;
    wifi_shield_time_init(&core, 100);
    for (size_t i = 0; i < WIFI_SHIELD_TIME_MAX_TARGETS; ++i) {
        address[4] = (uint8_t)(i >> 8);
        address[5] = (uint8_t)i;
        assert(wifi_shield_time_observe_anchor(&core, address, 100, 1000, &reset));
        assert(!reset);
    }
    assert(!wifi_shield_time_observe_anchor(&core, bssid, 100, 1000, &reset));
    assert(!reset);
    assert(!wifi_shield_time_exact(&core, bssid, 100, 1000, &stamp));
    assert_none(&stamp, 1000);
    for (size_t i = 0; i < WIFI_SHIELD_TIME_MAX_TARGETS; ++i) {
        address[4] = (uint8_t)(i >> 8);
        address[5] = (uint8_t)i;
        assert(wifi_shield_time_exact(&core, address, 101, 1001, &stamp));
        assert(stamp.ap_epoch == 1);
    }
}

static void test_zero_age_and_invalid_arguments(void)
{
    wifi_shield_time_core_t core;
    wifi_shield_time_stamp_t stamp;
    bool reset = true;
    wifi_shield_time_init(NULL, 0);
    wifi_shield_time_init(&core, 0);
    assert(!wifi_shield_time_observe_anchor(NULL, bssid, 0, 0, &reset));
    assert(!reset);
    assert(!wifi_shield_time_observe_anchor(&core, NULL, 0, 0, &reset));
    assert(!wifi_shield_time_exact(&core, bssid, 0, 0, NULL));
    assert(!wifi_shield_time_resolve(&core, bssid, 0, &stamp));
    assert(wifi_shield_time_observe_anchor(&core, bssid, 0, 0, NULL));
    assert(wifi_shield_time_resolve(&core, bssid, 0, &stamp));
    assert(stamp.quality == WIFI_SHIELD_TIME_ESTIMATED && stamp.uncertainty_us == 0);
    assert(!wifi_shield_time_resolve(&core, bssid, 1, &stamp));
    assert_none(&stamp, 1);
    assert(!wifi_shield_time_resolve(NULL, bssid, 2, &stamp));
    assert_none(&stamp, 2);
    assert(!wifi_shield_time_resolve(&core, NULL, 3, &stamp));
    assert_none(&stamp, 3);
    assert(!wifi_shield_time_resolve(&core, bssid, 0, NULL));
    assert(!wifi_shield_time_exact(NULL, bssid, 0, 4, &stamp));
    assert_none(&stamp, 4);
    assert(!wifi_shield_time_exact(&core, NULL, 0, 5, &stamp));
    assert_none(&stamp, 5);
}

int main(void)
{
    test_required_scenario();
    test_exact_refresh_and_independence();
    test_unknown_and_backward_boot();
    test_saturation_and_extreme_deltas();
    test_discontinuities();
    test_fixed_capacity();
    test_zero_age_and_invalid_arguments();
    puts("wifi shield time: PASS");
    return 0;
}
