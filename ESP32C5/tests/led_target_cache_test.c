#include "led_target_cache.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void first_sighting_only(void)
{
    led_target_cache_t cache = {0};
    const uint8_t first[6] = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};
    const uint8_t second[6] = {0x02, 0x01, 0x02, 0x03, 0x04, 0x06};
    assert(!led_target_cache_record(NULL, first));
    assert(!led_target_cache_record(&cache, NULL));
    assert(led_target_cache_record(&cache, first));
    assert(!led_target_cache_record(&cache, first));
    assert(led_target_cache_record(&cache, second));
    assert(!led_target_cache_record(&cache, second));
    led_target_cache_clear(&cache);
    assert(led_target_cache_record(&cache, first));
}

static void saturation_never_relabels_a_repeat_as_new(void)
{
    led_target_cache_t cache = {0};
    uint8_t bssid[6] = {0x02, 0, 0, 0, 0, 0};
    for (unsigned i = 0; i < LED_TARGET_CACHE_CAPACITY; ++i) {
        bssid[4] = (uint8_t)(i >> 8);
        bssid[5] = (uint8_t)i;
        assert(led_target_cache_record(&cache, bssid));
        assert(!led_target_cache_record(&cache, bssid));
    }
    bssid[4] = (uint8_t)(LED_TARGET_CACHE_CAPACITY >> 8);
    bssid[5] = (uint8_t)LED_TARGET_CACHE_CAPACITY;
    assert(!led_target_cache_record(&cache, bssid));

    bssid[4] = 0;
    bssid[5] = 0;
    assert(!led_target_cache_record(&cache, bssid));
    bssid[4] = (uint8_t)((LED_TARGET_CACHE_CAPACITY - 1U) >> 8);
    bssid[5] = (uint8_t)(LED_TARGET_CACHE_CAPACITY - 1U);
    assert(!led_target_cache_record(&cache, bssid));

    led_target_cache_clear(&cache);
    bssid[4] = (uint8_t)(LED_TARGET_CACHE_CAPACITY >> 8);
    bssid[5] = (uint8_t)LED_TARGET_CACHE_CAPACITY;
    assert(led_target_cache_record(&cache, bssid));
}

int main(void)
{
    first_sighting_only();
    saturation_never_relabels_a_repeat_as_new();
    puts("LED_TARGET_CACHE_PASS");
    return 0;
}
