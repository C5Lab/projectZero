#include "led_target_cache.h"

#include <stddef.h>
#include <string.h>

bool led_target_cache_record(led_target_cache_t *cache, const uint8_t bssid[6])
{
    if (cache == NULL || bssid == NULL) {
        return false;
    }
    for (uint16_t i = 0; i < cache->count; ++i) {
        if (memcmp(cache->entries[i], bssid, 6) == 0) {
            return false;
        }
    }
    if (cache->count >= LED_TARGET_CACHE_CAPACITY) {
        return false;
    }
    memcpy(cache->entries[cache->count], bssid, 6);
    ++cache->count;
    return true;
}

void led_target_cache_clear(led_target_cache_t *cache)
{
    if (cache != NULL) {
        cache->count = 0;
    }
}
