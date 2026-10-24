#ifndef JANOS_LED_TARGET_CACHE_H
#define JANOS_LED_TARGET_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#define LED_TARGET_CACHE_CAPACITY 128U

/* Zero initialization is a valid empty cache. Caller serializes concurrent access. */
typedef struct {
    uint8_t entries[LED_TARGET_CACHE_CAPACITY][6];
    uint16_t count;
} led_target_cache_t;

/* No eviction: a full cache suppresses unknown BSSIDs as well as repeats. */
bool led_target_cache_record(led_target_cache_t *cache, const uint8_t bssid[6]);
void led_target_cache_clear(led_target_cache_t *cache);

#endif
