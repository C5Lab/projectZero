#ifndef DEAUTH_TARGET_CORE_H
#define DEAUTH_TARGET_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEAUTH_TARGET_MAX 64

typedef struct {
    uint8_t bssid[DEAUTH_TARGET_MAX][6];
    size_t count;
} deauth_target_filter_t;

bool deauth_target_parse_index(const char *arg, size_t scan_count, size_t *zero_index);
bool deauth_target_add(deauth_target_filter_t *filter, const uint8_t bssid[6]);
bool deauth_target_contains(const deauth_target_filter_t *filter, const uint8_t bssid[6]);

#endif
