#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSSID_PROTECTION_ADDRESS_LEN 6U

typedef enum {
    BSSID_PROTECTION_ADDED = 0,
    BSSID_PROTECTION_EXISTS,
    BSSID_PROTECTION_FULL,
    BSSID_PROTECTION_INVALID,
} bssid_protection_add_result_t;

bool bssid_protection_parse(const char *text,
                            uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN]);

bool bssid_protection_contains(const uint8_t *protected_bssids,
                               size_t protected_count,
                               const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN]);

size_t bssid_protection_filter(const uint8_t *protected_bssids,
                               size_t protected_count,
                               const uint8_t *candidate_bssids,
                               size_t candidate_count,
                               size_t *accepted_indices,
                               size_t accepted_capacity);

bssid_protection_add_result_t bssid_protection_add(
    uint8_t *protected_bssids,
    size_t *protected_count,
    size_t protected_capacity,
    const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN]);

bool bssid_protection_remove(uint8_t *protected_bssids,
                             size_t *protected_count,
                             const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN]);

#ifdef __cplusplus
}
#endif
