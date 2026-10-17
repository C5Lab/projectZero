#include "bssid_protection.h"

#include <string.h>

static int bssid_hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool bssid_protection_parse(const char *text,
                            uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN])
{
    if (text == NULL || bssid == NULL || strlen(text) != 17U) return false;
    char separator = text[2];
    if (separator != ':' && separator != '-') return false;

    for (size_t i = 0; i < BSSID_PROTECTION_ADDRESS_LEN; ++i) {
        size_t offset = i * 3U;
        int high = bssid_hex_value(text[offset]);
        int low = bssid_hex_value(text[offset + 1U]);
        if (high < 0 || low < 0) return false;
        if (i + 1U < BSSID_PROTECTION_ADDRESS_LEN &&
            text[offset + 2U] != separator) return false;
        bssid[i] = (uint8_t)((high << 4) | low);
    }

    /* Broadcast and group addresses can never identify an AP BSSID. */
    if ((bssid[0] & 0x01U) != 0U) return false;
    return true;
}

bool bssid_protection_contains(const uint8_t *protected_bssids,
                               size_t protected_count,
                               const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN])
{
    if (protected_bssids == NULL || bssid == NULL) {
        return false;
    }

    for (size_t i = 0; i < protected_count; ++i) {
        const uint8_t *entry = protected_bssids + (i * BSSID_PROTECTION_ADDRESS_LEN);
        if (memcmp(entry, bssid, BSSID_PROTECTION_ADDRESS_LEN) == 0) {
            return true;
        }
    }

    return false;
}

size_t bssid_protection_filter(const uint8_t *protected_bssids,
                               size_t protected_count,
                               const uint8_t *candidate_bssids,
                               size_t candidate_count,
                               size_t *accepted_indices,
                               size_t accepted_capacity)
{
    if (candidate_bssids == NULL || accepted_indices == NULL || accepted_capacity == 0) {
        return 0;
    }

    size_t accepted_count = 0;
    for (size_t i = 0; i < candidate_count && accepted_count < accepted_capacity; ++i) {
        const uint8_t *candidate = candidate_bssids + (i * BSSID_PROTECTION_ADDRESS_LEN);
        if (!bssid_protection_contains(protected_bssids, protected_count, candidate)) {
            accepted_indices[accepted_count++] = i;
        }
    }

    return accepted_count;
}

bssid_protection_add_result_t bssid_protection_add(
    uint8_t *protected_bssids,
    size_t *protected_count,
    size_t protected_capacity,
    const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN])
{
    if (protected_bssids == NULL || protected_count == NULL || bssid == NULL ||
        *protected_count > protected_capacity) return BSSID_PROTECTION_INVALID;
    if (bssid_protection_contains(protected_bssids, *protected_count, bssid))
        return BSSID_PROTECTION_EXISTS;
    if (*protected_count == protected_capacity) return BSSID_PROTECTION_FULL;

    memcpy(protected_bssids + (*protected_count * BSSID_PROTECTION_ADDRESS_LEN),
           bssid, BSSID_PROTECTION_ADDRESS_LEN);
    ++(*protected_count);
    return BSSID_PROTECTION_ADDED;
}

bool bssid_protection_remove(uint8_t *protected_bssids,
                             size_t *protected_count,
                             const uint8_t bssid[BSSID_PROTECTION_ADDRESS_LEN])
{
    if (protected_bssids == NULL || protected_count == NULL || bssid == NULL)
        return false;

    for (size_t i = 0; i < *protected_count; ++i) {
        uint8_t *entry = protected_bssids + (i * BSSID_PROTECTION_ADDRESS_LEN);
        if (memcmp(entry, bssid, BSSID_PROTECTION_ADDRESS_LEN) != 0) continue;
        size_t trailing = *protected_count - i - 1U;
        if (trailing > 0) {
            memmove(entry, entry + BSSID_PROTECTION_ADDRESS_LEN,
                    trailing * BSSID_PROTECTION_ADDRESS_LEN);
        }
        --(*protected_count);
        memset(protected_bssids + (*protected_count * BSSID_PROTECTION_ADDRESS_LEN),
               0, BSSID_PROTECTION_ADDRESS_LEN);
        return true;
    }
    return false;
}
