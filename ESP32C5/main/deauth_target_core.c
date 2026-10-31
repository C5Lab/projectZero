#include "deauth_target_core.h"
#include <string.h>

bool deauth_target_parse_index(const char *arg, size_t scan_count, size_t *zero_index)
{
    if (!arg || !*arg || !zero_index || scan_count == 0) return false;
    size_t value = 0;
    for (const unsigned char *p = (const unsigned char *)arg; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        size_t digit = (size_t)(*p - '0');
        if (value > (SIZE_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    if (value == 0 || value > scan_count) return false;
    *zero_index = value - 1;
    return true;
}

bool deauth_target_add(deauth_target_filter_t *filter, const uint8_t bssid[6])
{
    if (!filter || !bssid || filter->count > DEAUTH_TARGET_MAX) return false;
    if (deauth_target_contains(filter, bssid)) return true;
    if (filter->count == DEAUTH_TARGET_MAX) return false;
    memcpy(filter->bssid[filter->count], bssid, 6);
    ++filter->count;
    return true;
}

bool deauth_target_contains(const deauth_target_filter_t *filter, const uint8_t bssid[6])
{
    if (!filter || !bssid || filter->count > DEAUTH_TARGET_MAX) return false;
    for (size_t i = 0; i < filter->count; ++i) {
        if (memcmp(filter->bssid[i], bssid, 6) == 0) return true;
    }
    return false;
}
