#include "sta_mac_policy_core.h"
#include <string.h>

sta_mac_policy_status_t sta_mac_fixed_validate(const uint8_t mac[STA_MAC_SIZE])
{
    if (!mac) return STA_MAC_POLICY_INVALID_ARGUMENT;
    /* Local-admin/unicast also excludes all-zero and all-FF addresses. */
    return (mac[0] & 3u) == 2u ? STA_MAC_POLICY_OK : STA_MAC_POLICY_INVALID_FIXED_MAC;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

sta_mac_policy_status_t sta_mac_fixed_parse(const char *text, uint8_t out[STA_MAC_SIZE])
{
    if (!text || !out) return STA_MAC_POLICY_INVALID_ARGUMENT;
    if (strlen(text) != 17) return STA_MAC_POLICY_INVALID_TEXT;
    uint8_t mac[STA_MAC_SIZE];
    for (size_t i = 0; i < STA_MAC_SIZE; ++i) {
        int high = hex_value(text[i * 3]);
        int low = hex_value(text[i * 3 + 1]);
        if (high < 0 || low < 0 || (i < 5 && text[i * 3 + 2] != ':'))
            return STA_MAC_POLICY_INVALID_TEXT;
        mac[i] = (uint8_t)((high << 4) | low);
    }
    sta_mac_policy_status_t status = sta_mac_fixed_validate(mac);
    if (status == STA_MAC_POLICY_OK) memcpy(out, mac, sizeof(mac));
    return status;
}

sta_mac_policy_status_t sta_mac_policy_validate(const sta_mac_policy_record_t *record)
{
    if (!record) return STA_MAC_POLICY_INVALID_ARGUMENT;
    if (record->version != STA_MAC_POLICY_VERSION) return STA_MAC_POLICY_UNSUPPORTED_VERSION;
    switch (record->mode) {
    case STA_MAC_MODE_FACTORY:
    case STA_MAC_MODE_RANDOM_PER_BOOT:
        return STA_MAC_POLICY_OK;
    case STA_MAC_MODE_FIXED:
        return sta_mac_fixed_validate(record->mac);
    default:
        return STA_MAC_POLICY_INVALID_MODE;
    }
}

sta_mac_policy_status_t sta_mac_policy_encode(const sta_mac_policy_record_t *record, uint8_t *out, size_t length)
{
    if (!record || !out) return STA_MAC_POLICY_INVALID_ARGUMENT;
    if (length != STA_MAC_POLICY_RECORD_SIZE) return STA_MAC_POLICY_WRONG_LENGTH;
    sta_mac_policy_status_t status = sta_mac_policy_validate(record);
    if (status != STA_MAC_POLICY_OK) return status;
    uint8_t bytes[STA_MAC_POLICY_RECORD_SIZE] = {STA_MAC_POLICY_VERSION, (uint8_t)record->mode};
    if (record->mode == STA_MAC_MODE_FIXED) memcpy(bytes + 2, record->mac, STA_MAC_SIZE);
    memcpy(out, bytes, sizeof(bytes));
    return STA_MAC_POLICY_OK;
}

sta_mac_policy_status_t sta_mac_policy_decode(const uint8_t *data, size_t length, sta_mac_policy_record_t *out)
{
    if (!data || !out) return STA_MAC_POLICY_INVALID_ARGUMENT;
    if (length != STA_MAC_POLICY_RECORD_SIZE) return STA_MAC_POLICY_WRONG_LENGTH;
    sta_mac_policy_record_t record = {data[0], (sta_mac_policy_mode_t)data[1], {0}};
    memcpy(record.mac, data + 2, STA_MAC_SIZE);
    sta_mac_policy_status_t status = sta_mac_policy_validate(&record);
    if (status != STA_MAC_POLICY_OK) return status;
    if (record.mode != STA_MAC_MODE_FIXED) {
        for (size_t i = 0; i < STA_MAC_SIZE; ++i)
            if (record.mac[i] != 0) return STA_MAC_POLICY_INVALID_PAYLOAD;
    }
    *out = record;
    return STA_MAC_POLICY_OK;
}

sta_mac_policy_status_t sta_mac_random_from_entropy(const uint8_t *entropy, size_t length, uint8_t out[STA_MAC_SIZE])
{
    if (!entropy || !out) return STA_MAC_POLICY_INVALID_ARGUMENT;
    if (length != STA_MAC_SIZE) return STA_MAC_POLICY_WRONG_LENGTH;
    uint8_t mac[STA_MAC_SIZE];
    memcpy(mac, entropy, sizeof(mac));
    mac[0] = (uint8_t)((mac[0] | 0x02u) & 0xfeu);
    memcpy(out, mac, sizeof(mac));
    return STA_MAC_POLICY_OK;
}
