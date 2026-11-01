#include "pmkid_probe_detector.h"

#include <stdbool.h>
#include <string.h>

#define DOT11_HEADER_LEN 24U
#define FC_SUBTYPE_MASK 0xf0U
#define FC_TYPE_MASK 0x0cU
#define FC_ASSOC_REQUEST 0x00U
#define FC_REASSOC_REQUEST 0x20U
#define FC_AUTH 0xb0U

static bool bytes_nonzero(const uint8_t *value, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0; i < length; ++i) combined |= value[i];
    return combined != 0U;
}
static bool unicast_address(const uint8_t address[6])
{
    return address && (address[0] & 1U) == 0U &&
           bytes_nonzero(address, 6U);
}

static uint16_t read_le16(const uint8_t *value)
{
    return (uint16_t)(value[0] | ((uint16_t)value[1] << 8));
}

static pmkid_probe_slot_t *find_slot(pmkid_probe_detector_t *detector,
                                     const uint8_t bssid[6],
                                     const uint8_t sta[6])
{
    for (size_t i = 0; i < PMKID_PROBE_SLOTS; ++i) {
        pmkid_probe_slot_t *slot = &detector->slots[i];
        if (slot->used && memcmp(slot->bssid, bssid, 6U) == 0 &&
            memcmp(slot->sta, sta, 6U) == 0) return slot;
    }
    return NULL;
}

static pmkid_probe_slot_t *allocate_slot(pmkid_probe_detector_t *detector)
{
    pmkid_probe_slot_t *oldest = &detector->slots[0];
    for (size_t i = 0; i < PMKID_PROBE_SLOTS; ++i) {
        pmkid_probe_slot_t *slot = &detector->slots[i];
        if (!slot->used) return slot;
        if (slot->last_seen_us < oldest->last_seen_us) oldest = slot;
    }
    return oldest;
}

void pmkid_probe_reset(pmkid_probe_detector_t *detector)
{
    if (detector) memset(detector, 0, sizeof(*detector));
}

pmkid_probe_result_t pmkid_probe_observe(
    pmkid_probe_detector_t *detector, const uint8_t *frame, size_t length,
    uint8_t rx_channel, int64_t now_us,
    uint8_t bssid_out[6], uint8_t sta_out[6])
{
    if (bssid_out) memset(bssid_out, 0, 6U);
    if (sta_out) memset(sta_out, 0, 6U);
    if (!detector || !frame || !bssid_out || !sta_out ||
        length < DOT11_HEADER_LEN || rx_channel == 0U || now_us < 0) {
        return PMKID_PROBE_NONE;
    }
    if ((frame[0] & FC_TYPE_MASK) != 0U ||
        (frame[1] & 0x43U) != 0U) {
        return PMKID_PROBE_NONE;
    }

    const uint8_t subtype = frame[0] & FC_SUBTYPE_MASK;
    if (subtype != FC_AUTH && subtype != FC_ASSOC_REQUEST &&
        subtype != FC_REASSOC_REQUEST) return PMKID_PROBE_NONE;

    const uint8_t *destination = frame + 4U;
    const uint8_t *sta = frame + 10U;
    const uint8_t *bssid = frame + 16U;
    if (!unicast_address(bssid) || !unicast_address(sta) ||
        memcmp(destination, bssid, 6U) != 0) return PMKID_PROBE_NONE;

    if (subtype == FC_AUTH) {
        if (length < 30U || read_le16(frame + 24U) != 0U ||
            read_le16(frame + 26U) != 1U || read_le16(frame + 28U) != 0U) {
            return PMKID_PROBE_NONE;
        }
        pmkid_probe_slot_t *slot = find_slot(detector, bssid, sta);
        if (!slot) slot = allocate_slot(detector);
        memset(slot, 0, sizeof(*slot));
        memcpy(slot->bssid, bssid, 6U);
        memcpy(slot->sta, sta, 6U);
        slot->channel = rx_channel;
        slot->auth_us = now_us;
        slot->last_seen_us = now_us;
        slot->used = 1U;
        return PMKID_PROBE_AUTH_SEEN;
    }

    const size_t minimum = subtype == FC_REASSOC_REQUEST ? 34U : 28U;
    if (length < minimum) return PMKID_PROBE_NONE;
    pmkid_probe_slot_t *slot = find_slot(detector, bssid, sta);
    if (!slot || slot->channel != rx_channel || now_us < slot->auth_us) {
        return PMKID_PROBE_NONE;
    }
    if (now_us - slot->auth_us > PMKID_PROBE_WINDOW_US) {
        memset(slot, 0, sizeof(*slot));
        return PMKID_PROBE_NONE;
    }
    memcpy(bssid_out, bssid, 6U);
    memcpy(sta_out, sta, 6U);
    memset(slot, 0, sizeof(*slot));
    return PMKID_PROBE_ASSOC_SEQUENCE;
}
