#include "sae_guard_parser.h"

#include <limits.h>
#include <string.h>

#define SAE_ALGORITHM 3U
#define SAE_AUTH_HEADER_LEN 6U
#define SAE_COMMIT_GROUP_OFFSET 6U
#define SAE_COMMIT_DATA_OFFSET 8U
#define SAE_CONFIRM_MIN_BODY_LEN (SAE_AUTH_HEADER_LEN + 2U + 32U)
#define SAE_STATUS_ANTI_CLOGGING_TOKEN_REQUIRED 76U
#define SAE_STATUS_GROUP_NOT_SUPPORTED 77U
#define SAE_STATUS_HASH_TO_ELEMENT 126U
#define SAE_STATUS_SAE_PK 127U

static uint16_t read_le16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static bool nonzero_address(const uint8_t address[6])
{
    return (address[0] | address[1] | address[2] |
            address[3] | address[4] | address[5]) != 0;
}

static bool unicast_address(const uint8_t address[6])
{
    return nonzero_address(address) && (address[0] & 1U) == 0;
}

static bool same_address(const uint8_t left[6], const uint8_t right[6])
{
    return memcmp(left, right, 6) == 0;
}

static bool direction_is_unambiguous(const wifi_security_decoded_t *frame,
                                     bool *from_ap)
{
    if (frame->to_ds || frame->from_ds ||
        !unicast_address(frame->bssid) ||
        !unicast_address(frame->station) ||
        same_address(frame->bssid, frame->station) ||
        !same_address(frame->addr3, frame->bssid)) {
        return false;
    }
    const bool ap_to_sta = same_address(frame->addr1, frame->station) &&
                           same_address(frame->addr2, frame->bssid);
    const bool sta_to_ap = same_address(frame->addr1, frame->bssid) &&
                           same_address(frame->addr2, frame->station);
    if (ap_to_sta == sta_to_ap) return false;
    *from_ap = ap_to_sta;
    return true;
}

static size_t known_group_data_minimum(uint16_t group)
{
    switch (group) {
    case 19: return 32U + 64U;
    case 20: return 48U + 96U;
    case 21: return 66U + 132U;
    default: return 0;
    }
}

static bool commit_bearing_status(uint16_t status)
{
    return status == 0 || status == SAE_STATUS_HASH_TO_ELEMENT ||
           status == SAE_STATUS_SAE_PK;
}

static void mark_malformed(sae_guard_observation_t *out,
                           sae_guard_parse_reason_t reason)
{
    out->kind = SAE_GUARD_MALFORMED;
    out->reason = reason;
}

bool sae_guard_parse(const wifi_security_decoded_t *frame,
                     bool input_truncated, uint64_t timestamp_us,
                     sae_guard_observation_t *out)
{
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (frame == NULL || frame->kind != WIFI_SEC_FRAME_AUTH ||
        frame->protected_frame ||
        frame->body_len > UINT16_MAX) {
        return false;
    }
    bool from_ap = false;
    if (!direction_is_unambiguous(frame, &from_ap)) return false;

    if (frame->body == NULL || frame->body_len < 2 ||
        read_le16(frame->body) != SAE_ALGORITHM) {
        return false;
    }

    memcpy(out->bssid, frame->bssid, sizeof(out->bssid));
    memcpy(out->station, frame->station, sizeof(out->station));
    out->from_ap = from_ap;
    out->retry = frame->retry;
    out->sequence = frame->sequence;
    out->body_len = (uint16_t)frame->body_len;
    out->timestamp_us = timestamp_us;

    const uint8_t *body = frame->body;
    if (frame->body_len >= 4) out->transaction = read_le16(body + 2);
    if (frame->body_len >= SAE_AUTH_HEADER_LEN) out->status = read_le16(body + 4);
    if (input_truncated) {
        mark_malformed(out, SAE_GUARD_INPUT_TRUNCATED);
        return true;
    }
    if (frame->body_len < SAE_AUTH_HEADER_LEN) {
        mark_malformed(out, SAE_GUARD_SHORT_AUTH_BODY);
        return true;
    }
    if (out->transaction != 1 && out->transaction != 2) {
        mark_malformed(out, SAE_GUARD_BAD_TRANSACTION);
        return true;
    }

    if (out->transaction == 1 && commit_bearing_status(out->status)) {
        if (frame->body_len < SAE_COMMIT_DATA_OFFSET) {
            mark_malformed(out, SAE_GUARD_SHORT_GROUP);
            return true;
        }
        out->group = read_le16(body + SAE_COMMIT_GROUP_OFFSET);
        const size_t minimum = known_group_data_minimum(out->group);
        if (minimum != 0 && frame->body_len - SAE_COMMIT_DATA_OFFSET < minimum) {
            mark_malformed(out, SAE_GUARD_KNOWN_GROUP_UNDERSIZE);
            return true;
        }
        out->kind = SAE_GUARD_COMMIT;
        out->reason = SAE_GUARD_PARSE_OK;
        return true;
    }

    if (out->transaction == 1 &&
        out->status == SAE_STATUS_ANTI_CLOGGING_TOKEN_REQUIRED) {
        if (frame->body_len < SAE_COMMIT_DATA_OFFSET) {
            mark_malformed(out, SAE_GUARD_SHORT_GROUP);
            return true;
        }
        out->group = read_le16(body + SAE_COMMIT_GROUP_OFFSET);
        out->kind = SAE_GUARD_ANTI_CLOGGING;
        out->reason = SAE_GUARD_PARSE_OK;
        return true;
    }

    if (out->transaction == 1 &&
        out->status == SAE_STATUS_GROUP_NOT_SUPPORTED) {
        out->kind = SAE_GUARD_UNSUPPORTED_GROUP;
        out->reason = SAE_GUARD_PARSE_OK;
        return true;
    }

    if (out->status != 0) {
        out->kind = SAE_GUARD_STATUS_ONLY;
        out->reason = SAE_GUARD_PARSE_OK;
        return true;
    }

    if (frame->body_len < SAE_CONFIRM_MIN_BODY_LEN) {
        mark_malformed(out, SAE_GUARD_CONFIRM_UNDERSIZE);
        return true;
    }
    out->kind = SAE_GUARD_CONFIRM;
    out->reason = SAE_GUARD_PARSE_OK;
    return true;
}
