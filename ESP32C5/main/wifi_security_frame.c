#include "wifi_security_frame.h"

#include <string.h>

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

static bool management_addresses(wifi_security_decoded_t *decoded)
{
    if (decoded->to_ds || decoded->from_ds ||
        !nonzero_address(decoded->addr1) || !unicast_address(decoded->addr2)) {
        return false;
    }

    const bool valid_bssid = unicast_address(decoded->addr3);
    const bool from_ap = valid_bssid && same_address(decoded->addr2, decoded->addr3);
    const bool to_ap = valid_bssid && same_address(decoded->addr1, decoded->addr3);
    if (decoded->kind == WIFI_SEC_FRAME_BEACON ||
        decoded->kind == WIFI_SEC_FRAME_PROBE_RESPONSE) {
        if (!from_ap) {
            return false;
        }
    }
    if (decoded->kind == WIFI_SEC_FRAME_AUTH &&
        (!unicast_address(decoded->addr1) || from_ap == to_ap)) {
        return false;
    }
    if (decoded->kind == WIFI_SEC_FRAME_MGMT && from_ap == to_ap) {
        /* Wildcard/unknown BSSID and ambiguous endpoints are still valid headers. */
        return true;
    }

    memcpy(decoded->bssid, decoded->addr3, 6);
    if (from_ap && !to_ap && unicast_address(decoded->addr1)) {
        memcpy(decoded->station, decoded->addr1, 6);
    } else if (to_ap && !from_ap) {
        memcpy(decoded->station, decoded->addr2, 6);
    }
    return true;
}

static bool data_addresses(wifi_security_decoded_t *decoded)
{
    if ((decoded->to_ds && decoded->from_ds) ||
        !nonzero_address(decoded->addr1) ||
        !unicast_address(decoded->addr2) || !nonzero_address(decoded->addr3)) {
        return false;
    }
    if (decoded->to_ds) {
        if (!unicast_address(decoded->addr1)) {
            return false;
        }
        memcpy(decoded->bssid, decoded->addr1, 6);
        memcpy(decoded->station, decoded->addr2, 6);
    } else if (decoded->from_ds) {
        memcpy(decoded->bssid, decoded->addr2, 6);
        if (unicast_address(decoded->addr1)) {
            memcpy(decoded->station, decoded->addr1, 6);
        }
    } else if (!unicast_address(decoded->addr3)) {
        /* With neither DS bit, addr3 is an individual BSSID. */
        return false;
    }
    /* Neither DS bit: keep original addresses, with no inferred identities. */
    return true;
}

static bool control_header(const uint8_t *frame, size_t length,
                           wifi_security_decoded_t *decoded)
{
    size_t minimum = 10;
    bool transmitter = false;
    switch (decoded->subtype) {
    case 8: /* Block Ack Request: RA, TA, control and starting sequence. */
        minimum = 20;
        transmitter = true;
        break;
    case 9: /* Block Ack: at least compressed control/sequence/bitmap. */
        minimum = 28;
        transmitter = true;
        break;
    case 10: /* PS-Poll */
    case 11: /* RTS */
    case 14: /* CF-End */
    case 15: /* CF-End + CF-Ack */
        minimum = 16;
        transmitter = true;
        break;
    default:
        break;
    }
    if (length < minimum || decoded->to_ds || decoded->from_ds ||
        !nonzero_address(frame + 4) ||
        (decoded->subtype == 13 && !unicast_address(frame + 4))) {
        return false;
    }
    memcpy(decoded->addr1, frame + 4, 6);
    if (transmitter) {
        if (!unicast_address(frame + 10)) {
            return false;
        }
        memcpy(decoded->addr2, frame + 10, 6);
    }
    return true;
}

bool wifi_security_decode(const uint8_t *frame, size_t length,
                          wifi_security_decoded_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (frame == NULL || length < 2 || length > WIFI_SECURITY_FRAME_COPY_MAX) {
        return false;
    }

    const uint16_t control = read_le16(frame);
    const uint8_t type = (uint8_t)((control >> 2) & 3U);
    if ((control & 3U) != 0 || type == 3) {
        return false;
    }
    wifi_security_decoded_t decoded = {0};
    decoded.subtype = (uint8_t)((control >> 4) & 15U);
    decoded.to_ds = (control & 0x0100U) != 0;
    decoded.from_ds = (control & 0x0200U) != 0;
    decoded.retry = (control & 0x0800U) != 0;
    decoded.protected_frame = (control & 0x4000U) != 0;

    if (type == 1) {
        if (!control_header(frame, length, &decoded)) {
            return false;
        }
        *out = decoded;
        return true;
    }
    if (length < 24) {
        return false;
    }
    memcpy(decoded.addr1, frame + 4, 6);
    memcpy(decoded.addr2, frame + 10, 6);
    memcpy(decoded.addr3, frame + 16, 6);
    const uint16_t sequence_control = read_le16(frame + 22);
    decoded.sequence = sequence_control >> 4;

    size_t header_length = 24;
    bool amsdu = false;
    if (type == 0) {
        decoded.kind = WIFI_SEC_FRAME_MGMT;
        switch (decoded.subtype) {
        case 5: decoded.kind = WIFI_SEC_FRAME_PROBE_RESPONSE; break;
        case 8: decoded.kind = WIFI_SEC_FRAME_BEACON; break;
        case 11: decoded.kind = WIFI_SEC_FRAME_AUTH; break;
        default: break;
        }
        if (!management_addresses(&decoded)) {
            return false;
        }
        /* Management Order indicates an additional HT control field. */
        if ((control & 0x8000U) != 0) {
            header_length += 4;
        }
    } else {
        decoded.kind = WIFI_SEC_FRAME_DATA;
        if (!data_addresses(&decoded)) {
            return false;
        }
        decoded.qos = (decoded.subtype & 8U) != 0;
        if (decoded.qos) {
            header_length += 2;
            if (length < header_length) {
                return false;
            }
            amsdu = (frame[24] & 0x80U) != 0;
            if ((control & 0x8000U) != 0) {
                header_length += 4;
            }
        }
    }
    if (length < header_length) {
        return false;
    }
    if (!decoded.protected_frame) {
        decoded.body = frame + header_length;
        decoded.body_len = length - header_length;
        static const uint8_t eapol_snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
        if (type == 2 && (decoded.subtype & 4U) == 0 && !amsdu &&
            (sequence_control & 15U) == 0 && (control & 0x0400U) == 0 &&
            decoded.body_len >= sizeof(eapol_snap) &&
            memcmp(decoded.body, eapol_snap, sizeof(eapol_snap)) == 0) {
            decoded.kind = WIFI_SEC_FRAME_EAPOL;
            decoded.eapol = decoded.body + sizeof(eapol_snap);
            decoded.eapol_len = decoded.body_len - sizeof(eapol_snap);
        }
    }
    *out = decoded;
    return true;
}
