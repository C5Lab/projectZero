#include "session_frames.h"

#include <string.h>

static void put16(uint8_t *p, unsigned value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static bool add_attr(uint8_t *out, size_t cap, size_t *pos, unsigned type,
                     const void *data, size_t size) {
    if (!out || !pos || !data || size > 65535 || *pos > cap || cap - *pos < 4 ||
        size > cap - *pos - 4) return false;
    put16(out + *pos, type);
    put16(out + *pos + 2, (unsigned)size);
    memcpy(out + *pos + 4, data, size);
    *pos += size + 4;
    return true;
}

size_t wps_build_nack(uint8_t *out, size_t cap, uint8_t eap_id,
                      const uint8_t enrollee_nonce[16],
                      const uint8_t registrar_nonce[16], bool wsc2) {
    if (!out || !enrollee_nonce || !registrar_nonce || cap < 18) return 0;
    static const uint8_t version = 0x10, message_type = 0x0e;
    static const uint8_t config_error[] = {0, 0};
    static const uint8_t version2[] = {0, 0x37, 0x2a, 0, 1, 0x20};
    size_t pos = 18;
    memset(out, 0, 18);
    if (!add_attr(out, cap, &pos, 0x104a, &version, 1) ||
        !add_attr(out, cap, &pos, 0x1022, &message_type, 1) ||
        !add_attr(out, cap, &pos, 0x101a, enrollee_nonce, 16) ||
        !add_attr(out, cap, &pos, 0x1039, registrar_nonce, 16) ||
        !add_attr(out, cap, &pos, 0x1009, config_error, sizeof(config_error)) ||
        (wsc2 && !add_attr(out, cap, &pos, 0x1049, version2, sizeof(version2)))) return 0;
    size_t attrs_len = pos - 18;
    out[0] = 1;
    out[4] = 2;
    out[5] = eap_id;
    put16(out + 2, (unsigned)attrs_len + 14);
    put16(out + 6, (unsigned)attrs_len + 14);
    out[8] = 254;
    out[10] = 0x37;
    out[11] = 0x2a;
    out[15] = 1;
    out[16] = 3;
    return pos;
}

bool wps_parse_config_error(const uint8_t *frame, size_t len,
                            uint16_t *config_error) {
    if (!frame || !config_error || len < 18) return false;
    size_t pos = 18;
    while (pos <= len && len - pos >= 4) {
        unsigned type = ((unsigned)frame[pos] << 8) | frame[pos + 1];
        size_t size = ((size_t)frame[pos + 2] << 8) | frame[pos + 3];
        pos += 4;
        if (size > len - pos) return false;
        if (type == 0x1009) {
            if (size != 2) return false;
            *config_error = (uint16_t)(((unsigned)frame[pos] << 8) | frame[pos + 1]);
            return true;
        }
        pos += size;
    }
    return false;
}
