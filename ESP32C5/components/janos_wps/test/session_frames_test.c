#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "session_frames.h"

static unsigned be16(const uint8_t *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static void builds_wsc_nack_with_matching_eap_id_and_nonces(void) {
    uint8_t nonce_e[16], nonce_r[16], frame[128];
    memset(nonce_e, 0x11, sizeof(nonce_e));
    memset(nonce_r, 0x22, sizeof(nonce_r));
    size_t n = wps_build_nack(frame, sizeof(frame), 0x5a, nonce_e, nonce_r, true);

    assert(n == 84);
    assert(frame[0] == 1 && frame[4] == 2 && frame[5] == 0x5a);
    assert(be16(frame + 2) == n - 4 && be16(frame + 6) == n - 4);
    assert(frame[8] == 254 && frame[16] == 3 && frame[17] == 0);
    assert(frame[18] == 0x10 && frame[19] == 0x4a && frame[22] == 0x10);
    assert(frame[23] == 0x10 && frame[24] == 0x22 && frame[27] == 0x0e);
    assert(!memcmp(frame + 32, nonce_e, 16));
    assert(!memcmp(frame + 52, nonce_r, 16));
}

static void parses_config_error_from_wsc_nack(void) {
    uint8_t frame[26] = {0};
    frame[18] = 0x10;
    frame[19] = 0x09;
    frame[20] = 0x00;
    frame[21] = 0x02;
    frame[22] = 0x00;
    frame[23] = 0x0f;
    uint16_t config_error = 0;

    assert(wps_parse_config_error(frame, 24, &config_error));
    assert(config_error == 15);
    assert(!wps_parse_config_error(frame, 23, &config_error));
    frame[21] = 0x01;
    assert(!wps_parse_config_error(frame, 24, &config_error));
}

int main(void) {
    builds_wsc_nack_with_matching_eap_id_and_nonces();
    parses_config_error_from_wsc_nack();
    puts("PASS: WSC NACK frame");
    return 0;
}
