#ifndef HANDSHAKE_RADIO_POLICY_H
#define HANDSHAKE_RADIO_POLICY_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    HANDSHAKE_RADIO_PATH_APSTA_TX_AP = 0,
    HANDSHAKE_RADIO_PATH_STA_TX_STA = 1,
} handshake_radio_path_t;

bool handshake_radio_channel_is_dfs(uint8_t channel);
handshake_radio_path_t handshake_radio_path_for_channel(uint8_t channel);

#endif
