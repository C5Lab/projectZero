#include "handshake_radio_policy.h"

bool handshake_radio_channel_is_dfs(uint8_t channel)
{
    return (channel >= 52 && channel <= 64) ||
           (channel >= 100 && channel <= 144);
}

handshake_radio_path_t handshake_radio_path_for_channel(uint8_t channel)
{
    return handshake_radio_channel_is_dfs(channel)
        ? HANDSHAKE_RADIO_PATH_STA_TX_STA
        : HANDSHAKE_RADIO_PATH_APSTA_TX_AP;
}
