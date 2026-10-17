#include <assert.h>
#include <stdio.h>

#include "handshake_radio_policy.h"

int main(void)
{
    assert(!handshake_radio_channel_is_dfs(36));
    assert(!handshake_radio_channel_is_dfs(48));
    assert(handshake_radio_channel_is_dfs(52));
    assert(handshake_radio_channel_is_dfs(64));
    assert(!handshake_radio_channel_is_dfs(68));
    assert(!handshake_radio_channel_is_dfs(96));
    assert(handshake_radio_channel_is_dfs(100));
    assert(handshake_radio_channel_is_dfs(144));
    assert(!handshake_radio_channel_is_dfs(149));
    assert(!handshake_radio_channel_is_dfs(165));

    assert(handshake_radio_path_for_channel(1) ==
           HANDSHAKE_RADIO_PATH_APSTA_TX_AP);
    assert(handshake_radio_path_for_channel(48) ==
           HANDSHAKE_RADIO_PATH_APSTA_TX_AP);
    assert(handshake_radio_path_for_channel(52) ==
           HANDSHAKE_RADIO_PATH_STA_TX_STA);
    assert(handshake_radio_path_for_channel(100) ==
           HANDSHAKE_RADIO_PATH_STA_TX_STA);
    assert(handshake_radio_path_for_channel(149) ==
           HANDSHAKE_RADIO_PATH_APSTA_TX_AP);

    puts("PASS: handshake radio policy");
    return 0;
}
