#include "wifi_channel_policy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef TEST_PA_EXTENDED
#define TEST_PA_EXTENDED 0
#endif

int main(void)
{
    const uint8_t channels[] = {
        36,40,44,48,52,56,60,64,100,104,108,112,116,120,
        124,128,132,136,140,144,149,153,157,161,165,169,173,177
    };
    wifi_country_t country = {
        .cc = "US", .schan = 1, .nchan = 11,
        .policy = WIFI_COUNTRY_POLICY_MANUAL,
    };
    unsigned non_dfs = 0, dfs = 0, disallowed = 0;
    for (unsigned i = 0; i < sizeof(channels); ++i) {
        wifi_channel_policy_t policy = wifi_channel_policy_classify(&country, channels[i]);
        assert(policy == (channels[i] >= 52 && channels[i] <= 144 ?
                         WIFI_CHANNEL_POLICY_DFS : WIFI_CHANNEL_POLICY_NON_DFS));
        non_dfs += policy == WIFI_CHANNEL_POLICY_NON_DFS;
        dfs += policy == WIFI_CHANNEL_POLICY_DFS;
    }
    assert(non_dfs == 12 && dfs == 16);

    memcpy(country.cc, "PA", 3);
    country.nchan = 14;
    non_dfs = 0;
    for (unsigned i = 0; i < sizeof(channels); ++i) {
        wifi_channel_policy_t policy = wifi_channel_policy_classify(&country, channels[i]);
        bool excluded = !TEST_PA_EXTENDED && (channels[i] == 144 || channels[i] >= 169);
        assert(policy == (excluded ? WIFI_CHANNEL_POLICY_DISALLOWED : WIFI_CHANNEL_POLICY_NON_DFS));
        non_dfs += policy == WIFI_CHANNEL_POLICY_NON_DFS;
        disallowed += policy == WIFI_CHANNEL_POLICY_DISALLOWED;
    }
    assert(non_dfs == (TEST_PA_EXTENDED ? 28U : 24U));
    assert(disallowed == (TEST_PA_EXTENDED ? 0U : 4U));
    assert(wifi_channel_policy_classify(&country, 14) == WIFI_CHANNEL_POLICY_NON_DFS);

    memcpy(country.cc, "US", 3);
    country.nchan = 11;
    assert(wifi_channel_policy_classify(&country, 12) == WIFI_CHANNEL_POLICY_DISALLOWED);
    assert(wifi_channel_policy_classify(&country, 0) == WIFI_CHANNEL_POLICY_DISALLOWED);
    assert(wifi_channel_policy_classify(&country, 37) == WIFI_CHANNEL_POLICY_DISALLOWED);
    assert(wifi_channel_policy_classify(&country, 145) == WIFI_CHANNEL_POLICY_DISALLOWED);
    assert(wifi_channel_policy_classify(&country, 255) == WIFI_CHANNEL_POLICY_DISALLOWED);

    country.wifi_5g_channel_mask = CHANNEL_TO_BIT(36) | CHANNEL_TO_BIT(52);
    assert(wifi_channel_policy_classify(&country, 36) == WIFI_CHANNEL_POLICY_NON_DFS);
    assert(wifi_channel_policy_classify(&country, 40) == WIFI_CHANNEL_POLICY_DISALLOWED);
    assert(wifi_channel_policy_classify(&country, 52) == WIFI_CHANNEL_POLICY_DFS);
    country.policy = WIFI_COUNTRY_POLICY_AUTO;
    assert(wifi_channel_policy_classify(&country, 40) == WIFI_CHANNEL_POLICY_NON_DFS);

    memcpy(country.cc, "PA", 3);
    country.policy = WIFI_COUNTRY_POLICY_MANUAL;
    country.wifi_5g_channel_mask = CHANNEL_TO_BIT(144);
    assert(wifi_channel_policy_classify(&country, 144) ==
           (TEST_PA_EXTENDED ? WIFI_CHANNEL_POLICY_NON_DFS : WIFI_CHANNEL_POLICY_DISALLOWED));
    memcpy(country.cc, "ZZ", 3);
    assert(wifi_channel_policy_classify(&country, 36) == WIFI_CHANNEL_POLICY_UNKNOWN);
    assert(wifi_channel_policy_classify(NULL, 36) == WIFI_CHANNEL_POLICY_UNKNOWN);
    puts(TEST_PA_EXTENDED ?
         "PASS: US 12 non-DFS/16 DFS; PA 28 non-DFS/0 excluded; masks and unknown countries" :
         "PASS: US 12 non-DFS/16 DFS; PA 24 non-DFS/4 excluded; masks and unknown countries");
    return 0;
}
