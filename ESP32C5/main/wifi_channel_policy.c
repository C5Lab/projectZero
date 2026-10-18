/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_channel_policy.h"

#include <stddef.h>
#include <string.h>

/* These tables are linked by ESP-IDF's esp_wifi component from
 * regulatory/esp_wifi_regulatory.c. Use the same rules as the driver rather
 * than maintaining a second country/DFS database in the application. */
extern const wifi_regdomain_t regdomain_table[WIFI_MAX_SUPPORT_COUNTRY_NUM];
extern const wifi_regulatory_t regulatory_data[];

wifi_channel_policy_t wifi_channel_policy_classify(
    const wifi_country_t *country, uint8_t channel)
{
    if (country == NULL) return WIFI_CHANNEL_POLICY_UNKNOWN;

    const wifi_regulatory_t *rules = NULL;
    for (size_t i = 0; i < WIFI_MAX_SUPPORT_COUNTRY_NUM; ++i) {
        if (memcmp(regdomain_table[i].cn, country->cc, 2) == 0) {
            rules = &regulatory_data[regdomain_table[i].regulatory_type];
            break;
        }
    }
    if (rules == NULL || rules->n_reg_rules > WIFI_MAX_REGULATORY_RULE_NUM)
        return WIFI_CHANNEL_POLICY_UNKNOWN;

    if (channel >= 1 && channel <= 14) {
        /* The active legacy country structure can customize 2.4 GHz bounds. */
        return channel >= country->schan &&
               channel < (unsigned)country->schan + country->nchan ?
               WIFI_CHANNEL_POLICY_NON_DFS : WIFI_CHANNEL_POLICY_DISALLOWED;
    }

    if (CHANNEL_TO_BIT_NUMBER(channel) == 0)
        return WIFI_CHANNEL_POLICY_DISALLOWED;
    if (country->policy == WIFI_COUNTRY_POLICY_MANUAL &&
        country->wifi_5g_channel_mask != 0 &&
        !(country->wifi_5g_channel_mask & CHANNEL_TO_BIT(channel)))
        return WIFI_CHANNEL_POLICY_DISALLOWED;

    bool allowed = false;
    bool dfs = false;
    for (unsigned i = 0; i < rules->n_reg_rules; ++i) {
        const wifi_reg_rule_t *rule = &rules->reg_rules[i];
        if (channel >= rule->start_channel && channel <= rule->end_channel) {
            allowed = true;
            dfs |= rule->is_dfs != 0;
        }
    }
    return !allowed ? WIFI_CHANNEL_POLICY_DISALLOWED :
           dfs ? WIFI_CHANNEL_POLICY_DFS : WIFI_CHANNEL_POLICY_NON_DFS;
}
