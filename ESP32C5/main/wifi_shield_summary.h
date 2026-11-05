#ifndef WIFI_SHIELD_SUMMARY_H
#define WIFI_SHIELD_SUMMARY_H

#include "wifi_shield_journal.h"

#define WIFI_SHIELD_SUMMARY_TEXT_MAX 3072U

typedef struct {
    size_t target_count;
    bool primary_target_valid;
    uint8_t primary_bssid[6];
    uint8_t primary_channel;
    char primary_ssid[33];
    bool active_defence;
    bool pmkid_decoy;
    bool multi_vector;
    bool protect_all;
} wifi_shield_summary_metadata_t;

/* Writer-owned normalized state. It retains no station identity, frame bytes,
 * credentials, nonces, MICs or decoy material. */
typedef struct {
    wifi_shield_summary_metadata_t metadata;
    uint32_t boot_id;
    uint32_t session_id;
    uint64_t started_us;
    uint64_t ended_us;
    uint32_t event_counts[10];
    wifi_shield_threat_t threat;
    wifi_shield_campaign_reason_t reason;
    wifi_shield_journal_outcome_t outcome;
    wifi_shield_ap_health_snapshot_t ap_health;
    bool started;
    bool terminal;
    bool ap_health_valid;
} wifi_shield_summary_t;

bool wifi_shield_summary_init(wifi_shield_summary_t *summary,
    const wifi_shield_summary_metadata_t *metadata,
    uint32_t boot_id, uint32_t session_id);
void wifi_shield_summary_observe(wifi_shield_summary_t *summary,
    const wifi_shield_journal_record_t *record);
/* Returns bytes excluding NUL. Formats directly into caller-owned PSRAM;
 * failure clears the first byte. No large task-stack scratch is used. */
int wifi_shield_summary_format(char *out, size_t capacity,
    const wifi_shield_summary_t *summary,
    const wifi_shield_journal_status_t *journal, const char *json_path);

#endif
