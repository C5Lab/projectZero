#ifndef WIFI_SHIELD_TIME_H
#define WIFI_SHIELD_TIME_H

#include "wifi_shield_channel.h"

#define WIFI_SHIELD_TIME_MAX_TARGETS WIFI_SHIELD_TARGET_MAX

typedef enum {
    WIFI_SHIELD_TIME_NONE = 0,
    WIFI_SHIELD_TIME_EXACT,
    WIFI_SHIELD_TIME_ESTIMATED
} wifi_shield_time_quality_t;

/* AP-relative, spoofable evidence; neither UTC nor an authenticated clock.
 * quality == NONE means AP time/epoch/uncertainty are absent (zeroed).
 * A legitimate exact AP TSF may itself be zero. */
typedef struct {
    uint64_t boot_us;
    uint64_t ap_tsf_us;
    uint32_t ap_epoch;
    uint64_t uncertainty_us;
    wifi_shield_time_quality_t quality;
} wifi_shield_time_stamp_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    uint64_t ap_tsf_us;
    uint64_t boot_us;
    uint32_t ap_epoch;
} wifi_shield_time_anchor_t;

/* Fixed storage, owned and serialized by the caller. No eviction: a full
 * table still permits refreshes of existing BSSIDs. */
typedef struct {
    wifi_shield_time_anchor_t anchors[WIFI_SHIELD_TIME_MAX_TARGETS];
    uint64_t max_anchor_age_us;
} wifi_shield_time_core_t;

void wifi_shield_time_init(wifi_shield_time_core_t *core,
                           uint64_t max_anchor_age_us);
/* Rejects backward boot time without changing an existing anchor.
 * First anchor starts epoch 1; new_epoch reports subsequent resets only.
 * Reset: backward TSF or absolute TSF/local delta difference > 5 seconds.
 * Epoch increments saturate at UINT32_MAX, never wrap to zero.
 * new_epoch may be NULL; when supplied it is false on rejection. */
bool wifi_shield_time_observe_anchor(wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t ap_tsf_us, uint64_t boot_us,
    bool *new_epoch);
/* Refreshes the anchor and emits the observed TSF with zero uncertainty.
 * out must not overlap core or bssid. A NULL out rejects without mutation. */
bool wifi_shield_time_exact(wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t ap_tsf_us, uint64_t boot_us,
    wifi_shield_time_stamp_t *out);
/* Estimated uncertainty equals anchor age, inclusive of the configured limit.
 * TSF addition saturates at UINT64_MAX. Returns false for absent/stale anchors,
 * backward boot time or invalid arguments. Failures preserve boot_us in out
 * and clear AP fields to NONE. out must not overlap core or bssid. */
bool wifi_shield_time_resolve(const wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t boot_us,
    wifi_shield_time_stamp_t *out);

#endif
