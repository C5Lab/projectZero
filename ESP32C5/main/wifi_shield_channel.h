#ifndef WIFI_SHIELD_CHANNEL_H
#define WIFI_SHIELD_CHANNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_SHIELD_TARGET_MAX 64U

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    char ssid[33];
    bool wpa2_psk_ccmp;
} wifi_shield_target_t;

/* Session-owned snapshot: callers must not mutate targets/channels/counts. */
typedef struct {
    wifi_shield_target_t targets[WIFI_SHIELD_TARGET_MAX];
    uint8_t channels[WIFI_SHIELD_TARGET_MAX];
    size_t target_count;
    size_t channel_count;
    size_t cursor;
    uint8_t locked_channel;
    bool locked;
} wifi_shield_channel_plan_t;

/* Clears destination on failure. Input must not overlap destination.
 * SSID is copied as 33 bounded bytes; platform snapshotting sanitizes evidence.
 * Platform channel policy validates regulatory availability before this call.
 */
bool wifi_shield_channel_plan_init(wifi_shield_channel_plan_t *plan,
                                  const wifi_shield_target_t *targets, size_t count);
bool wifi_shield_target_selected(const wifi_shield_channel_plan_t *plan,
                                 const uint8_t bssid[6]);
/* Returns zero for an empty/NULL plan; locks do not advance the cursor. */
uint8_t wifi_shield_channel_next(wifi_shield_channel_plan_t *plan);
bool wifi_shield_channel_lock(wifi_shield_channel_plan_t *plan,
                              const uint8_t bssid[6], uint8_t channel);
void wifi_shield_channel_release(wifi_shield_channel_plan_t *plan);
/* Snapshot coverage: none / continuous / sampled, independent of a lock. */
const char *wifi_shield_channel_coverage(const wifi_shield_channel_plan_t *plan);

#endif
