#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEAUTH_DEFENCE_TARGET_SLOTS 64U
#define DEAUTH_DEFENCE_STATION_SLOTS 32U
#define DEAUTH_DEFENCE_PAIR_COOLDOWN_US INT64_C(1000000)
#define DEAUTH_DEFENCE_PAIR_WINDOW_US INT64_C(10000000)
#define DEAUTH_DEFENCE_PMKID_COOLDOWN_US INT64_C(5000000)
#define DEAUTH_DEFENCE_IDLE_RELEASE_US INT64_C(20000000)

typedef enum {
    DEF_TRIG_DEAUTH = 0,
    DEF_TRIG_DISASSOC,
    DEF_TRIG_CSA,
    DEF_TRIG_PMKID_PROBE,
} deauth_defence_trigger_t;

typedef enum {
    DEF_ACT_OBSERVE = 0,
    DEF_ACT_DECOY_4WAY,
    DEF_ACT_DECOY_PMKID,
} deauth_defence_action_t;

typedef enum {
    DEF_ARMED_HOPPING = 0,
    DEF_PROVISIONAL_LOCK,
    DEF_FAST_RESPONSE,
    DEF_CONFIRMING,
    DEF_CONFIRMED_LOCK,
    DEF_RELEASE,
} deauth_defence_state_t;

typedef struct {
    deauth_defence_trigger_t trigger;
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t channel;
    bool selected;
    bool wpa2_psk_ccmp;
} deauth_defence_observation_t;

typedef struct {
    deauth_defence_action_t action;
    const char *reason;
    bool enter_provisional_lock;
} deauth_defence_decision_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    int64_t pair_times_us[3];
    int64_t last_seen_us;
    uint8_t pair_count;
} deauth_defence_target_rate_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    uint8_t sta[6];
    int64_t last_pmkid_us;
    int64_t last_seen_us;
    bool has_pmkid;
} deauth_defence_station_rate_t;

typedef struct {
    deauth_defence_state_t state;
    bool pmkid_decoy_enabled;
    bool response_satisfied;
    uint32_t generation;
    uint8_t active_bssid[6];
    uint8_t active_channel;
    int64_t last_activity_us;
    int64_t last_now_us;
    bool has_time;
    deauth_defence_target_rate_t targets[DEAUTH_DEFENCE_TARGET_SLOTS];
    deauth_defence_station_rate_t stations[DEAUTH_DEFENCE_STATION_SLOTS];
} deauth_defence_core_t;

void deauth_defence_core_reset(deauth_defence_core_t *core,
                               bool pmkid_decoy_enabled,
                               uint32_t generation);

deauth_defence_decision_t deauth_defence_consume(
    deauth_defence_core_t *core,
    const deauth_defence_observation_t *observation,
    int64_t now_us);

bool deauth_defence_response_started(deauth_defence_core_t *core);
bool deauth_defence_confirmation_started(deauth_defence_core_t *core);
bool deauth_defence_response_succeeded(deauth_defence_core_t *core);
bool deauth_defence_abort_attempt(deauth_defence_core_t *core);
bool deauth_defence_confirm_lock(deauth_defence_core_t *core,
                                 const uint8_t bssid[6], uint8_t channel,
                                 int64_t now_us);
bool deauth_defence_release_if_idle(deauth_defence_core_t *core,
                                    int64_t now_us);
bool deauth_defence_rearm(deauth_defence_core_t *core);
