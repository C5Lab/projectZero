#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "deauth_defence_core.h"
#include "wpa_decoy.h"

#define DEAUTH_DEFENCE_RUNTIME_TARGETS DEAUTH_DEFENCE_TARGET_SLOTS
#define DEAUTH_DEFENCE_SUPPRESSION_REASONS 3U
#define DEAUTH_DEFENCE_SUPPRESSION_SLOTS \
    (DEAUTH_DEFENCE_RUNTIME_TARGETS * DEAUTH_DEFENCE_SUPPRESSION_REASONS)

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    bool wpa2_psk_ccmp;
} deauth_defence_runtime_target_t;

typedef bool (*deauth_defence_random_fn)(void *opaque, uint8_t *out,
                                         size_t length);
typedef int (*deauth_defence_tune_fn)(void *opaque, uint8_t channel);
typedef int (*deauth_defence_radio_enter_fn)(void *opaque, uint8_t channel);
typedef int (*deauth_defence_radio_leave_fn)(void *opaque);
typedef int (*deauth_defence_tx_fn)(void *opaque, const uint8_t *frame,
                                    size_t length, bool en_sys_seq);
typedef int64_t (*deauth_defence_now_fn)(void *opaque);
typedef void (*deauth_defence_notify_fn)(void *opaque);
typedef void (*deauth_defence_telemetry_fn)(void *opaque, const char *line);
typedef bool (*deauth_defence_pair_builder_fn)(
    const wpa_decoy_material_t *material, wpa_decoy_pair_t *out);
typedef bool (*deauth_defence_pmkid_builder_fn)(
    const wpa_decoy_material_t *material,
    uint8_t out[WPA_DECOY_FRAME_MAX], size_t *out_len);

typedef struct {
    const deauth_defence_runtime_target_t *targets;
    size_t target_count;
    bool pmkid_decoy;
    bool multi_vector;
    uint32_t generation;
    void *opaque;
    deauth_defence_random_fn random;
    deauth_defence_tune_fn tune;
    deauth_defence_radio_enter_fn radio_enter;
    deauth_defence_radio_leave_fn radio_leave;
    deauth_defence_tx_fn tx;
    deauth_defence_now_fn now;
    deauth_defence_notify_fn notify;
    deauth_defence_telemetry_fn telemetry;
    deauth_defence_pair_builder_fn build_pair;
    deauth_defence_pmkid_builder_fn build_pmkid;
} deauth_defence_config_t;

typedef struct {
    uint32_t generation;
    deauth_defence_trigger_t trigger;
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t channel;
    int64_t rx_us;
} deauth_defence_runtime_observation_t;

typedef struct {
    uint32_t observations;
    uint32_t tx_pairs;
    uint32_t pmkid_m1;
    uint32_t satisfied;
    uint32_t errors;
} deauth_defence_runtime_stats_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    const char *reason;
    uint32_t count;
    int64_t started_us;
} deauth_defence_runtime_suppression_t;

typedef struct {
    deauth_defence_core_t core;
    deauth_defence_config_t config;
    deauth_defence_runtime_target_t targets[DEAUTH_DEFENCE_RUNTIME_TARGETS];
    deauth_defence_runtime_suppression_t
        suppression[DEAUTH_DEFENCE_SUPPRESSION_SLOTS];
    deauth_defence_runtime_stats_t stats;
    uint32_t active_satisfied;
    deauth_defence_action_t active_response;
    bool started;
    bool announced;
    bool response_sent;
    bool response_activity;
    bool observation_log_suppressed;
    atomic_bool armed;
    atomic_bool processing;
    atomic_uint tx_gate;
} deauth_defence_runtime_t;

bool deauth_defence_runtime_start(deauth_defence_runtime_t *runtime,
                                  const deauth_defence_config_t *config);
bool deauth_defence_runtime_arm(deauth_defence_runtime_t *runtime,
                                uint32_t generation);
void deauth_defence_runtime_notify(deauth_defence_runtime_t *runtime);
bool deauth_defence_runtime_process(
    deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation);
bool deauth_defence_runtime_confirm(deauth_defence_runtime_t *runtime,
                                    const uint8_t bssid[6], uint8_t channel);
bool deauth_defence_runtime_abort_confirmation(
    deauth_defence_runtime_t *runtime);
bool deauth_defence_runtime_poll_idle(deauth_defence_runtime_t *runtime);
void deauth_defence_runtime_request_stop(deauth_defence_runtime_t *runtime);
bool deauth_defence_runtime_join(deauth_defence_runtime_t *runtime,
                                 uint32_t timeout_ticks);
void deauth_defence_runtime_quiesce(deauth_defence_runtime_t *runtime);
void deauth_defence_runtime_finish_stop(deauth_defence_runtime_t *runtime,
                                        uint32_t dropped);
