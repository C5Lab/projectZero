#include "deauth_defence_runtime.h"

#include <stdio.h>
#include <string.h>

#define TX_GATE_STOP UINT32_C(0x80000000)
#define TX_GATE_ACTIVE_MASK UINT32_C(0x7fffffff)
#define SUPPRESSION_WINDOW_US INT64_C(1000000)

static void secure_zero(void *value, size_t length)
{
    volatile uint8_t *bytes = value;
    while (length--) *bytes++ = 0U;
}

static bool nonzero_unicast(const uint8_t address[6])
{
    if (!address || (address[0] & 1U) != 0U) return false;
    uint8_t combined = 0U;
    for (size_t i = 0; i < 6U; ++i) combined |= address[i];
    return combined != 0U;
}

static void emit(deauth_defence_runtime_t *runtime, const char *line)
{
    if (runtime->config.telemetry) {
        runtime->config.telemetry(runtime->config.opaque, line);
    }
}

static const char *trigger_name(deauth_defence_trigger_t trigger)
{
    switch (trigger) {
        case DEF_TRIG_DEAUTH: return "deauth";
        case DEF_TRIG_DISASSOC: return "disassoc";
        case DEF_TRIG_CSA: return "csa";
        case DEF_TRIG_PMKID_PROBE: return "pmkid_probe";
        default: return "unknown";
    }
}

static const char *action_name(deauth_defence_action_t action)
{
    switch (action) {
        case DEF_ACT_DECOY_4WAY: return "decoy_4way";
        case DEF_ACT_DECOY_PMKID: return "decoy_pmkid";
        default: return "observe";
    }
}

static const deauth_defence_runtime_target_t *find_target(
    const deauth_defence_runtime_t *runtime, const uint8_t bssid[6])
{
    for (size_t i = 0; i < runtime->config.target_count; ++i) {
        if (memcmp(runtime->targets[i].bssid, bssid, 6U) == 0) {
            return &runtime->targets[i];
        }
    }
    return NULL;
}

static void emit_trigger(
    deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation,
    deauth_defence_action_t action, const char *reason)
{
    char line[256];
    if (observation->trigger == DEF_TRIG_PMKID_PROBE) {
        snprintf(line, sizeof(line),
                 "[DETECTOR_DEFENCE] trigger=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X STA=%02X:%02X:%02X:%02X:%02X:%02X RX=%u decision=%s reason=%s",
                 trigger_name(observation->trigger),
                 observation->bssid[0], observation->bssid[1],
                 observation->bssid[2], observation->bssid[3],
                 observation->bssid[4], observation->bssid[5],
                 observation->sta[0], observation->sta[1], observation->sta[2],
                 observation->sta[3], observation->sta[4], observation->sta[5],
                 (unsigned)observation->channel, action_name(action), reason);
    } else {
        snprintf(line, sizeof(line),
                 "[DETECTOR_DEFENCE] trigger=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X STA=- RX=%u decision=%s reason=%s",
                 trigger_name(observation->trigger),
                 observation->bssid[0], observation->bssid[1],
                 observation->bssid[2], observation->bssid[3],
                 observation->bssid[4], observation->bssid[5],
                 (unsigned)observation->channel, action_name(action), reason);
    }
    emit(runtime, line);
}

static int64_t response_latency(
    const deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation)
{
    int64_t now_us = runtime->config.now(runtime->config.opaque);
    return now_us >= observation->rx_us ? now_us - observation->rx_us : 0;
}

static void emit_tx(
    deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation,
    deauth_defence_action_t action, bool success, unsigned frames,
    const char *error)
{
    char line[256];
    const char *stage = action == DEF_ACT_DECOY_PMKID
                            ? "m1_pmkid" : "m1_m2";
    snprintf(line, sizeof(line),
             "[DETECTOR_DEFENCE] tx=%s stage=%s result=%s frames=%u latency_us=%lld error=%s",
             action_name(action), stage, success ? "ok" : "error", frames,
             (long long)response_latency(runtime, observation), error);
    emit(runtime, line);
}

static bool suppressible_reason(const char *reason)
{
    return reason &&
        (strcmp(reason, "rate_limited_cooldown") == 0 ||
         strcmp(reason, "rate_limited_window") == 0 ||
         strcmp(reason, "pmkid_rate_limited") == 0);
}

static void increment_saturating(uint32_t *value)
{
    if (value && *value != UINT32_MAX) ++*value;
}

static void emit_suppression(
    deauth_defence_runtime_t *runtime,
    deauth_defence_runtime_suppression_t *suppression)
{
    if (!suppression->used || suppression->count == 0U) return;
    char line[224];
    snprintf(line, sizeof(line),
             "[DETECTOR_DEFENCE] suppressed=%lu reason=%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X window_ms=1000",
             (unsigned long)suppression->count, suppression->reason,
             suppression->bssid[0], suppression->bssid[1],
             suppression->bssid[2], suppression->bssid[3],
             suppression->bssid[4], suppression->bssid[5]);
    emit(runtime, line);
    memset(suppression, 0, sizeof(*suppression));
}

static void flush_suppressions(deauth_defence_runtime_t *runtime,
                               int64_t now_us, bool force)
{
    for (size_t i = 0; i < DEAUTH_DEFENCE_SUPPRESSION_SLOTS; ++i) {
        deauth_defence_runtime_suppression_t *suppression =
            &runtime->suppression[i];
        if (!suppression->used) continue;
        if (force ||
            (now_us >= suppression->started_us &&
             now_us - suppression->started_us >= SUPPRESSION_WINDOW_US)) {
            emit_suppression(runtime, suppression);
        }
    }
}

static bool record_suppression(deauth_defence_runtime_t *runtime,
                               const uint8_t bssid[6], const char *reason,
                               int64_t now_us)
{
    if (!suppressible_reason(reason)) return false;
    deauth_defence_runtime_suppression_t *free_slot = NULL;
    for (size_t i = 0; i < DEAUTH_DEFENCE_SUPPRESSION_SLOTS; ++i) {
        deauth_defence_runtime_suppression_t *suppression =
            &runtime->suppression[i];
        if (suppression->used && strcmp(suppression->reason, reason) == 0 &&
            memcmp(suppression->bssid, bssid, 6U) == 0) {
            if (suppression->count != UINT32_MAX) ++suppression->count;
            runtime->observation_log_suppressed = true;
            return true;
        }
        if (!suppression->used && !free_slot) free_slot = suppression;
    }
    if (!free_slot) return false;
    free_slot->used = true;
    memcpy(free_slot->bssid, bssid, 6U);
    free_slot->reason = reason;
    free_slot->count = 1U;
    free_slot->started_us = now_us;
    runtime->observation_log_suppressed = true;
    return true;
}

static bool finish_error(
    deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation,
    deauth_defence_action_t action, unsigned frames, const char *error,
    bool provisional)
{
    increment_saturating(&runtime->stats.errors);
    runtime->response_sent = false;
    runtime->observation_log_suppressed = false;
    emit_tx(runtime, observation, action, false, frames, error);
    if (provisional) deauth_defence_abort_attempt(&runtime->core);
    atomic_store_explicit(&runtime->processing, false, memory_order_release);
    return false;
}

static bool tx_claim(deauth_defence_runtime_t *runtime)
{
    unsigned gate = atomic_load_explicit(&runtime->tx_gate,
                                         memory_order_acquire);
    for (;;) {
        if ((gate & TX_GATE_STOP) != 0U ||
            (gate & TX_GATE_ACTIVE_MASK) == TX_GATE_ACTIVE_MASK) {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &runtime->tx_gate, &gate, gate + 1U,
                memory_order_acq_rel, memory_order_acquire)) {
            return true;
        }
    }
}

static void tx_release(deauth_defence_runtime_t *runtime)
{
    (void)atomic_fetch_sub_explicit(&runtime->tx_gate, 1U,
                                    memory_order_release);
}

static bool stop_is_requested(const deauth_defence_runtime_t *runtime)
{
    return (atomic_load_explicit(&runtime->tx_gate, memory_order_acquire) &
            TX_GATE_STOP) != 0U;
}

bool deauth_defence_runtime_start(deauth_defence_runtime_t *runtime,
                                  const deauth_defence_config_t *config)
{
    if (!runtime || !config || !config->targets || config->target_count == 0U ||
        config->target_count > DEAUTH_DEFENCE_RUNTIME_TARGETS ||
        !config->random || !config->tune || !config->tx || !config->now) {
        return false;
    }
    for (size_t i = 0; i < config->target_count; ++i) {
        if (!nonzero_unicast(config->targets[i].bssid) ||
            config->targets[i].channel == 0U) return false;
    }
    memset(runtime, 0, sizeof(*runtime));
    memcpy(runtime->targets, config->targets,
           config->target_count * sizeof(runtime->targets[0]));
    runtime->config = *config;
    runtime->config.targets = runtime->targets;
    runtime->started = true;
    atomic_init(&runtime->armed, false);
    atomic_init(&runtime->processing, false);
    atomic_init(&runtime->tx_gate, 0U);
    deauth_defence_core_reset(&runtime->core, config->pmkid_decoy,
                              config->generation);
    return true;
}

bool deauth_defence_runtime_arm(deauth_defence_runtime_t *runtime,
                                uint32_t generation)
{
    if (!runtime || !runtime->started || generation == 0U ||
        runtime->announced || stop_is_requested(runtime)) {
        return false;
    }
    runtime->config.generation = generation;
    deauth_defence_core_reset(&runtime->core,
                              runtime->config.pmkid_decoy, generation);
    char line[128];
    snprintf(line, sizeof(line),
             "[DETECTOR_DEFENCE] armed targets=%u trace=fast pmkid=%s",
             (unsigned)runtime->config.target_count,
             runtime->config.pmkid_decoy ? "decoy" : "monitor");
    runtime->announced = true;
    atomic_store_explicit(&runtime->armed, true, memory_order_release);
    emit(runtime, line);
    return true;
}

void deauth_defence_runtime_notify(deauth_defence_runtime_t *runtime)
{
    if (runtime && runtime->started &&
        atomic_load_explicit(&runtime->armed, memory_order_acquire) &&
        !stop_is_requested(runtime) &&
        runtime->config.notify) {
        runtime->config.notify(runtime->config.opaque);
    }
}

bool deauth_defence_runtime_process(
    deauth_defence_runtime_t *runtime,
    const deauth_defence_runtime_observation_t *observation)
{
    if (!runtime || !observation || !runtime->started ||
        !atomic_load_explicit(&runtime->armed, memory_order_acquire) ||
        stop_is_requested(runtime)) return false;
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &runtime->processing, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) return false;
    runtime->observation_log_suppressed = false;
    if (!atomic_load_explicit(&runtime->armed, memory_order_acquire) ||
        stop_is_requested(runtime)) {
        atomic_store_explicit(&runtime->processing, false,
                              memory_order_release);
        return false;
    }
    runtime->response_sent = false;
    runtime->response_activity = false;

    if (observation->generation != runtime->core.generation) {
        emit_trigger(runtime, observation, DEF_ACT_OBSERVE,
                     "stale_generation");
        atomic_store_explicit(&runtime->processing, false,
                              memory_order_release);
        return true;
    }

    const deauth_defence_runtime_target_t *target =
        find_target(runtime, observation->bssid);
    if (target) increment_saturating(&runtime->stats.observations);
    uint8_t response_channel = target ? target->channel : observation->channel;
    deauth_defence_observation_t policy = {
        .trigger = observation->trigger,
        .channel = response_channel,
        .selected = target != NULL,
        .wpa2_psk_ccmp = target && target->wpa2_psk_ccmp,
    };
    memcpy(policy.bssid, observation->bssid, 6U);
    memcpy(policy.sta, observation->sta, 6U);
    int64_t now_us = runtime->config.now(runtime->config.opaque);
    deauth_defence_decision_t decision =
        deauth_defence_consume(&runtime->core, &policy, now_us);
    bool response_satisfied = decision.action == DEF_ACT_OBSERVE &&
        strcmp(decision.reason, "response_satisfied") == 0;
    if (response_satisfied) {
        runtime->response_activity = true;
        runtime->observation_log_suppressed = true;
        increment_saturating(&runtime->stats.satisfied);
        increment_saturating(&runtime->active_satisfied);
    }
    flush_suppressions(runtime, now_us, false);
    if (response_satisfied) {
        atomic_store_explicit(&runtime->processing, false,
                              memory_order_release);
        return true;
    }
    if (decision.action == DEF_ACT_OBSERVE &&
        record_suppression(runtime, observation->bssid, decision.reason,
                           now_us)) {
        atomic_store_explicit(&runtime->processing, false,
                              memory_order_release);
        return true;
    }
    emit_trigger(runtime, observation, decision.action, decision.reason);
    if (decision.action == DEF_ACT_OBSERVE) {
        atomic_store_explicit(&runtime->processing, false,
                              memory_order_release);
        return true;
    }

    bool provisional = decision.enter_provisional_lock;
    if (provisional) {
        char line[160];
        snprintf(line, sizeof(line),
                 "[DETECTOR_DEFENCE] provisional_bssid=%02X:%02X:%02X:%02X:%02X:%02X channel=%u",
                 observation->bssid[0], observation->bssid[1],
                 observation->bssid[2], observation->bssid[3],
                 observation->bssid[4], observation->bssid[5],
                 (unsigned)response_channel);
        emit(runtime, line);
    }
    if (runtime->config.tune(runtime->config.opaque,
                             response_channel) != 0) {
        return finish_error(runtime, observation, decision.action, 0U,
                            "tune", provisional);
    }
    if (provisional && !deauth_defence_response_started(&runtime->core)) {
        return finish_error(runtime, observation, decision.action, 0U,
                            "state", provisional);
    }

    wpa_decoy_material_t material = {0};
    wpa_decoy_pair_t pair = {0};
    uint8_t pmkid_frame[WPA_DECOY_FRAME_MAX] = {0};
    size_t pmkid_length = 0U;
    memcpy(material.bssid, observation->bssid, 6U);
    bool random_ok = runtime->config.random(runtime->config.opaque,
                                            material.pmk,
                                            sizeof(material.pmk)) &&
        runtime->config.random(runtime->config.opaque, material.anonce,
                               sizeof(material.anonce)) &&
        runtime->config.random(runtime->config.opaque, material.snonce,
                               sizeof(material.snonce));
    if (decision.action == DEF_ACT_DECOY_PMKID) {
        memcpy(material.sta, observation->sta, 6U);
    } else {
        random_ok = random_ok && runtime->config.random(
            runtime->config.opaque, material.sta, sizeof(material.sta));
        material.sta[0] = (uint8_t)((material.sta[0] | 0x02U) & 0xfeU);
    }
    random_ok = random_ok && runtime->config.random(
        runtime->config.opaque, (uint8_t *)&material.replay_counter,
        sizeof(material.replay_counter));
    if (!random_ok) {
        secure_zero(&material, sizeof(material));
        return finish_error(runtime, observation, decision.action, 0U,
                            "random", provisional);
    }

    bool built;
    if (decision.action == DEF_ACT_DECOY_PMKID) {
        deauth_defence_pmkid_builder_fn builder = runtime->config.build_pmkid
            ? runtime->config.build_pmkid : wpa_decoy_build_pmkid_m1;
        built = builder(&material, pmkid_frame, &pmkid_length);
    } else {
        deauth_defence_pair_builder_fn builder = runtime->config.build_pair
            ? runtime->config.build_pair : wpa_decoy_build_pair;
        built = builder(&material, &pair);
    }
    if (!built) {
        secure_zero(&material, sizeof(material));
        secure_zero(&pair, sizeof(pair));
        secure_zero(pmkid_frame, sizeof(pmkid_frame));
        return finish_error(runtime, observation, decision.action, 0U,
                            "builder", provisional);
    }

    const uint8_t *first = decision.action == DEF_ACT_DECOY_PMKID
                               ? pmkid_frame : pair.m1;
    size_t first_length = decision.action == DEF_ACT_DECOY_PMKID
                              ? pmkid_length : pair.m1_len;
    if (!tx_claim(runtime)) {
        secure_zero(&material, sizeof(material));
        secure_zero(&pair, sizeof(pair));
        secure_zero(pmkid_frame, sizeof(pmkid_frame));
        return finish_error(runtime, observation, decision.action, 0U,
                            "stopped", provisional);
    }
    int first_result = runtime->config.tx(runtime->config.opaque, first,
                                          first_length, true);
    tx_release(runtime);
    unsigned sent = first_result == 0 ? 1U : 0U;
    if (first_result != 0) {
        secure_zero(&material, sizeof(material));
        secure_zero(&pair, sizeof(pair));
        secure_zero(pmkid_frame, sizeof(pmkid_frame));
        return finish_error(runtime, observation, decision.action, sent,
                            "m1_tx", provisional);
    }
    if (decision.action == DEF_ACT_DECOY_4WAY) {
        if (stop_is_requested(runtime)) {
            secure_zero(&material, sizeof(material));
            secure_zero(&pair, sizeof(pair));
            secure_zero(pmkid_frame, sizeof(pmkid_frame));
            return finish_error(runtime, observation, decision.action, sent,
                                "stopped", provisional);
        }
        if (!tx_claim(runtime)) {
            secure_zero(&material, sizeof(material));
            secure_zero(&pair, sizeof(pair));
            secure_zero(pmkid_frame, sizeof(pmkid_frame));
            return finish_error(runtime, observation, decision.action, sent,
                                "stopped", provisional);
        }
        int second_result = runtime->config.tx(runtime->config.opaque, pair.m2,
                                               pair.m2_len, true);
        tx_release(runtime);
        if (second_result != 0) {
            secure_zero(&material, sizeof(material));
            secure_zero(&pair, sizeof(pair));
            return finish_error(runtime, observation, decision.action, sent,
                                "m2_tx", provisional);
        }
        ++sent;
        increment_saturating(&runtime->stats.tx_pairs);
    } else {
        increment_saturating(&runtime->stats.pmkid_m1);
    }
    secure_zero(&material, sizeof(material));
    secure_zero(&pair, sizeof(pair));
    secure_zero(pmkid_frame, sizeof(pmkid_frame));
    emit_tx(runtime, observation, decision.action, true, sent, "none");
    if (provisional) deauth_defence_confirmation_started(&runtime->core);
    (void)deauth_defence_response_succeeded(&runtime->core);
    runtime->active_response = decision.action;
    runtime->response_sent = true;
    runtime->response_activity = true;
    atomic_store_explicit(&runtime->processing, false, memory_order_release);
    return true;
}

bool deauth_defence_runtime_confirm(deauth_defence_runtime_t *runtime,
                                    const uint8_t bssid[6], uint8_t channel)
{
    if (!runtime || !runtime->started ||
        !atomic_load_explicit(&runtime->armed, memory_order_acquire) ||
        stop_is_requested(runtime)) return false;
    const deauth_defence_runtime_target_t *target =
        find_target(runtime, bssid);
    uint8_t response_channel = target ? target->channel : channel;
    return deauth_defence_confirm_lock(
        &runtime->core, bssid, response_channel,
        runtime->config.now(runtime->config.opaque));
}

bool deauth_defence_runtime_abort_confirmation(
    deauth_defence_runtime_t *runtime)
{
    if (!runtime || !runtime->started ||
        !atomic_load_explicit(&runtime->armed, memory_order_acquire) ||
        stop_is_requested(runtime)) return false;
    if (!deauth_defence_abort_attempt(&runtime->core)) return false;
    runtime->active_satisfied = 0U;
    runtime->active_response = DEF_ACT_OBSERVE;
    return true;
}

bool deauth_defence_runtime_poll_idle(deauth_defence_runtime_t *runtime)
{
    if (!runtime || !runtime->started ||
        !atomic_load_explicit(&runtime->armed, memory_order_acquire) ||
        stop_is_requested(runtime)) return false;
    int64_t now_us = runtime->config.now(runtime->config.opaque);
    flush_suppressions(runtime, now_us, false);
    uint8_t bssid[6];
    memcpy(bssid, runtime->core.active_bssid, sizeof(bssid));
    uint8_t channel = runtime->core.active_channel;
    uint32_t satisfied = runtime->active_satisfied;
    deauth_defence_action_t response = runtime->active_response;
    if (!deauth_defence_release_if_idle(&runtime->core, now_us)) {
        return false;
    }
    char line[224];
    snprintf(line, sizeof(line),
             "[DETECTOR_DEFENCE] released_bssid=%02X:%02X:%02X:%02X:%02X:%02X channel=%u reason=idle idle_ms=20000 response=%s suppressed=%lu",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
             (unsigned)channel, action_name(response),
             (unsigned long)satisfied);
    emit(runtime, line);
    runtime->active_satisfied = 0U;
    runtime->active_response = DEF_ACT_OBSERVE;
    deauth_defence_rearm(&runtime->core);
    return true;
}

void deauth_defence_runtime_request_stop(deauth_defence_runtime_t *runtime)
{
    if (!runtime) return;
    /* This single RMW is the Stop linearization point. A TX claim that wins
     * before it is in-flight and joined; every later claim observes STOP. */
    (void)atomic_fetch_or_explicit(&runtime->tx_gate, TX_GATE_STOP,
                                   memory_order_acq_rel);
}

bool deauth_defence_runtime_join(deauth_defence_runtime_t *runtime,
                                 uint32_t timeout_ticks)
{
    (void)timeout_ticks;
    return runtime &&
        !atomic_load_explicit(&runtime->processing, memory_order_acquire) &&
        (atomic_load_explicit(&runtime->tx_gate, memory_order_acquire) &
         TX_GATE_ACTIVE_MASK) == 0U;
}

void deauth_defence_runtime_quiesce(deauth_defence_runtime_t *runtime)
{
    if (!runtime || !runtime->started) return;
    atomic_store_explicit(&runtime->armed, false, memory_order_release);
    runtime->response_sent = false;
    runtime->response_activity = false;
    runtime->active_satisfied = 0U;
    runtime->active_response = DEF_ACT_OBSERVE;
    runtime->observation_log_suppressed = false;
    secure_zero(&runtime->core, sizeof(runtime->core));
    secure_zero(runtime->targets, sizeof(runtime->targets));
}

void deauth_defence_runtime_finish_stop(deauth_defence_runtime_t *runtime,
                                        uint32_t dropped)
{
    if (!runtime || !runtime->started) return;
    flush_suppressions(runtime,
                       runtime->config.now(runtime->config.opaque), true);
    if (runtime->announced) {
        char line[256];
        unsigned long long responses =
            (unsigned long long)runtime->stats.tx_pairs +
            (unsigned long long)runtime->stats.pmkid_m1;
        const char *outcome = responses > 0U ? "responded" :
            (runtime->stats.observations > 0U ? "observed" : "idle");
        snprintf(line, sizeof(line),
                 "[DETECTOR_DEFENCE] stopped observations=%lu tx_pairs=%lu pmkid_m1=%lu responses=%llu satisfied=%lu errors=%lu dropped=%lu outcome=%s",
                 (unsigned long)runtime->stats.observations,
                 (unsigned long)runtime->stats.tx_pairs,
                 (unsigned long)runtime->stats.pmkid_m1,
                 responses, (unsigned long)runtime->stats.satisfied,
                 (unsigned long)runtime->stats.errors, (unsigned long)dropped,
                 outcome);
        emit(runtime, line);
    }
    deauth_defence_runtime_quiesce(runtime);
    secure_zero(runtime->suppression, sizeof(runtime->suppression));
    runtime->started = false;
    runtime->announced = false;
    (void)atomic_fetch_or_explicit(&runtime->tx_gate, TX_GATE_STOP,
                                   memory_order_release);
}
