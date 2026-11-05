#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "deauth_defence_core.h"

static const uint8_t AP_A[6] = {0x02, 0, 0, 0, 0, 1};
static const uint8_t AP_B[6] = {0x02, 0, 0, 0, 0, 2};
static const uint8_t STA_A[6] = {0x06, 0, 0, 0, 0, 1};

static deauth_defence_observation_t observation(
    deauth_defence_trigger_t trigger)
{
    deauth_defence_observation_t value = {
        .trigger = trigger,
        .channel = 6,
        .selected = true,
        .wpa2_psk_ccmp = true,
    };
    memcpy(value.bssid, AP_A, sizeof(value.bssid));
    memcpy(value.sta, STA_A, sizeof(value.sta));
    return value;
}
static void assert_decision(deauth_defence_decision_t decision,
                            deauth_defence_action_t action,
                            const char *reason, bool provisional)
{
    assert(decision.action == action);
    assert(strcmp(decision.reason, reason) == 0);
    assert(decision.enter_provisional_lock == provisional);
}

static void test_state_machine_and_idle_release(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 7U);
    assert(core.state == DEF_ARMED_HOPPING && core.generation == 7U);

    deauth_defence_observation_t event = observation(DEF_TRIG_DEAUTH);
    int64_t start = INT64_C(1000000);
    assert_decision(deauth_defence_consume(&core, &event, start),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", true);
    assert(core.state == DEF_PROVISIONAL_LOCK);
    assert(memcmp(core.active_bssid, AP_A, 6U) == 0);
    assert(core.active_channel == 6U);
    assert(deauth_defence_response_started(&core));
    assert(core.state == DEF_FAST_RESPONSE);
    assert(deauth_defence_confirmation_started(&core));
    assert(core.state == DEF_CONFIRMING);
    assert(!deauth_defence_confirm_lock(&core, AP_B, 11U, start + 10U));
    assert(deauth_defence_confirm_lock(&core, AP_A, 11U, start + 10U));
    assert(core.state == DEF_CONFIRMED_LOCK && core.active_channel == 11U);

    assert(!deauth_defence_release_if_idle(
        &core, start + 10U + DEAUTH_DEFENCE_IDLE_RELEASE_US - 1));
    assert(deauth_defence_release_if_idle(
        &core, start + 10U + DEAUTH_DEFENCE_IDLE_RELEASE_US));
    assert(core.state == DEF_RELEASE);
    assert(deauth_defence_rearm(&core));
    assert(core.state == DEF_ARMED_HOPPING && core.active_channel == 0U);
    for (size_t i = 0; i < sizeof(core.active_bssid); ++i) {
        assert(core.active_bssid[i] == 0U);
    }
}

static void test_filter_akm_address_channel_and_time_fail_closed(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 1U);
    deauth_defence_observation_t event = observation(DEF_TRIG_DISASSOC);

    event.selected = false;
    assert_decision(deauth_defence_consume(&core, &event, 100U),
                    DEF_ACT_OBSERVE, "unselected_bssid", false);
    event.selected = true;
    event.wpa2_psk_ccmp = false;
    assert_decision(deauth_defence_consume(&core, &event, 101U),
                    DEF_ACT_OBSERVE, "observe_only_unsupported_akm", false);
    event.wpa2_psk_ccmp = true;
    event.channel = 0U;
    assert_decision(deauth_defence_consume(&core, &event, 102U),
                    DEF_ACT_OBSERVE, "invalid_observation", false);
    event.channel = 6U;
    event.bssid[0] |= 1U;
    assert_decision(deauth_defence_consume(&core, &event, 103U),
                    DEF_ACT_OBSERVE, "invalid_observation", false);
    event = observation(DEF_TRIG_DEAUTH);
    assert_decision(deauth_defence_consume(&core, &event, -1),
                    DEF_ACT_OBSERVE, "invalid_time", false);

    assert_decision(deauth_defence_consume(&core, &event, 1000U),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", true);
    assert_decision(deauth_defence_consume(&core, &event, 999U),
                    DEF_ACT_OBSERVE, "clock_regressed", false);
    memcpy(event.bssid, AP_B, 6U);
    assert_decision(deauth_defence_consume(&core, &event, 2000000U),
                    DEF_ACT_OBSERVE, "busy_other_bssid", false);
}

static void test_pair_cooldown_and_window_are_exact(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 2U);
    deauth_defence_observation_t event = observation(DEF_TRIG_CSA);
    int64_t start = INT64_C(5000000);
    assert_decision(deauth_defence_consume(&core, &event, start),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", true);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + DEAUTH_DEFENCE_PAIR_COOLDOWN_US - 1),
                    DEF_ACT_OBSERVE, "rate_limited_cooldown", false);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + DEAUTH_DEFENCE_PAIR_COOLDOWN_US),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", false);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + 2 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", false);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + 3 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US),
                    DEF_ACT_OBSERVE, "rate_limited_window", false);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + DEAUTH_DEFENCE_PAIR_WINDOW_US),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", false);

    deauth_defence_core_reset(&core, false, false, 9U);
    assert(deauth_defence_consume(&core, &event, start).action ==
           DEF_ACT_DECOY_4WAY);
    assert(deauth_defence_consume(
               &core, &event,
               start + DEAUTH_DEFENCE_PAIR_COOLDOWN_US).action ==
           DEF_ACT_DECOY_4WAY);
    assert(deauth_defence_consume(
               &core, &event,
               start + 9 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US).action ==
           DEF_ACT_DECOY_4WAY);
    assert(deauth_defence_consume(
               &core, &event,
               start + 10 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US).action ==
           DEF_ACT_DECOY_4WAY);
    assert(deauth_defence_consume(
               &core, &event,
               start + 11 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US).action ==
           DEF_ACT_DECOY_4WAY);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + 12 * DEAUTH_DEFENCE_PAIR_COOLDOWN_US),
                    DEF_ACT_OBSERVE, "rate_limited_window", false);
}

static void test_pmkid_is_opt_in_and_station_rate_limited(void)
{
    deauth_defence_observation_t event = observation(DEF_TRIG_PMKID_PROBE);
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 3U);
    assert_decision(deauth_defence_consume(&core, &event, 1000U),
                    DEF_ACT_OBSERVE, "pmkid_monitor", false);

    deauth_defence_core_reset(&core, true, false, 4U);
    assert_decision(deauth_defence_consume(&core, &event, 1000U),
                    DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", true);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        1000U + DEAUTH_DEFENCE_PMKID_COOLDOWN_US - 1),
                    DEF_ACT_OBSERVE, "pmkid_rate_limited", false);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        1000U + DEAUTH_DEFENCE_PMKID_COOLDOWN_US),
                    DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", false);
    event.sta[0] |= 1U;
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        1000U + 2 * DEAUTH_DEFENCE_PMKID_COOLDOWN_US),
                    DEF_ACT_OBSERVE, "invalid_station", false);
}

static void test_pmkid_capacity_fails_closed_without_evicting_cooldown(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, true, false, 10U);
    deauth_defence_observation_t event = observation(DEF_TRIG_PMKID_PROBE);
    int64_t start = INT64_C(1000000);

    for (size_t i = 0; i < DEAUTH_DEFENCE_STATION_SLOTS; ++i) {
        event.sta[5] = (uint8_t)(i + 1U);
        assert_decision(deauth_defence_consume(&core, &event,
                                               start + (int64_t)i),
                        DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", true);
        assert(deauth_defence_abort_attempt(&core));
    }

    event.sta[5] = (uint8_t)(DEAUTH_DEFENCE_STATION_SLOTS + 1U);
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + (int64_t)DEAUTH_DEFENCE_STATION_SLOTS),
                    DEF_ACT_OBSERVE, "pmkid_capacity", false);

    event.sta[5] = 1U;
    assert_decision(deauth_defence_consume(
                        &core, &event,
                        start + (int64_t)DEAUTH_DEFENCE_STATION_SLOTS + 1),
                    DEF_ACT_OBSERVE, "pmkid_rate_limited", false);
}

static void test_burst_is_bounded(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 5U);
    deauth_defence_observation_t event = observation(DEF_TRIG_DEAUTH);
    unsigned actions = 0U;
    for (int64_t i = 0; i < 100000; ++i) {
        deauth_defence_decision_t decision =
            deauth_defence_consume(&core, &event, i);
        if (decision.action == DEF_ACT_DECOY_4WAY) ++actions;
    }
    assert(actions == 1U);

    deauth_defence_core_reset(&core, false, false, 6U);
    for (int64_t i = 0; i < 100000; ++i) {
        event.selected = false;
        event.bssid[5] = (uint8_t)i;
        assert(deauth_defence_consume(&core, &event, i).action ==
               DEF_ACT_OBSERVE);
    }
    assert(core.state == DEF_ARMED_HOPPING);
}

static void test_aborted_attempt_keeps_cooldown_without_false_lock(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, false, false, 8U);
    deauth_defence_observation_t event = observation(DEF_TRIG_DEAUTH);
    assert(deauth_defence_consume(&core, &event, 1000000U).action ==
           DEF_ACT_DECOY_4WAY);
    assert(core.state == DEF_PROVISIONAL_LOCK);
    assert(deauth_defence_abort_attempt(&core));
    assert(core.state == DEF_ARMED_HOPPING);
    assert_decision(deauth_defence_consume(&core, &event, 1000100U),
                    DEF_ACT_OBSERVE, "rate_limited_cooldown", false);
    assert(core.state == DEF_ARMED_HOPPING);
    assert(core.active_channel == 0U);
}

static void test_success_latches_all_decoys_until_idle_release(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, true, false, 11U);
    deauth_defence_observation_t pmkid =
        observation(DEF_TRIG_PMKID_PROBE);
    int64_t start = INT64_C(30000000);

    assert_decision(deauth_defence_consume(&core, &pmkid, start),
                    DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", true);
    assert(deauth_defence_response_started(&core));
    assert(deauth_defence_confirmation_started(&core));
    assert(deauth_defence_response_succeeded(&core));

    deauth_defence_observation_t deauth = observation(DEF_TRIG_DEAUTH);
    assert_decision(deauth_defence_consume(&core, &deauth, start + 1),
                    DEF_ACT_OBSERVE, "response_satisfied", false);
    assert_decision(deauth_defence_consume(&core, &pmkid, start + 2),
                    DEF_ACT_OBSERVE, "response_satisfied", false);

    assert(deauth_defence_confirm_lock(&core, AP_A, 6U, start + 3));
    assert(deauth_defence_release_if_idle(
        &core, start + 3 + DEAUTH_DEFENCE_IDLE_RELEASE_US));
    assert(deauth_defence_rearm(&core));
    assert_decision(deauth_defence_consume(
                        &core, &deauth,
                        start + 4 + DEAUTH_DEFENCE_IDLE_RELEASE_US),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", true);
}

static void test_multi_vector_allows_deauth_after_pmkid(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, true, true, 12U);
    deauth_defence_observation_t pmkid =
        observation(DEF_TRIG_PMKID_PROBE);
    deauth_defence_observation_t deauth = observation(DEF_TRIG_DEAUTH);
    int64_t start = INT64_C(40000000);

    assert_decision(deauth_defence_consume(&core, &pmkid, start),
                    DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", true);
    assert(deauth_defence_response_started(&core));
    assert(deauth_defence_confirmation_started(&core));
    assert(deauth_defence_response_succeeded(&core));
    assert_decision(deauth_defence_consume(&core, &pmkid, start + 1),
                    DEF_ACT_OBSERVE, "response_satisfied", false);

    assert_decision(deauth_defence_consume(&core, &deauth, start + 2),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", false);
    assert(deauth_defence_response_succeeded(&core));
    assert_decision(deauth_defence_consume(&core, &deauth, start + 3),
                    DEF_ACT_OBSERVE, "response_satisfied", false);
    assert_decision(deauth_defence_consume(&core, &pmkid, start + 4),
                    DEF_ACT_OBSERVE, "response_satisfied", false);
}

static void test_multi_vector_allows_pmkid_after_deauth(void)
{
    deauth_defence_core_t core;
    deauth_defence_core_reset(&core, true, true, 13U);
    deauth_defence_observation_t deauth = observation(DEF_TRIG_DEAUTH);
    deauth_defence_observation_t pmkid =
        observation(DEF_TRIG_PMKID_PROBE);
    int64_t start = INT64_C(50000000);

    assert_decision(deauth_defence_consume(&core, &deauth, start),
                    DEF_ACT_DECOY_4WAY, "selected_wpa2", true);
    assert(deauth_defence_response_started(&core));
    assert(deauth_defence_confirmation_started(&core));
    assert(deauth_defence_response_succeeded(&core));
    assert_decision(deauth_defence_consume(&core, &deauth, start + 1),
                    DEF_ACT_OBSERVE, "response_satisfied", false);

    assert_decision(deauth_defence_consume(&core, &pmkid, start + 2),
                    DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in", false);
    assert(deauth_defence_response_succeeded(&core));
    assert_decision(deauth_defence_consume(&core, &pmkid, start + 3),
                    DEF_ACT_OBSERVE, "response_satisfied", false);
}

int main(void)
{
    test_state_machine_and_idle_release();
    test_filter_akm_address_channel_and_time_fail_closed();
    test_pair_cooldown_and_window_are_exact();
    test_pmkid_is_opt_in_and_station_rate_limited();
    test_pmkid_capacity_fails_closed_without_evicting_cooldown();
    test_burst_is_bounded();
    test_aborted_attempt_keeps_cooldown_without_false_lock();
    test_success_latches_all_decoys_until_idle_release();
    test_multi_vector_allows_deauth_after_pmkid();
    test_multi_vector_allows_pmkid_after_deauth();
    puts("deauth defence core: PASS");
    return 0;
}
