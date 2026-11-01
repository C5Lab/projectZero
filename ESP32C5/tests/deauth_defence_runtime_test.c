#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "deauth_defence_runtime.h"

static const uint8_t AP[6] = {0x02, 0, 0, 0, 0, 1};
static const uint8_t AP_B[6] = {0x02, 0, 0, 0, 0, 2};
static const uint8_t STA[6] = {0x06, 5, 4, 3, 2, 1};

typedef struct {
    deauth_defence_runtime_t *runtime;
    int64_t now_us;
    unsigned notify_calls;
    unsigned random_calls;
    unsigned tune_calls;
    unsigned tx_calls;
    unsigned fail_random_call;
    unsigned fail_tx_call;
    bool fail_tune;
    bool fail_builder;
    bool stop_after_first_tx;
    bool stop_before_first_tx;
    atomic_bool block_tx;
    atomic_bool tx_entered;
    uint8_t tuned_channel;
    size_t tx_lengths[16];
    bool tx_system_sequence[16];
    uint8_t tx_frames[16][WPA_DECOY_FRAME_MAX];
    char telemetry[4096];
    size_t telemetry_used;
} fixture_t;

static bool fake_random(void *opaque, uint8_t *out, size_t length)
{
    fixture_t *fixture = opaque;
    ++fixture->random_calls;
    if (fixture->fail_random_call == fixture->random_calls) return false;
    for (size_t i = 0; i < length; ++i) {
        out[i] = (uint8_t)(fixture->random_calls * 29U + i + 1U);
    }
    if (fixture->stop_before_first_tx && fixture->random_calls == 4U) {
        deauth_defence_runtime_request_stop(fixture->runtime);
    }
    return true;
}

static int fake_tune(void *opaque, uint8_t channel)
{
    fixture_t *fixture = opaque;
    ++fixture->tune_calls;
    fixture->tuned_channel = channel;
    return fixture->fail_tune ? -1 : 0;
}

static int fake_tx(void *opaque, const uint8_t *frame, size_t length,
                   bool en_sys_seq)
{
    fixture_t *fixture = opaque;
    assert(fixture->tx_calls < 16U);
    unsigned slot = fixture->tx_calls++;
    fixture->tx_lengths[slot] = length;
    fixture->tx_system_sequence[slot] = en_sys_seq;
    memcpy(fixture->tx_frames[slot], frame, length);
    if (atomic_load_explicit(&fixture->block_tx, memory_order_acquire)) {
        atomic_store_explicit(&fixture->tx_entered, true,
                              memory_order_release);
        while (atomic_load_explicit(&fixture->block_tx,
                                    memory_order_acquire)) {
            sched_yield();
        }
    }
    if (fixture->stop_after_first_tx && fixture->tx_calls == 1U) {
        deauth_defence_runtime_request_stop(fixture->runtime);
    }
    return fixture->fail_tx_call == fixture->tx_calls ? -1 : 0;
}

static int64_t fake_now(void *opaque)
{
    return ((fixture_t *)opaque)->now_us;
}

static void fake_notify(void *opaque)
{
    ++((fixture_t *)opaque)->notify_calls;
}

static void fake_telemetry(void *opaque, const char *line)
{
    fixture_t *fixture = opaque;
    int written = snprintf(fixture->telemetry + fixture->telemetry_used,
                           sizeof(fixture->telemetry) - fixture->telemetry_used,
                           "%s\n", line);
    assert(written > 0);
    fixture->telemetry_used += (size_t)written;
    assert(fixture->telemetry_used < sizeof(fixture->telemetry));
}

static bool failing_pair_builder(const wpa_decoy_material_t *material,
                                 wpa_decoy_pair_t *out)
{
    (void)material;
    memset(out, 0, sizeof(*out));
    return false;
}

static deauth_defence_config_t config_for(fixture_t *fixture, bool pmkid)
{
    static const deauth_defence_runtime_target_t target = {
        .bssid = {0x02, 0, 0, 0, 0, 1},
        .channel = 6,
        .wpa2_psk_ccmp = true,
    };
    return (deauth_defence_config_t){
        .targets = &target,
        .target_count = 1U,
        .pmkid_decoy = pmkid,
        .generation = 7U,
        .opaque = fixture,
        .random = fake_random,
        .tune = fake_tune,
        .tx = fake_tx,
        .now = fake_now,
        .notify = fake_notify,
        .telemetry = fake_telemetry,
    };
}

static deauth_defence_config_t config_for_two(fixture_t *fixture, bool pmkid)
{
    static const deauth_defence_runtime_target_t targets[] = {
        {
            .bssid = {0x02, 0, 0, 0, 0, 1},
            .channel = 6,
            .wpa2_psk_ccmp = true,
        },
        {
            .bssid = {0x02, 0, 0, 0, 0, 2},
            .channel = 6,
            .wpa2_psk_ccmp = true,
        },
    };
    deauth_defence_config_t config = config_for(fixture, pmkid);
    config.targets = targets;
    config.target_count = sizeof(targets) / sizeof(targets[0]);
    return config;
}

static deauth_defence_runtime_observation_t observation(
    deauth_defence_trigger_t trigger, int64_t rx_us)
{
    deauth_defence_runtime_observation_t result = {
        .generation = 7U,
        .trigger = trigger,
        .channel = 6U,
        .rx_us = rx_us,
    };
    memcpy(result.bssid, AP, 6U);
    memcpy(result.sta, STA, 6U);
    return result;
}

static void assert_contains(const fixture_t *fixture, const char *line)
{
    assert(strstr(fixture->telemetry, line) != NULL);
}

static unsigned count_occurrences(const char *text, const char *needle)
{
    unsigned count = 0U;
    size_t length = strlen(needle);
    while ((text = strstr(text, needle)) != NULL) {
        ++count;
        text += length;
    }
    return count;
}

static void successful_fast_pair(void)
{
    fixture_t fixture = {.now_us = 1200500};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(fixture.telemetry[0] == '\0');
    deauth_defence_runtime_notify(&runtime);
    assert(fixture.notify_calls == 0U);
    assert(deauth_defence_runtime_arm(&runtime, 7U));
    assert(!strcmp(fixture.telemetry,
                   "[DETECTOR_DEFENCE] armed targets=1 trace=fast pmkid=monitor\n"));
    deauth_defence_runtime_notify(&runtime);
    assert(fixture.notify_calls == 1U);

    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_DEAUTH, 1200000);
    event.channel = 5U; /* Adjacent-channel RX must not steer selected TX. */
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(fixture.tune_calls == 1U && fixture.tuned_channel == 6U);
    assert(fixture.tx_calls == 2U);
    assert(fixture.tx_lengths[0] == 131U && fixture.tx_lengths[1] == 131U);
    assert(fixture.tx_system_sequence[0] && fixture.tx_system_sequence[1]);
    assert(fixture.tx_frames[0][0] == 0x08U && fixture.tx_frames[0][1] == 0x02U);
    assert(fixture.tx_frames[1][0] == 0x08U && fixture.tx_frames[1][1] == 0x01U);
    assert(runtime.core.state == DEF_CONFIRMING);
    assert(runtime.response_sent);
    assert(runtime.response_activity);
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] trigger=deauth BSSID=02:00:00:00:00:01 STA=- RX=5 decision=decoy_4way reason=selected_wpa2\n");
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] provisional_bssid=02:00:00:00:00:01 channel=6\n");
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] tx=decoy_4way stage=m1_m2 result=ok frames=2 latency_us=500 error=none\n");

    fixture.now_us += DEAUTH_DEFENCE_PAIR_COOLDOWN_US - 1;
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(!runtime.response_sent);
    assert(runtime.response_activity);
    assert(runtime.observation_log_suppressed);
    assert(fixture.tx_calls == 2U);
    assert(count_occurrences(fixture.telemetry, "trigger=deauth") == 1U);
    fixture.now_us += INT64_C(1000000);
    assert(!deauth_defence_runtime_poll_idle(&runtime));
    assert(!strstr(fixture.telemetry,
                   "reason=response_satisfied"));

    deauth_defence_runtime_observation_t stale = event;
    stale.generation = 6U;
    assert(deauth_defence_runtime_process(&runtime, &stale));
    assert(!runtime.response_activity);
    assert(!runtime.observation_log_suppressed);

    assert(deauth_defence_runtime_confirm(&runtime, AP, 6U));
    fixture.now_us += DEAUTH_DEFENCE_IDLE_RELEASE_US - 1;
    assert(!deauth_defence_runtime_poll_idle(&runtime));
    fixture.now_us += 1;
    assert(deauth_defence_runtime_poll_idle(&runtime));
    assert(runtime.core.state == DEF_ARMED_HOPPING);
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] released_bssid=02:00:00:00:00:01 channel=6 reason=idle idle_ms=20000 response=decoy_4way suppressed=1\n");

    deauth_defence_runtime_request_stop(&runtime);
    assert(deauth_defence_runtime_join(&runtime, 0U));
    deauth_defence_runtime_finish_stop(&runtime, 3U);
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] stopped observations=2 tx_pairs=1 pmkid_m1=0 responses=1 satisfied=1 errors=0 dropped=3 outcome=responded\n");
}

static void failure_case(const char *expected, unsigned random_failure,
                         bool tune_failure, bool builder_failure,
                         unsigned tx_failure, bool stop_after_first,
                         bool stop_before_first,
                         unsigned expected_frames)
{
    fixture_t fixture = {
        .now_us = 2000100,
        .fail_random_call = random_failure,
        .fail_tune = tune_failure,
        .fail_tx_call = tx_failure,
        .stop_after_first_tx = stop_after_first,
        .stop_before_first_tx = stop_before_first,
    };
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    if (builder_failure) config.build_pair = failing_pair_builder;
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));
    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_DISASSOC, 2000000);
    assert(!deauth_defence_runtime_process(&runtime, &event));
    assert(!runtime.response_activity);
    assert(fixture.tx_calls == expected_frames);
    assert_contains(&fixture, expected);
    assert(runtime.stats.errors == 1U);
    assert(runtime.core.state == DEF_ARMED_HOPPING);
}

static void bounded_failures(void)
{
    failure_case("result=error frames=0 latency_us=100 error=random\n",
                 1U, false, false, 0U, false, false, 0U);
    failure_case("result=error frames=0 latency_us=100 error=tune\n",
                 0U, true, false, 0U, false, false, 0U);
    failure_case("result=error frames=0 latency_us=100 error=builder\n",
                 0U, false, true, 0U, false, false, 0U);
    failure_case("result=error frames=0 latency_us=100 error=m1_tx\n",
                 0U, false, false, 1U, false, false, 1U);
    failure_case("result=error frames=1 latency_us=100 error=m2_tx\n",
                 0U, false, false, 2U, false, false, 2U);
    failure_case("result=error frames=1 latency_us=100 error=stopped\n",
                 0U, false, false, 0U, true, false, 1U);
    failure_case("result=error frames=0 latency_us=100 error=stopped\n",
                 0U, false, false, 0U, false, true, 0U);
}

static void failed_response_reports_observed_outcome_on_stop(void)
{
    fixture_t fixture = {.now_us = 2500100, .fail_tune = true};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));
    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_DEAUTH, 2500000);
    assert(!deauth_defence_runtime_process(&runtime, &event));

    deauth_defence_runtime_request_stop(&runtime);
    assert(deauth_defence_runtime_join(&runtime, 0U));
    deauth_defence_runtime_finish_stop(&runtime, 0U);
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] stopped observations=1 tx_pairs=0 pmkid_m1=0 responses=0 satisfied=0 errors=1 dropped=0 outcome=observed\n");
}

static void empty_session_reports_idle_outcome_on_stop(void)
{
    fixture_t fixture = {.now_us = 2600000};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    deauth_defence_runtime_request_stop(&runtime);
    assert(deauth_defence_runtime_join(&runtime, 0U));
    deauth_defence_runtime_finish_stop(&runtime, 0U);
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] stopped observations=0 tx_pairs=0 pmkid_m1=0 responses=0 satisfied=0 errors=0 dropped=0 outcome=idle\n");
}

static void pmkid_and_stale_generation(void)
{
    fixture_t fixture = {.now_us = 3000400};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, true);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    deauth_defence_runtime_observation_t stale =
        observation(DEF_TRIG_PMKID_PROBE, 3000000);
    stale.generation = 6U;
    assert(deauth_defence_runtime_process(&runtime, &stale));
    assert(!runtime.observation_log_suppressed);
    assert(fixture.tune_calls == 0U && fixture.tx_calls == 0U);
    assert_contains(&fixture,
        "trigger=pmkid_probe BSSID=02:00:00:00:00:01 STA=06:05:04:03:02:01 RX=6 decision=observe reason=stale_generation\n");

    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_PMKID_PROBE, 3000000);
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(fixture.tx_calls == 1U && fixture.tx_lengths[0] == 153U);
    assert(fixture.tx_system_sequence[0]);
    assert(runtime.stats.pmkid_m1 == 1U);
    assert_contains(&fixture,
        "decision=decoy_pmkid reason=pmkid_decoy_opt_in\n");
    assert_contains(&fixture,
        "tx=decoy_pmkid stage=m1_pmkid result=ok frames=1 latency_us=400 error=none\n");

    fixture.now_us += 100;
    deauth_defence_runtime_observation_t deauth =
        observation(DEF_TRIG_DEAUTH, fixture.now_us);
    assert(deauth_defence_runtime_process(&runtime, &deauth));
    assert(runtime.observation_log_suppressed);
    assert(fixture.tx_calls == 1U);

    fixture.now_us += INT64_C(1000000);
    assert(!deauth_defence_runtime_poll_idle(&runtime));
    assert(!strstr(fixture.telemetry, "reason=response_satisfied"));
    assert(deauth_defence_runtime_confirm(&runtime, AP, 6U));
    fixture.now_us += DEAUTH_DEFENCE_IDLE_RELEASE_US;
    assert(deauth_defence_runtime_poll_idle(&runtime));
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] released_bssid=02:00:00:00:00:01 channel=6 reason=idle idle_ms=20000 response=decoy_pmkid suppressed=1\n");
}

static void satisfied_latch_is_silent_and_counted_on_stop(void)
{
    fixture_t fixture = {.now_us = 4000000};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));
    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_DEAUTH, fixture.now_us);

    assert(deauth_defence_runtime_process(&runtime, &event));
    fixture.now_us += DEAUTH_DEFENCE_PAIR_COOLDOWN_US;
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(runtime.observation_log_suppressed);
    ++fixture.now_us;
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(runtime.observation_log_suppressed);
    assert(fixture.tx_calls == 2U);
    assert(!strstr(fixture.telemetry, "suppressed=2 reason=response_satisfied"));

    deauth_defence_runtime_request_stop(&runtime);
    assert(deauth_defence_runtime_join(&runtime, 0U));
    deauth_defence_runtime_finish_stop(&runtime, 0U);
    assert(!strstr(fixture.telemetry, "reason=response_satisfied"));
    const char *stopped = strstr(fixture.telemetry,
        "[DETECTOR_DEFENCE] stopped observations=3 tx_pairs=1 pmkid_m1=0 responses=1 satisfied=2 errors=0 dropped=0 outcome=responded\n");
    assert(stopped);
}

static void suppression_is_keyed_by_bssid_and_reason(void)
{
    fixture_t fixture = {.now_us = 20000000};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for_two(&fixture, true);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    deauth_defence_runtime_observation_t pmkid =
        observation(DEF_TRIG_PMKID_PROBE, fixture.now_us);
    assert(deauth_defence_runtime_process(&runtime, &pmkid));
    fixture.now_us += 100;
    assert(deauth_defence_runtime_process(&runtime, &pmkid));
    assert(deauth_defence_runtime_abort_confirmation(&runtime));

    fixture.now_us += 100;
    assert(deauth_defence_runtime_process(&runtime, &pmkid));

    memcpy(pmkid.bssid, AP_B, sizeof(pmkid.bssid));
    pmkid.rx_us = fixture.now_us;
    assert(deauth_defence_runtime_process(&runtime, &pmkid));
    fixture.now_us += 100;
    assert(deauth_defence_runtime_process(&runtime, &pmkid));

    deauth_defence_runtime_request_stop(&runtime);
    assert(deauth_defence_runtime_join(&runtime, 0U));
    deauth_defence_runtime_finish_stop(&runtime, 0U);
    assert(!strstr(fixture.telemetry, "reason=response_satisfied"));
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] suppressed=1 reason=pmkid_rate_limited BSSID=02:00:00:00:00:01 window_ms=1000\n");
    assert_contains(&fixture,
        "[DETECTOR_DEFENCE] stopped observations=5 tx_pairs=0 pmkid_m1=2 responses=2 satisfied=2 errors=0 dropped=0 outcome=responded\n");
}

static void invalid_start_and_join_timeout(void)
{
    deauth_defence_runtime_t runtime = {0};
    fixture_t fixture = {0};
    deauth_defence_config_t config = config_for(&fixture, false);
    config.target_count = 0U;
    assert(!deauth_defence_runtime_start(&runtime, &config));

    config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));
    runtime.processing = true;
    deauth_defence_runtime_request_stop(&runtime);
    assert(!deauth_defence_runtime_join(&runtime, 0U));
    runtime.processing = false;
    assert(deauth_defence_runtime_join(&runtime, 0U));

    deauth_defence_runtime_quiesce(&runtime);
    assert(runtime.started && !runtime.armed);
    for (size_t i = 0; i < sizeof(runtime.targets); ++i) {
        assert(((const uint8_t *)runtime.targets)[i] == 0U);
    }
}

typedef struct {
    deauth_defence_runtime_t *runtime;
    deauth_defence_runtime_observation_t event;
    bool result;
} process_thread_t;

static void *process_in_thread(void *opaque)
{
    process_thread_t *thread = opaque;
    thread->result = deauth_defence_runtime_process(thread->runtime,
                                                     &thread->event);
    return NULL;
}

static void concurrent_stop_linearizes_against_tx_claim(void)
{
    fixture_t fixture = {.now_us = 9000100};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    atomic_init(&fixture.block_tx, true);
    atomic_init(&fixture.tx_entered, false);
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    process_thread_t worker = {
        .runtime = &runtime,
        .event = observation(DEF_TRIG_DEAUTH, 9000000),
    };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, process_in_thread, &worker) == 0);
    while (!atomic_load_explicit(&fixture.tx_entered,
                                 memory_order_acquire)) {
        sched_yield();
    }

    deauth_defence_runtime_request_stop(&runtime);
    assert(!deauth_defence_runtime_join(&runtime, 0U));
    atomic_store_explicit(&fixture.block_tx, false, memory_order_release);
    assert(pthread_join(thread, NULL) == 0);

    assert(!worker.result);
    assert(fixture.tx_calls == 1U); /* in-flight M1 drains; M2 cannot claim */
    assert(deauth_defence_runtime_join(&runtime, 0U));
    assert(!deauth_defence_runtime_process(&runtime, &worker.event));
    assert(fixture.tx_calls == 1U);
}

static void concurrent_stop_counts_completed_pmkid_m1(void)
{
    fixture_t fixture = {.now_us = 9100100};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    atomic_init(&fixture.block_tx, true);
    atomic_init(&fixture.tx_entered, false);
    deauth_defence_config_t config = config_for(&fixture, true);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    process_thread_t worker = {
        .runtime = &runtime,
        .event = observation(DEF_TRIG_PMKID_PROBE, 9100000),
    };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, process_in_thread, &worker) == 0);
    while (!atomic_load_explicit(&fixture.tx_entered,
                                 memory_order_acquire)) {
        sched_yield();
    }

    deauth_defence_runtime_request_stop(&runtime);
    assert(!deauth_defence_runtime_join(&runtime, 0U));
    atomic_store_explicit(&fixture.block_tx, false, memory_order_release);
    assert(pthread_join(thread, NULL) == 0);

    assert(worker.result);
    assert(fixture.tx_calls == 1U);
    assert(runtime.stats.pmkid_m1 == 1U);
    assert(runtime.response_sent);
    assert(deauth_defence_runtime_join(&runtime, 0U));
}

static void suppression_capacity_covers_every_target_and_reason(void)
{
    fixture_t fixture = {.now_us = 9200100};
    deauth_defence_runtime_t runtime = {0};
    fixture.runtime = &runtime;
    deauth_defence_config_t config = config_for(&fixture, false);
    assert(deauth_defence_runtime_start(&runtime, &config));
    assert(deauth_defence_runtime_arm(&runtime, 7U));

    /* Simulate one occupied reason for every supported target. */
    for (size_t i = 0; i < DEAUTH_DEFENCE_RUNTIME_TARGETS; ++i) {
        runtime.suppression[i].used = true;
        runtime.suppression[i].bssid[0] = 0x02U;
        runtime.suppression[i].bssid[5] = (uint8_t)i;
        runtime.suppression[i].reason = "pmkid_rate_limited";
        runtime.suppression[i].count = 1U;
        runtime.suppression[i].started_us = fixture.now_us;
    }

    deauth_defence_runtime_observation_t event =
        observation(DEF_TRIG_DEAUTH, 9200000);
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(deauth_defence_runtime_abort_confirmation(&runtime));
    fixture.now_us += 100;
    assert(deauth_defence_runtime_process(&runtime, &event));
    assert(runtime.observation_log_suppressed);
    assert(!strstr(fixture.telemetry,
                   "decision=observe reason=rate_limited_cooldown"));
}

static void telemetry_counters_saturate(void)
{
    fixture_t error_fixture = {.now_us = 9300100, .fail_tune = true};
    deauth_defence_runtime_t error_runtime = {0};
    error_fixture.runtime = &error_runtime;
    deauth_defence_config_t error_config = config_for(&error_fixture, false);
    assert(deauth_defence_runtime_start(&error_runtime, &error_config));
    assert(deauth_defence_runtime_arm(&error_runtime, 7U));
    error_runtime.stats.errors = UINT32_MAX;
    deauth_defence_runtime_observation_t deauth =
        observation(DEF_TRIG_DEAUTH, 9300000);
    assert(!deauth_defence_runtime_process(&error_runtime, &deauth));
    assert(error_runtime.stats.errors == UINT32_MAX);

    fixture_t pair_fixture = {.now_us = 9400100};
    deauth_defence_runtime_t pair_runtime = {0};
    pair_fixture.runtime = &pair_runtime;
    deauth_defence_config_t pair_config = config_for(&pair_fixture, false);
    assert(deauth_defence_runtime_start(&pair_runtime, &pair_config));
    assert(deauth_defence_runtime_arm(&pair_runtime, 7U));
    pair_runtime.stats.tx_pairs = UINT32_MAX;
    assert(deauth_defence_runtime_process(&pair_runtime, &deauth));
    assert(pair_runtime.stats.tx_pairs == UINT32_MAX);

    fixture_t pmkid_fixture = {.now_us = 9500100};
    deauth_defence_runtime_t pmkid_runtime = {0};
    pmkid_fixture.runtime = &pmkid_runtime;
    deauth_defence_config_t pmkid_config = config_for(&pmkid_fixture, true);
    assert(deauth_defence_runtime_start(&pmkid_runtime, &pmkid_config));
    assert(deauth_defence_runtime_arm(&pmkid_runtime, 7U));
    pmkid_runtime.stats.pmkid_m1 = UINT32_MAX;
    deauth_defence_runtime_observation_t pmkid =
        observation(DEF_TRIG_PMKID_PROBE, 9500000);
    assert(deauth_defence_runtime_process(&pmkid_runtime, &pmkid));
    assert(pmkid_runtime.stats.pmkid_m1 == UINT32_MAX);
}

int main(void)
{
    successful_fast_pair();
    bounded_failures();
    failed_response_reports_observed_outcome_on_stop();
    empty_session_reports_idle_outcome_on_stop();
    pmkid_and_stale_generation();
    satisfied_latch_is_silent_and_counted_on_stop();
    suppression_is_keyed_by_bssid_and_reason();
    invalid_start_and_join_timeout();
    concurrent_stop_linearizes_against_tx_claim();
    concurrent_stop_counts_completed_pmkid_m1();
    suppression_capacity_covers_every_target_and_reason();
    telemetry_counters_saturate();
    puts("deauth defence runtime: PASS");
    return 0;
}
