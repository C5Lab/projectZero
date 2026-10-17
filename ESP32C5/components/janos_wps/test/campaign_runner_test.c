#include <assert.h>
#include <limits.h>
#include <stdio.h>

#include "campaign_runner.h"

typedef struct {
    const wps_session_result_t *results;
    unsigned available;
    unsigned calls;
    unsigned first;
} script_t;

static wps_session_result_t scripted_attempt(unsigned index, void *context) {
    script_t *script = context;
    assert(script->calls < script->available); /* Also catches callbacks after stop. */
    assert(index == script->first + script->calls);
    return script->results[script->calls++];
}

static void rejects_then_lock(void) {
    const wps_session_result_t sequence[] = {
        WPS_SESSION_PIN_REJECTED, WPS_SESSION_PIN_REJECTED, WPS_SESSION_SETUP_LOCKED
    };
    script_t script = {sequence, 3, 0, 4};
    campaign_run_result_t result = campaign_run(4, 3, 10, scripted_attempt, &script);
    assert(result.decision == CAMPAIGN_DECISION_LOCKED);
    assert(result.attempt_count == 3 && script.calls == 3);
    assert(result.last_result == WPS_SESSION_SETUP_LOCKED);
    assert(result.resume_index == 6);
}

static void terminal_results_keep_current_candidate(void) {
    const struct { wps_session_result_t session; campaign_decision_t decision; } cases[] = {
        {WPS_SESSION_TIMEOUT, CAMPAIGN_DECISION_PAUSE},
        {WPS_SESSION_DISCONNECTED, CAMPAIGN_DECISION_PAUSE},
        {WPS_SESSION_PRE_PIN_REJECTED, CAMPAIGN_DECISION_PAUSE},
        {WPS_SESSION_IDENTITY_LOOP, CAMPAIGN_DECISION_PAUSE},
        {WPS_SESSION_SUCCESS, CAMPAIGN_DECISION_SUCCESS},
        {WPS_SESSION_FATAL, CAMPAIGN_DECISION_FATAL},
        {(wps_session_result_t)99, CAMPAIGN_DECISION_FATAL},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script_t script = {&cases[i].session, 1, 0, 2};
        campaign_run_result_t result = campaign_run(2, 3, 8, scripted_attempt, &script);
        assert(result.decision == cases[i].decision);
        assert(result.attempt_count == 1 && script.calls == 1);
        assert(result.last_result == cases[i].session && result.resume_index == 2);
    }
}

static void clips_budget_and_reports_exhaustion(void) {
    const wps_session_result_t rejected[] = {
        WPS_SESSION_PIN_REJECTED, WPS_SESSION_PIN_REJECTED, WPS_SESSION_PIN_REJECTED
    };
    script_t script = {rejected, 2, 0, 6};
    campaign_run_result_t result = campaign_run(6, 3, 8, scripted_attempt, &script);
    assert(result.decision == CAMPAIGN_DECISION_EXHAUSTED);
    assert(result.attempt_count == 2 && script.calls == 2);
    assert(result.resume_index == 8 && result.last_result == WPS_SESSION_PIN_REJECTED);
    script = (script_t){rejected, 3, 0, 0};
    result = campaign_run(0, 3, 10, scripted_attempt, &script);
    assert(result.decision == CAMPAIGN_DECISION_EXHAUSTED && result.resume_index == 3);
    assert(result.attempt_count == 3 && script.calls == 3); /* No universal two-reject lock. */
    script = (script_t){rejected, 1, 0, UINT_MAX - 1};
    result = campaign_run(UINT_MAX - 1, 3, UINT_MAX, scripted_attempt, &script);
    assert(result.attempt_count == 1 && result.resume_index == UINT_MAX);
}

static void rejection_then_transport_stop_resumes_at_advanced_candidate(void) {
    const wps_session_result_t terminals[] = {
        WPS_SESSION_TIMEOUT, WPS_SESSION_DISCONNECTED,
        WPS_SESSION_PRE_PIN_REJECTED, WPS_SESSION_IDENTITY_LOOP
    };
    for (unsigned i = 0; i < sizeof(terminals) / sizeof(terminals[0]); ++i) {
        const wps_session_result_t sequence[] = {
            WPS_SESSION_PIN_REJECTED, terminals[i]
        };
        script_t script = {sequence, 2, 0, 4};
        campaign_run_result_t result = campaign_run(4, 3, 10, scripted_attempt, &script);
        assert(result.decision == CAMPAIGN_DECISION_PAUSE);
        assert(result.attempt_count == 2 && script.calls == 2);
        assert(result.last_result == terminals[i]);
        assert(result.resume_index == 5);
    }
}

static void invalid_ranges_do_not_attempt(void) {
    script_t script = {NULL, 0, 0, 0};
    const unsigned ranges[][3] = {{0, 0, 10}, {0, 4, 10}, {10, 1, 10}, {0, 1, 0}};
    for (unsigned i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i) {
        campaign_run_result_t result = campaign_run(ranges[i][0], ranges[i][1],
                                                    ranges[i][2], scripted_attempt, &script);
        assert(result.decision == CAMPAIGN_DECISION_INVALID);
        assert(result.attempt_count == 0 && result.resume_index == ranges[i][0]);
        assert(result.last_result == WPS_SESSION_FATAL);
    }
    assert(campaign_run(0, 1, 1, NULL, NULL).decision == CAMPAIGN_DECISION_INVALID);
    assert(script.calls == 0);
}

int main(void) {
    rejects_then_lock();
    terminal_results_keep_current_candidate();
    rejection_then_transport_stop_resumes_at_advanced_candidate();
    clips_budget_and_reports_exhaustion();
    invalid_ranges_do_not_attempt();
    puts("PASS: WPS campaign runner");
}
