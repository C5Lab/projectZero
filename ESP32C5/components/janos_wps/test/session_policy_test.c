#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "session_policy.h"

static void terminal_results_never_retry(void) {
    assert(wps_session_action(WPS_SESSION_SUCCESS, 1, 3) == WPS_ACTION_FINISH);
    assert(wps_session_action(WPS_SESSION_PIN_REJECTED, 1, 3) == WPS_ACTION_FINISH);
    assert(wps_session_action(WPS_SESSION_FATAL, 1, 3) == WPS_ACTION_FINISH);
}

static void transient_results_retry_within_budget(void) {
    assert(wps_session_action(WPS_SESSION_TIMEOUT, 1, 3) == WPS_ACTION_RETRY);
    assert(wps_session_action(WPS_SESSION_IDENTITY_LOOP, 2, 3) == WPS_ACTION_RETRY);
    assert(wps_session_action(WPS_SESSION_DISCONNECTED, 1, 3) == WPS_ACTION_RETRY);
}

static void transient_results_stop_at_budget(void) {
    assert(wps_session_action(WPS_SESSION_TIMEOUT, 3, 3) == WPS_ACTION_FINISH);
    assert(wps_session_action(WPS_SESSION_IDENTITY_LOOP, 3, 3) == WPS_ACTION_FINISH);
    assert(wps_session_action(WPS_SESSION_DISCONNECTED, 4, 3) == WPS_ACTION_FINISH);
}

static void nack_before_m4_retries_without_rejecting_the_pin(void) {
    assert(wps_nack_result(0, false, 0) == WPS_SESSION_PRE_PIN_REJECTED);
    assert(wps_nack_result(1, true, 0) == WPS_SESSION_PRE_PIN_REJECTED);
    assert(wps_session_action(WPS_SESSION_PRE_PIN_REJECTED, 1, 3) == WPS_ACTION_RETRY);
    assert(wps_session_action(WPS_SESSION_PRE_PIN_REJECTED, 3, 3) == WPS_ACTION_FINISH);
}

static void only_explicit_password_auth_failure_rejects_the_pin(void) {
    assert(wps_nack_result(2, false, 0) == WPS_SESSION_PRE_PIN_REJECTED);
    assert(wps_nack_result(3, true, 0) == WPS_SESSION_PRE_PIN_REJECTED);
    assert(wps_nack_result(3, true, 12) == WPS_SESSION_PRE_PIN_REJECTED);
    assert(wps_nack_result(3, true, 18) == WPS_SESSION_PIN_REJECTED);
    assert(wps_eap_failure_result() == WPS_SESSION_PRE_PIN_REJECTED);
}

static void setup_locked_is_terminal_at_every_stage(void) {
    assert(wps_nack_result(1, true, 15) == WPS_SESSION_SETUP_LOCKED);
    assert(wps_nack_result(2, true, 15) == WPS_SESSION_SETUP_LOCKED);
    assert(wps_session_action(WPS_SESSION_SETUP_LOCKED, 1, 3) == WPS_ACTION_FINISH);
}

static void pixie_capture_closes_after_m3_with_nack_without_committing_a_pin(void) {
    assert(wps_m3_action(true) == WPS_M3_CLOSE_CAPTURE_WITH_NACK);
    assert(wps_m3_action(false) == WPS_M3_CONTINUE_WITH_M4);
}

static void identity_policy_matches_tp_link_and_wifite3(void) {
    assert(wps_identity_action(0, 1) == WPS_IDENTITY_RESPOND);
    assert(wps_identity_action(0, 8) == WPS_IDENTITY_RESPOND);
    assert(wps_identity_action(0, 9) == WPS_IDENTITY_STALL);
    assert(wps_identity_action(1, 1) == WPS_IDENTITY_RESPOND);
    assert(wps_identity_action(1, 2) == WPS_IDENTITY_RESPOND);
    assert(wps_identity_action(1, 8) == WPS_IDENTITY_RESPOND);
    assert(wps_identity_action(1, 9) == WPS_IDENTITY_STALL);
    assert(wps_identity_action(2, 1) == WPS_IDENTITY_IGNORE);
}

static void next_wsc_request_may_reuse_outbound_response_id(void) {
    /* Observed TP-Link trace: M2 response 233, Identity 232, M3 request 233. */
    assert(wps_next_request_id_allowed(233, 233));
    assert(wps_next_request_id_allowed(233, 10));
    assert(wps_next_request_id_allowed(255, 0));
}

static void fresh_m1_restarts_only_the_pre_m3_exchange(void) {
    assert(wps_m1_action(0, 0) == WPS_M1_ACCEPT_INITIAL);
    assert(wps_m1_action(1, 1) == WPS_M1_RESTART);
    assert(wps_m1_action(1, 2) == WPS_M1_RESTART);
    assert(wps_m1_action(1, 3) == WPS_M1_STALL);
    assert(wps_m1_action(2, 1) == WPS_M1_IGNORE);
    assert(wps_m1_action(3, 1) == WPS_M1_IGNORE);
}

static void eapol_start_retries_only_before_identity(void) {
    assert(wps_start_timeout_action(0, 1) == WPS_START_RESEND);
    assert(wps_start_timeout_action(0, 2) == WPS_START_RESEND);
    assert(wps_start_timeout_action(0, 3) == WPS_START_TIMEOUT);
    assert(wps_start_timeout_action(1, 1) == WPS_START_TIMEOUT);
}

int main(void) {
    terminal_results_never_retry();
    transient_results_retry_within_budget();
    transient_results_stop_at_budget();
    nack_before_m4_retries_without_rejecting_the_pin();
    only_explicit_password_auth_failure_rejects_the_pin();
    setup_locked_is_terminal_at_every_stage();
    pixie_capture_closes_after_m3_with_nack_without_committing_a_pin();
    identity_policy_matches_tp_link_and_wifite3();
    next_wsc_request_may_reuse_outbound_response_id();
    fresh_m1_restarts_only_the_pre_m3_exchange();
    eapol_start_retries_only_before_identity();
    puts("PASS: WPS fresh-session retry policy");
    return 0;
}
