#include "session_policy.h"

#include <stdbool.h>

wps_session_action_t wps_session_action(wps_session_result_t result,
                                        unsigned attempt,
                                        unsigned max_attempts) {
    bool transient = result == WPS_SESSION_TIMEOUT ||
                     result == WPS_SESSION_IDENTITY_LOOP ||
                     result == WPS_SESSION_DISCONNECTED ||
                     result == WPS_SESSION_PRE_PIN_REJECTED;
    return transient && attempt < max_attempts ? WPS_ACTION_RETRY : WPS_ACTION_FINISH;
}

wps_session_result_t wps_nack_result(unsigned stage, bool has_config_error,
                                     uint16_t config_error) {
    (void)stage;
    if (has_config_error && config_error == 15) return WPS_SESSION_SETUP_LOCKED;
    if (has_config_error && config_error == 18) return WPS_SESSION_PIN_REJECTED;
    return WPS_SESSION_PRE_PIN_REJECTED;
}

wps_session_result_t wps_eap_failure_result(void) {
    return WPS_SESSION_PRE_PIN_REJECTED;
}

wps_m3_action_t wps_m3_action(bool capturing_pixie_bundle) {
    return capturing_pixie_bundle ? WPS_M3_CLOSE_CAPTURE_WITH_NACK :
                                    WPS_M3_CONTINUE_WITH_M4;
}

wps_identity_action_t wps_identity_action(unsigned stage,
                                          unsigned identities_at_stage) {
    if (stage <= 1)
        return identities_at_stage <= 8 ? WPS_IDENTITY_RESPOND : WPS_IDENTITY_STALL;
    return WPS_IDENTITY_IGNORE;
}

wps_m1_action_t wps_m1_action(unsigned stage, unsigned restart_ordinal) {
    if (stage == 0) return WPS_M1_ACCEPT_INITIAL;
    if (stage == 1)
        return restart_ordinal <= 2 ? WPS_M1_RESTART : WPS_M1_STALL;
    return WPS_M1_IGNORE;
}

wps_start_action_t wps_start_timeout_action(unsigned identities_seen,
                                            unsigned sends_done) {
    return identities_seen == 0 && sends_done < 3 ? WPS_START_RESEND :
                                                    WPS_START_TIMEOUT;
}

bool wps_next_request_id_allowed(uint8_t outbound_response_id,
                                 uint8_t inbound_request_id) {
    /*
     * M2/M4/M6 are EAP Responses.  The following M3/M5/M7 are new EAP
     * Requests, so their identifiers are chosen by the AP and may reuse the
     * identifier of the preceding response.  Message type, nonces,
     * authenticators and fragment-chain checks bind the WSC transaction.
     */
    (void)outbound_response_id;
    (void)inbound_request_id;
    return true;
}
