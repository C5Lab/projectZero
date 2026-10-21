#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    WPS_SESSION_SUCCESS = 0,
    WPS_SESSION_PIN_REJECTED,
    WPS_SESSION_PRE_PIN_REJECTED,
    WPS_SESSION_SETUP_LOCKED,
    WPS_SESSION_TIMEOUT,
    WPS_SESSION_IDENTITY_LOOP,
    WPS_SESSION_DISCONNECTED,
    WPS_SESSION_FATAL,
} wps_session_result_t;

typedef enum {
    WPS_ACTION_FINISH = 0,
    WPS_ACTION_RETRY,
} wps_session_action_t;

typedef enum {
    WPS_IDENTITY_RESPOND = 0,
    WPS_IDENTITY_IGNORE,
    WPS_IDENTITY_STALL,
} wps_identity_action_t;

typedef enum {
    WPS_M3_CONTINUE_WITH_M4 = 0,
    WPS_M3_CLOSE_CAPTURE_WITH_NACK,
} wps_m3_action_t;

typedef enum {
    WPS_M1_ACCEPT_INITIAL = 0,
    WPS_M1_RESTART,
    WPS_M1_IGNORE,
    WPS_M1_STALL,
} wps_m1_action_t;

typedef enum {
    WPS_START_RESEND = 0,
    WPS_START_TIMEOUT,
} wps_start_action_t;

wps_session_action_t wps_session_action(wps_session_result_t result,
                                        unsigned attempt,
                                        unsigned max_attempts);
wps_session_result_t wps_nack_result(unsigned stage, bool has_config_error,
                                     uint16_t config_error);
wps_session_result_t wps_eap_failure_result(void);
wps_m3_action_t wps_m3_action(bool capturing_pixie_bundle);
wps_identity_action_t wps_identity_action(unsigned stage,
                                          unsigned identities_at_stage);
wps_m1_action_t wps_m1_action(unsigned stage, unsigned restart_ordinal);
wps_start_action_t wps_start_timeout_action(unsigned identities_seen,
                                            unsigned sends_done);
bool wps_next_request_id_allowed(uint8_t outbound_response_id,
                                 uint8_t inbound_request_id);
