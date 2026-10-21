#include "lab_wps_session.h"

#include <string.h>

static void secure_wipe(void *memory, size_t size) {
    volatile uint8_t *bytes = memory;
    while (size--) *bytes++ = 0;
}

static bool unicast_bssid(const uint8_t bssid[6]) {
    uint8_t any = 0;
    uint8_t all_ff = 0xff;
    if (!bssid || (bssid[0] & 1U) != 0U) return false;
    for (size_t i = 0; i < 6; ++i) {
        any |= bssid[i];
        all_ff &= bssid[i];
    }
    return any != 0U && all_ff != 0xffU;
}

static bool pin_is_valid(const char *pin, size_t length) {
    unsigned accumulator = 0;
    if (!pin || (length != 4U && length != 8U)) return false;
    for (size_t i = 0; i < length; ++i) {
        if (pin[i] < '0' || pin[i] > '9') return false;
    }
    if (length == 4U) return true;
    for (size_t i = 0; i < 7; ++i)
        accumulator += (unsigned)(pin[i] - '0') * ((i & 1U) == 0U ? 3U : 1U);
    return (10U - accumulator % 10U) % 10U == (unsigned)(pin[7] - '0');
}

static bool send(lab_wps_session_t *session, lab_wps_action_t action,
                 uint8_t eap_id, lab_wps_result_t *result) {
    if (session->ops.send_action(session->ops_context, action, eap_id)) return true;
    result->session_result = WPS_SESSION_DISCONNECTED;
    return false;
}

bool lab_wps_session_init(lab_wps_session_t *session,
                          const lab_wps_session_ops_t *ops,
                          void *ops_context) {
    if (!session || !ops || !ops->next_event || !ops->send_action) return false;
    session->ops = *ops;
    session->ops_context = ops_context;
    return true;
}

static bool run(lab_wps_session_t *session, const lab_wps_request_t *request,
                bool capture, pixie_bundle_t *bundle_out,
                lab_wps_result_t *result) {
    enum { MAX_STAGE_RETRIES = 2 };
    unsigned stage = 0;
    unsigned identities_at_stage = 0;
    unsigned handled = 0;
    unsigned stage_retries = 0;
    bool associated = false;
    bool bundle_captured = false;
    bool last_action_valid = false;
    lab_wps_action_t last_action = LAB_WPS_ACTION_START;
    uint8_t last_eap_id = 0;

    if (!session || !request || !result || !unicast_bssid(request->bssid) ||
        !pin_is_valid(request->pin, request->pin_len) ||
        (capture && !bundle_out)) return false;

    memset(result, 0, sizeof(*result));
    result->session_result = WPS_SESSION_FATAL;
    if (capture) memset(bundle_out, 0, sizeof(*bundle_out));

    while (handled++ < LAB_WPS_MAX_EVENTS) {
        lab_wps_event_t event;
        memset(&event, 0, sizeof(event));
        if (request->cancelled && request->cancelled(request->cancel_context)) {
            result->cancelled = true;
            result->fatal_reason = LAB_WPS_FATAL_CANCELLED;
            return true;
        }
        if (!session->ops.next_event(session->ops_context, &event)) {
            result->session_result = WPS_SESSION_TIMEOUT;
            return true;
        }
        if (event.fragmented) ++result->fragmented_messages;
        if (event.kind != LAB_WPS_EVENT_TIMEOUT) stage_retries = 0;

        switch (event.kind) {
        case LAB_WPS_EVENT_ASSOCIATED:
            if (!associated) {
                associated = true;
                if (!send(session, LAB_WPS_ACTION_START, event.eap_id, result)) return true;
                last_action = LAB_WPS_ACTION_START;
                last_eap_id = event.eap_id;
                last_action_valid = true;
            }
            break;
        case LAB_WPS_EVENT_IDENTITY: {
            ++result->identities;
            wps_identity_action_t action =
                wps_identity_action(stage, ++identities_at_stage);
            if (action == WPS_IDENTITY_STALL) {
                result->session_result = WPS_SESSION_IDENTITY_LOOP;
                return true;
            }
            if (action == WPS_IDENTITY_RESPOND &&
                !send(session, LAB_WPS_ACTION_IDENTITY, event.eap_id, result)) return true;
            if (action == WPS_IDENTITY_RESPOND) {
                last_action = LAB_WPS_ACTION_IDENTITY;
                last_eap_id = event.eap_id;
                last_action_valid = true;
            }
            break;
        }
        case LAB_WPS_EVENT_M1:
            if (stage == 1U && event.authenticated && last_action_valid &&
                last_action == LAB_WPS_ACTION_M2 && event.eap_id == last_eap_id) {
                if (!send(session, last_action, last_eap_id, result)) return true;
                break;
            }
            if (stage != 0U || !event.authenticated) {
                result->session_result = WPS_SESSION_FATAL;
                result->fatal_reason = LAB_WPS_FATAL_INVALID_SEQUENCE;
                return true;
            }
            result->identity = event.identity;
            if (!send(session, LAB_WPS_ACTION_M2, event.eap_id, result)) return true;
            last_action = LAB_WPS_ACTION_M2;
            last_eap_id = event.eap_id;
            last_action_valid = true;
            stage = 1;
            identities_at_stage = 0;
            break;
        case LAB_WPS_EVENT_M3:
            if (stage == 2U && event.authenticated && last_action_valid &&
                last_action == LAB_WPS_ACTION_M4 && event.eap_id == last_eap_id) {
                if (!send(session, last_action, last_eap_id, result)) return true;
                break;
            }
            if (stage != 1U || !event.authenticated) {
                result->session_result = WPS_SESSION_FATAL;
                result->fatal_reason = LAB_WPS_FATAL_INVALID_SEQUENCE;
                return true;
            }
            if (capture) {
                *bundle_out = event.bundle;
                bundle_captured = true;
            }
            if (!send(session, LAB_WPS_ACTION_M4, event.eap_id, result)) return true;
            last_action = LAB_WPS_ACTION_M4;
            last_eap_id = event.eap_id;
            last_action_valid = true;
            stage = 2;
            identities_at_stage = 0;
            break;
        case LAB_WPS_EVENT_M5:
            if (capture && bundle_captured) {
                if (!event.authenticated) {
                    result->session_result = WPS_SESSION_FATAL;
                    result->fatal_reason = LAB_WPS_FATAL_INVALID_SEQUENCE;
                    return true;
                }
                /* M5 confirms that the AP accepted M4. The control PIN is
                 * irrelevant to capture, so never advance this attempt to M6. */
                (void)session->ops.send_action(
                    session->ops_context, LAB_WPS_ACTION_NACK, event.eap_id);
                result->session_result = WPS_SESSION_SUCCESS;
                return true;
            }
            if (stage == 3U && event.authenticated && event.pin_half_verified &&
                last_action_valid && last_action == LAB_WPS_ACTION_M6 &&
                event.eap_id == last_eap_id) {
                if (!send(session, last_action, last_eap_id, result)) return true;
                break;
            }
            if (stage != 2U || !event.authenticated) {
                result->session_result = WPS_SESSION_FATAL;
                result->fatal_reason = LAB_WPS_FATAL_INVALID_SEQUENCE;
                return true;
            }
            if (!event.pin_half_verified) {
                result->session_result = WPS_SESSION_PIN_REJECTED;
                return true;
            }
            if (!send(session, LAB_WPS_ACTION_M6, event.eap_id, result)) return true;
            last_action = LAB_WPS_ACTION_M6;
            last_eap_id = event.eap_id;
            last_action_valid = true;
            stage = 3;
            identities_at_stage = 0;
            break;
        case LAB_WPS_EVENT_M7:
            if (stage != 3U || !event.authenticated) {
                result->session_result = WPS_SESSION_FATAL;
                result->fatal_reason = LAB_WPS_FATAL_INVALID_SEQUENCE;
                return true;
            }
            if (!event.pin_half_verified) {
                result->session_result = WPS_SESSION_PIN_REJECTED;
                return true;
            }
            if (!event.credential_present || !event.network_key ||
                event.network_key_len == 0U ||
                event.network_key_len > sizeof(result->network_key)) {
                result->session_result = WPS_SESSION_FATAL;
                result->fatal_reason = LAB_WPS_FATAL_CREDENTIAL;
                return true;
            }
            memcpy(result->network_key, event.network_key, event.network_key_len);
            result->network_key_len = event.network_key_len;
            result->credential_present = true;
            if (event.ssid && event.ssid_len > 0U && event.ssid_len <= 32U &&
                memchr(event.ssid, 0, event.ssid_len) == NULL) {
                memcpy(result->ssid, event.ssid, event.ssid_len);
                result->ssid[event.ssid_len] = 0;
            }
            if (!send(session, LAB_WPS_ACTION_NACK, event.eap_id, result)) {
                secure_wipe(result->network_key, sizeof(result->network_key));
                result->network_key_len = 0;
                result->credential_present = false;
                return true;
            }
            result->session_result = WPS_SESSION_SUCCESS;
            return true;
        case LAB_WPS_EVENT_NACK:
            if (capture && bundle_captured) {
                wps_session_result_t nack = wps_nack_result(
                    stage, event.config_error_present, event.config_error);
                result->session_result = nack == WPS_SESSION_SETUP_LOCKED ?
                    nack : WPS_SESSION_SUCCESS;
                return true;
            }
            result->session_result = wps_nack_result(
                stage, event.config_error_present, event.config_error);
            return true;
        case LAB_WPS_EVENT_EAP_FAILURE:
            if (capture && bundle_captured) {
                result->session_result = WPS_SESSION_SUCCESS;
                return true;
            }
            result->session_result = wps_eap_failure_result();
            return true;
        case LAB_WPS_EVENT_TIMEOUT:
            if (last_action_valid && stage_retries++ < MAX_STAGE_RETRIES) {
                if (!send(session, last_action, last_eap_id, result)) return true;
                break;
            }
            /* Match Wifit3/Reaver timeout-as-NACK semantics: once an
             * authenticated M3 bundle has been retained and M4 was sent, AP
             * silence terminates the control-PIN attempt without invalidating
             * the bundle. Verification still happens in a fresh session. */
            result->session_result = capture && bundle_captured &&
                                     last_action == LAB_WPS_ACTION_M4 ?
                                     WPS_SESSION_SUCCESS : WPS_SESSION_TIMEOUT;
            return true;
        case LAB_WPS_EVENT_DISCONNECTED:
            result->session_result = capture && bundle_captured ?
                WPS_SESSION_SUCCESS : WPS_SESSION_DISCONNECTED;
            return true;
        case LAB_WPS_EVENT_QUEUE_OVERFLOW:
            ++result->dropped_events;
            result->session_result = WPS_SESSION_FATAL;
            result->fatal_reason = LAB_WPS_FATAL_QUEUE_OVERFLOW;
            return true;
        case LAB_WPS_EVENT_CANCELLED:
            result->cancelled = true;
            result->session_result = WPS_SESSION_FATAL;
            result->fatal_reason = LAB_WPS_FATAL_CANCELLED;
            return true;
        default:
            result->session_result = WPS_SESSION_FATAL;
            result->fatal_reason = LAB_WPS_FATAL_UNEXPECTED_EVENT;
            return true;
        }
    }
    result->session_result = WPS_SESSION_FATAL;
    result->fatal_reason = LAB_WPS_FATAL_EVENT_LIMIT;
    return true;
}

bool lab_wps_verify_pin(lab_wps_session_t *session,
                        const lab_wps_request_t *request,
                        lab_wps_result_t *result) {
    return run(session, request, false, NULL, result);
}

bool lab_wps_capture_pixie(lab_wps_session_t *session,
                           const lab_wps_request_t *request,
                           pixie_bundle_t *bundle_out,
                           lab_wps_result_t *result) {
    return run(session, request, true, bundle_out, result);
}

void lab_wps_result_wipe(lab_wps_result_t *result) {
    if (result) secure_wipe(result, sizeof(*result));
}
