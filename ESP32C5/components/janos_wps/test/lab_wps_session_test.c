#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "lab_wps_session.h"

typedef struct {
    const lab_wps_event_t *events;
    size_t count;
    size_t index;
    lab_wps_action_t actions[16];
    size_t action_count;
} fake_transport_t;

static bool next_event(void *opaque, lab_wps_event_t *event) {
    fake_transport_t *fake = opaque;
    if (fake->index >= fake->count) return false;
    *event = fake->events[fake->index++];
    return true;
}

static bool send_action(void *opaque, lab_wps_action_t action, uint8_t eap_id) {
    fake_transport_t *fake = opaque;
    (void)eap_id;
    assert(fake->action_count < sizeof(fake->actions) / sizeof(fake->actions[0]));
    fake->actions[fake->action_count++] = action;
    return true;
}

static bool never_cancel(void *opaque) {
    (void)opaque;
    return false;
}

static bool always_cancel(void *opaque) {
    (void)opaque;
    return true;
}

static lab_wps_request_t request(const char *pin) {
    lab_wps_request_t value = {
        .bssid = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        .pin = pin,
        .pin_len = pin ? strlen(pin) : 0,
        .cancelled = never_cancel,
    };
    return value;
}

static lab_wps_session_t session(fake_transport_t *fake) {
    const lab_wps_session_ops_t ops = {
        .next_event = next_event,
        .send_action = send_action,
    };
    lab_wps_session_t value;
    assert(lab_wps_session_init(&value, &ops, fake));
    return value;
}

static void test_complete_verify(void) {
    static const uint8_t key[] = "lab-password";
    static const uint8_t ssid[] = "Lab Network";
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_IDENTITY, .eap_id = 1},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true,
         .identity = {.manufacturer = "Realtek", .model_name = "RTL8xxx",
                      .model_number = "1.0", .device_name = "Lab Router"}},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M5, .eap_id = 4, .authenticated = true,
         .pin_half_verified = true},
        {.kind = LAB_WPS_EVENT_M7, .eap_id = 5, .authenticated = true,
         .pin_half_verified = true, .credential_present = true,
         .network_key = key, .network_key_len = sizeof(key) - 1,
         .ssid = ssid, .ssid_len = sizeof(ssid) - 1},
    };
    fake_transport_t fake = {.events = events, .count = sizeof(events) / sizeof(events[0])};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("31415927");
    lab_wps_result_t result;
    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(result.identities == 1 && result.credential_present);
    assert(result.network_key_len == sizeof(key) - 1);
    assert(memcmp(result.network_key, key, sizeof(key) - 1) == 0);
    assert(strcmp(result.ssid, "Lab Network") == 0);
    assert(strcmp(result.identity.manufacturer, "Realtek") == 0);
    assert(strcmp(result.identity.model_name, "RTL8xxx") == 0);
    const lab_wps_action_t expected[] = {LAB_WPS_ACTION_START, LAB_WPS_ACTION_IDENTITY,
        LAB_WPS_ACTION_M2, LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M6, LAB_WPS_ACTION_NACK};
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
    lab_wps_result_wipe(&result);
    for (size_t i = 0; i < sizeof(result); ++i) assert(((uint8_t *)&result)[i] == 0);
}

static void test_capture_continues_with_m4_until_terminal_event(
        lab_wps_event_kind_t terminal) {
    lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .authenticated = true, .fragmented = true},
        {.kind = LAB_WPS_EVENT_M3, .authenticated = true, .fragmented = true},
        {.kind = terminal},
    };
    for (size_t i = 0; i < sizeof(events[1].bundle.pke); ++i)
        events[2].bundle.pke[i] = (uint8_t)i;
    fake_transport_t fake = {
        .events = events,
        .count = sizeof(events) / sizeof(events[0]),
    };
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("12345670");
    lab_wps_result_t result;
    pixie_bundle_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    assert(lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(result.fragmented_messages == 2);
    assert(bundle.pke[0] == 0 && bundle.pke[191] == 191);
    assert(fake.index == sizeof(events) / sizeof(events[0]));
    assert(fake.action_count == 3);
    assert(fake.actions[fake.action_count - 1] == LAB_WPS_ACTION_M4);
}

static void test_capture_terminal_handshake(void) {
    test_capture_continues_with_m4_until_terminal_event(LAB_WPS_EVENT_NACK);
    test_capture_continues_with_m4_until_terminal_event(LAB_WPS_EVENT_EAP_FAILURE);
    test_capture_continues_with_m4_until_terminal_event(LAB_WPS_EVENT_DISCONNECTED);
}

static void test_capture_m5_closes_without_m6(bool pin_half_verified) {
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M5, .eap_id = 4, .authenticated = true,
         .pin_half_verified = pin_half_verified},
    };
    fake_transport_t fake = {
        .events = events,
        .count = sizeof(events) / sizeof(events[0]),
    };
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("12345670");
    lab_wps_result_t result;
    pixie_bundle_t bundle;
    const lab_wps_action_t expected[] = {
        LAB_WPS_ACTION_START, LAB_WPS_ACTION_M2,
        LAB_WPS_ACTION_M4, LAB_WPS_ACTION_NACK,
    };

    assert(lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
}

static void test_capture_retransmits_m4_for_duplicate_m3(void) {
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_EAP_FAILURE},
    };
    fake_transport_t fake = {
        .events = events,
        .count = sizeof(events) / sizeof(events[0]),
    };
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("12345670");
    lab_wps_result_t result;
    pixie_bundle_t bundle;
    const lab_wps_action_t expected[] = {
        LAB_WPS_ACTION_START, LAB_WPS_ACTION_M2,
        LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M4,
    };

    assert(lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(fake.index == sizeof(events) / sizeof(events[0]));
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
}

static void test_capture_timeout_after_m4_is_terminal_success(void) {
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_TIMEOUT},
        {.kind = LAB_WPS_EVENT_TIMEOUT},
        {.kind = LAB_WPS_EVENT_TIMEOUT},
    };
    fake_transport_t fake = {
        .events = events,
        .count = sizeof(events) / sizeof(events[0]),
    };
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("12345670");
    lab_wps_result_t result;
    pixie_bundle_t bundle;
    const lab_wps_action_t expected[] = {
        LAB_WPS_ACTION_START, LAB_WPS_ACTION_M2, LAB_WPS_ACTION_M4,
        LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M4,
    };

    assert(lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
}

static void test_capture_preserves_setup_lock_result(void) {
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_NACK, .config_error_present = true,
         .config_error = 15},
    };
    fake_transport_t fake = {
        .events = events,
        .count = sizeof(events) / sizeof(events[0]),
    };
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("12345670");
    lab_wps_result_t result;
    pixie_bundle_t bundle;

    assert(lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(result.session_result == WPS_SESSION_SETUP_LOCKED);
}

static void test_capture_requires_control_pin(void) {
    const lab_wps_event_t events[] = {{.kind = LAB_WPS_EVENT_ASSOCIATED}};
    fake_transport_t fake = {.events = events, .count = 1};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request(NULL);
    lab_wps_result_t result;
    pixie_bundle_t bundle;

    assert(!lab_wps_capture_pixie(&state, &input, &bundle, &result));
    assert(fake.index == 0 && fake.action_count == 0);
}

static void test_retransmits_last_response_for_duplicate_wsc_messages(void) {
    static const uint8_t key[] = "lab-password";
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M5, .eap_id = 4, .authenticated = true,
         .pin_half_verified = true},
        {.kind = LAB_WPS_EVENT_M5, .eap_id = 4, .authenticated = true,
         .pin_half_verified = true},
        {.kind = LAB_WPS_EVENT_M7, .eap_id = 5, .authenticated = true,
         .pin_half_verified = true, .credential_present = true,
         .network_key = key, .network_key_len = sizeof(key) - 1},
    };
    fake_transport_t fake = {.events = events, .count = sizeof(events) / sizeof(events[0])};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("31415927");
    lab_wps_result_t result;
    const lab_wps_action_t expected[] = {
        LAB_WPS_ACTION_START, LAB_WPS_ACTION_M2, LAB_WPS_ACTION_M2,
        LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M6,
        LAB_WPS_ACTION_M6, LAB_WPS_ACTION_NACK,
    };

    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
}

static void test_retries_last_response_after_one_stage_timeout(void) {
    static const uint8_t key[] = "lab-password";
    const lab_wps_event_t events[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .eap_id = 2, .authenticated = true},
        {.kind = LAB_WPS_EVENT_TIMEOUT},
        {.kind = LAB_WPS_EVENT_M3, .eap_id = 3, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M5, .eap_id = 4, .authenticated = true,
         .pin_half_verified = true},
        {.kind = LAB_WPS_EVENT_M7, .eap_id = 5, .authenticated = true,
         .pin_half_verified = true, .credential_present = true,
         .network_key = key, .network_key_len = sizeof(key) - 1},
    };
    fake_transport_t fake = {.events = events, .count = sizeof(events) / sizeof(events[0])};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("31415927");
    lab_wps_result_t result;
    const lab_wps_action_t expected[] = {
        LAB_WPS_ACTION_START, LAB_WPS_ACTION_M2, LAB_WPS_ACTION_M2,
        LAB_WPS_ACTION_M4, LAB_WPS_ACTION_M6, LAB_WPS_ACTION_NACK,
    };

    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.session_result == WPS_SESSION_SUCCESS);
    assert(fake.action_count == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(fake.actions, expected, sizeof(expected)) == 0);
}

static lab_wps_result_t run_terminal(lab_wps_event_t event) {
    const lab_wps_event_t prefix[] = {
        {.kind = LAB_WPS_EVENT_ASSOCIATED},
        {.kind = LAB_WPS_EVENT_M1, .authenticated = true},
        {.kind = LAB_WPS_EVENT_M3, .authenticated = true},
    };
    lab_wps_event_t events[4];
    memcpy(events, prefix, sizeof(prefix));
    events[3] = event;
    fake_transport_t fake = {.events = events, .count = 4};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("31415927");
    lab_wps_result_t result;
    assert(lab_wps_verify_pin(&state, &input, &result));
    return result;
}

static void test_terminal_results(void) {
    lab_wps_result_t result = run_terminal((lab_wps_event_t){
        .kind = LAB_WPS_EVENT_NACK, .config_error_present = true, .config_error = 15});
    assert(result.session_result == WPS_SESSION_SETUP_LOCKED);
    result = run_terminal((lab_wps_event_t){
        .kind = LAB_WPS_EVENT_NACK, .config_error_present = true, .config_error = 18});
    assert(result.session_result == WPS_SESSION_PIN_REJECTED);
    result = run_terminal((lab_wps_event_t){.kind = LAB_WPS_EVENT_TIMEOUT});
    assert(result.session_result == WPS_SESSION_TIMEOUT);
    result = run_terminal((lab_wps_event_t){.kind = LAB_WPS_EVENT_DISCONNECTED});
    assert(result.session_result == WPS_SESSION_DISCONNECTED);
    result = run_terminal((lab_wps_event_t){.kind = LAB_WPS_EVENT_QUEUE_OVERFLOW});
    assert(result.session_result == WPS_SESSION_FATAL && result.dropped_events == 1);
    assert(result.fatal_reason == LAB_WPS_FATAL_QUEUE_OVERFLOW);
}

static void test_identity_loop_and_cancel(void) {
    lab_wps_event_t events[10] = {{.kind = LAB_WPS_EVENT_ASSOCIATED}};
    for (size_t i = 1; i < 10; ++i) events[i].kind = LAB_WPS_EVENT_IDENTITY;
    fake_transport_t fake = {.events = events, .count = 10};
    lab_wps_session_t state = session(&fake);
    lab_wps_request_t input = request("31415927");
    lab_wps_result_t result;
    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.session_result == WPS_SESSION_IDENTITY_LOOP);

    const lab_wps_event_t cancel[] = {{.kind = LAB_WPS_EVENT_CANCELLED}};
    fake = (fake_transport_t){.events = cancel, .count = 1};
    state = session(&fake);
    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.cancelled && result.session_result == WPS_SESSION_FATAL);
    assert(result.fatal_reason == LAB_WPS_FATAL_CANCELLED);

    fake = (fake_transport_t){.events = events, .count = 1};
    state = session(&fake);
    input.cancelled = always_cancel;
    assert(lab_wps_verify_pin(&state, &input, &result));
    assert(result.cancelled && result.session_result == WPS_SESSION_FATAL);
    assert(result.fatal_reason == LAB_WPS_FATAL_CANCELLED);
    assert(fake.index == 0);
}

int main(void) {
    test_complete_verify();
    test_capture_terminal_handshake();
    test_capture_m5_closes_without_m6(false);
    test_capture_m5_closes_without_m6(true);
    test_capture_retransmits_m4_for_duplicate_m3();
    test_capture_timeout_after_m4_is_terminal_success();
    test_capture_preserves_setup_lock_result();
    test_capture_requires_control_pin();
    test_retransmits_last_response_for_duplicate_wsc_messages();
    test_retries_last_response_after_one_stage_timeout();
    test_terminal_results();
    test_identity_loop_and_cancel();
    puts("PASS: WPS lab session engine");
    return 0;
}
