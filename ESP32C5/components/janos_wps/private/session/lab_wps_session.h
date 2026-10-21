#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pixie.h"
#include "session_policy.h"

enum {
    LAB_WPS_NETWORK_KEY_MAX = 64,
    LAB_WPS_MAX_EVENTS = 128,
};

typedef struct {
    char manufacturer[33];
    char model_name[33];
    char model_number[33];
    char device_name[33];
} lab_wps_identity_t;

typedef enum {
    LAB_WPS_EVENT_ASSOCIATED = 0,
    LAB_WPS_EVENT_IDENTITY,
    LAB_WPS_EVENT_M1,
    LAB_WPS_EVENT_M3,
    LAB_WPS_EVENT_M5,
    LAB_WPS_EVENT_M7,
    LAB_WPS_EVENT_NACK,
    LAB_WPS_EVENT_EAP_FAILURE,
    LAB_WPS_EVENT_TIMEOUT,
    LAB_WPS_EVENT_DISCONNECTED,
    LAB_WPS_EVENT_QUEUE_OVERFLOW,
    LAB_WPS_EVENT_CANCELLED,
} lab_wps_event_kind_t;

typedef enum {
    LAB_WPS_ACTION_START = 0,
    LAB_WPS_ACTION_IDENTITY,
    LAB_WPS_ACTION_M2,
    LAB_WPS_ACTION_M4,
    LAB_WPS_ACTION_M6,
    LAB_WPS_ACTION_NACK,
} lab_wps_action_t;

typedef enum {
    LAB_WPS_FATAL_NONE = 0,
    LAB_WPS_FATAL_INVALID_SEQUENCE,
    LAB_WPS_FATAL_PIXIE_RECOVERY,
    LAB_WPS_FATAL_PIN_INSTALL,
    LAB_WPS_FATAL_CREDENTIAL,
    LAB_WPS_FATAL_QUEUE_OVERFLOW,
    LAB_WPS_FATAL_CANCELLED,
    LAB_WPS_FATAL_UNEXPECTED_EVENT,
    LAB_WPS_FATAL_EVENT_LIMIT,
    LAB_WPS_FATAL_TARGET_NOT_FOUND,
    LAB_WPS_FATAL_WPS_UNAVAILABLE,
    LAB_WPS_FATAL_SCAN_START,
    LAB_WPS_FATAL_SCAN_RESULTS,
    LAB_WPS_FATAL_CALLBACK_INSTALL,
    LAB_WPS_FATAL_EVENT_HANDLER,
    LAB_WPS_FATAL_WIFI_CONFIG,
    LAB_WPS_FATAL_CRYPTO_INIT,
    LAB_WPS_FATAL_WIFI_CONNECT,
    LAB_WPS_FATAL_ADAPTER_MEMORY,
    LAB_WPS_FATAL_ADAPTER_SCRATCH,
    LAB_WPS_FATAL_ADAPTER_QUEUE,
    LAB_WPS_FATAL_SESSION_INIT,
    LAB_WPS_FATAL_SESSION_MAC,
    LAB_WPS_FATAL_RADIO_ACQUIRE,
    LAB_WPS_FATAL_RADIO_START,
} lab_wps_fatal_reason_t;

/*
 * The ESP adapter authenticates and decrypts raw WSC frames before publishing
 * this bounded event.  Pointers are borrowed only for the duration of
 * next_event(); the engine copies successful output before asking for another
 * event.
 */
typedef struct {
    lab_wps_event_kind_t kind;
    uint8_t eap_id;
    bool authenticated;
    bool pin_half_verified;
    bool fragmented;
    bool credential_present;
    bool config_error_present;
    uint16_t config_error;
    const uint8_t *network_key;
    size_t network_key_len;
    const uint8_t *ssid;
    size_t ssid_len;
    pixie_bundle_t bundle;
    lab_wps_identity_t identity;
} lab_wps_event_t;

typedef struct {
    bool (*next_event)(void *context, lab_wps_event_t *event);
    bool (*send_action)(void *context, lab_wps_action_t action, uint8_t eap_id);
} lab_wps_session_ops_t;

typedef bool (*lab_wps_cancel_fn)(void *context);

typedef struct {
    uint8_t bssid[6];
    const char *pin;
    size_t pin_len;
    lab_wps_cancel_fn cancelled;
    void *cancel_context;
} lab_wps_request_t;

typedef struct {
    wps_session_result_t session_result;
    unsigned identities;
    unsigned dropped_events;
    unsigned coalesced_m3;
    unsigned fragmented_messages;
    lab_wps_fatal_reason_t fatal_reason;
    bool credential_present;
    bool cancelled;
    uint8_t network_key[LAB_WPS_NETWORK_KEY_MAX];
    size_t network_key_len;
    char ssid[33];
    lab_wps_identity_t identity;
} lab_wps_result_t;

typedef struct {
    lab_wps_session_ops_t ops;
    void *ops_context;
} lab_wps_session_t;

bool lab_wps_session_init(lab_wps_session_t *session,
                          const lab_wps_session_ops_t *ops,
                          void *ops_context);
bool lab_wps_verify_pin(lab_wps_session_t *session,
                        const lab_wps_request_t *request,
                        lab_wps_result_t *result);
bool lab_wps_capture_pixie(lab_wps_session_t *session,
                           const lab_wps_request_t *request,
                           pixie_bundle_t *bundle_out,
                           lab_wps_result_t *result);
void lab_wps_result_wipe(lab_wps_result_t *result);

