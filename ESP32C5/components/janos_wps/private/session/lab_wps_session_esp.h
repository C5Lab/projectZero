#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lab_radio.h"
#include "lab_wps_session.h"

typedef struct lab_wps_esp_session lab_wps_esp_session_t;

/* Radio must already be acquired and marked running for owner_token. */
bool lab_wps_esp_session_open(lab_wps_esp_session_t **out,
                              lab_wps_session_t *session,
                              lab_radio_t *radio, uint32_t owner_token,
                              const lab_wps_request_t *request,
                              bool capture_pixie,
                              lab_wps_fatal_reason_t *failure_reason);
unsigned lab_wps_esp_session_coalesced_m3(
    const lab_wps_esp_session_t *session);
bool lab_wps_esp_session_close(lab_wps_esp_session_t *session);

