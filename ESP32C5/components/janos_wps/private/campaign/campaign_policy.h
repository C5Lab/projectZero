#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "session_policy.h"

typedef enum {
    CAMPAIGN_COMMAND_INVALID = 0,
    CAMPAIGN_COMMAND_PLAN,
    CAMPAIGN_COMMAND_VERIFY,
    CAMPAIGN_COMMAND_RUN,
} campaign_command_type_t;

typedef struct {
    campaign_command_type_t type;
    uint8_t bssid[6];
    char ssid[33];
    char pin[9];
    unsigned start_index;
    unsigned count;
} campaign_command_t;

typedef enum {
    CAMPAIGN_DECISION_SUCCESS = 0,
    CAMPAIGN_DECISION_ADVANCE,
    CAMPAIGN_DECISION_PAUSE,
    CAMPAIGN_DECISION_LOCKED,
    CAMPAIGN_DECISION_FATAL,
    CAMPAIGN_DECISION_EXHAUSTED,
    CAMPAIGN_DECISION_INVALID,
} campaign_decision_t;

bool campaign_parse_command(const char *line, campaign_command_t *command);
campaign_decision_t campaign_decide(wps_session_result_t result);
