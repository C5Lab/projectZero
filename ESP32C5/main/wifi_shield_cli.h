#pragma once

#include <stdbool.h>

typedef enum {
    WIFI_SHIELD_COMMAND_START = 0,
    WIFI_SHIELD_COMMAND_STATUS,
    WIFI_SHIELD_COMMAND_STOP,
    WIFI_SHIELD_COMMAND_REPORT,
    WIFI_SHIELD_COMMAND_LOG_STATUS
} wifi_shield_command_kind_t;

typedef struct {
    wifi_shield_command_kind_t kind;
    bool only;
    bool defence;
    bool pmkid_decoy;
    bool multi_vector;
    bool protect_all;
    int first_index_arg;
    int index_count;
} wifi_shield_cli_t;

typedef enum {
    WIFI_SHIELD_CLI_OK = 0,
    WIFI_SHIELD_CLI_USAGE,
    WIFI_SHIELD_CLI_DEFENCE_REQUIRES_ONLY,
    WIFI_SHIELD_CLI_DEFENCE_VALUE,
    WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE,
    WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID,
    WIFI_SHIELD_CLI_DUPLICATE_OPTION,
    WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY,
    WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT
} wifi_shield_cli_result_t;

wifi_shield_cli_result_t wifi_shield_parse_cli(
    int argc, char **argv, wifi_shield_cli_t *out);
const char *wifi_shield_cli_error(wifi_shield_cli_result_t result);
