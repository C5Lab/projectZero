#pragma once

#include <stdbool.h>

typedef struct {
    bool trace;
    bool defence;
    bool pmkid_decoy;
    bool watch_only;
    int argument_count;
} deauth_detector_cli_t;

typedef enum {
    DEAUTH_CLI_OK = 0,
    DEAUTH_CLI_INVALID_OPTION,
    DEAUTH_CLI_DEFENCE_REQUIRES_ONLY,
    DEAUTH_CLI_PMKID_REQUIRES_DEFENCE,
    DEAUTH_CLI_LEGACY_REJECTS_ACTIVE,
} deauth_cli_result_t;

deauth_cli_result_t deauth_defence_parse_cli(
    int argc, char **argv, bool details, deauth_detector_cli_t *out);

const char *deauth_defence_cli_error(deauth_cli_result_t result);
