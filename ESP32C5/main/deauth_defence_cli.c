#include "deauth_defence_cli.h"

#include <stddef.h>
#include <string.h>

static const char *const TRACE_TOKEN = "trace";
static const char *const DEFENCE_TOKEN = "defence";
static const char *const PMKID_TOKEN = "pmkid-decoy";

static bool token_is(const char *value, const char *expected)
{
    return value && strcmp(value, expected) == 0;
}
static bool active_token(const char *value)
{
    return token_is(value, TRACE_TOKEN) ||
           token_is(value, DEFENCE_TOKEN) ||
           token_is(value, PMKID_TOKEN);
}

static deauth_cli_result_t fail(deauth_detector_cli_t *out,
                                deauth_cli_result_t result)
{
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    return result;
}

deauth_cli_result_t deauth_defence_parse_cli(
    int argc, char **argv, bool details, deauth_detector_cli_t *out)
{
    if (!out || argc < 1 || !argv || !argv[0]) {
        return fail(out, DEAUTH_CLI_INVALID_OPTION);
    }
    memset(out, 0, sizeof(*out));

    if (!details) {
        for (int i = 1; i < argc; ++i) {
            if (active_token(argv[i])) {
                return fail(out, DEAUTH_CLI_LEGACY_REJECTS_ACTIVE);
            }
        }
        out->watch_only = argc > 1 && token_is(argv[1], "--only");
        out->argument_count = argc;
        return DEAUTH_CLI_OK;
    }

    int argument_count = argc;
    bool pmkid_decoy = false;
    bool defence = false;
    bool trace = false;

    if (argument_count > 1 &&
        token_is(argv[argument_count - 1], PMKID_TOKEN)) {
        pmkid_decoy = true;
        --argument_count;
    }
    if (argument_count > 1 &&
        token_is(argv[argument_count - 1], DEFENCE_TOKEN)) {
        defence = true;
        trace = true;
        --argument_count;
    } else if (pmkid_decoy) {
        return fail(out, DEAUTH_CLI_PMKID_REQUIRES_DEFENCE);
    }
    if (argument_count > 1 &&
        token_is(argv[argument_count - 1], TRACE_TOKEN)) {
        trace = true;
        --argument_count;
    }

    const bool watch_only = argument_count > 1 &&
                            token_is(argv[1], "--only");
    for (int i = 1; i < argument_count; ++i) {
        const char *value = argv[i];
        if (!value || active_token(value) ||
            (value[0] == '-' && value[1] == '-' &&
             !(watch_only && i == 1))) {
            return fail(out, DEAUTH_CLI_INVALID_OPTION);
        }
    }
    if (defence && !watch_only) {
        return fail(out, DEAUTH_CLI_DEFENCE_REQUIRES_ONLY);
    }

    out->trace = trace;
    out->defence = defence;
    out->pmkid_decoy = pmkid_decoy;
    out->watch_only = watch_only;
    out->argument_count = argument_count;
    return DEAUTH_CLI_OK;
}

const char *deauth_defence_cli_error(deauth_cli_result_t result)
{
    switch (result) {
        case DEAUTH_CLI_OK:
            return "";
        case DEAUTH_CLI_DEFENCE_REQUIRES_ONLY:
            return "Defence requires --only protected scan indices.";
        case DEAUTH_CLI_PMKID_REQUIRES_DEFENCE:
            return "pmkid-decoy requires defence.";
        case DEAUTH_CLI_LEGACY_REJECTS_ACTIVE:
            return "Active Defence is unavailable in legacy deauth_detector.";
        case DEAUTH_CLI_INVALID_OPTION:
        default:
            return "Invalid detector option; use --only before scan indices.";
    }
}
