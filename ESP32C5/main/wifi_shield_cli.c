#include "wifi_shield_cli.h"

#include <stddef.h>
#include <string.h>

static const char *const ONLY_TOKEN = "--only";
static const char *const DEFENCE_TOKEN = "--defence";
static const char *const DEFENCE_VALUE = "decoy-4way";
static const char *const PMKID_TOKEN = "--pmkid-decoy";
static const char *const MULTI_VECTOR_TOKEN = "--multi-vector";
static const char *const PROTECT_ALL_TOKEN = "--protect-all";

static bool token_is(const char *value, const char *expected)
{
    return value && strcmp(value, expected) == 0;
}

static wifi_shield_cli_result_t fail(wifi_shield_cli_t *out,
                                     wifi_shield_cli_result_t result)
{
    if (out) memset(out, 0, sizeof(*out));
    return result;
}

static bool index_token(const char *value)
{
    if (!value || !value[0]) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

wifi_shield_cli_result_t wifi_shield_parse_cli(
    int argc, char **argv, wifi_shield_cli_t *out)
{
    if (!out || argc < 2 || !argv || !argv[0] || !argv[1]) {
        return fail(out, WIFI_SHIELD_CLI_USAGE);
    }
    memset(out, 0, sizeof(*out));

    if (token_is(argv[1], "status")) {
        if (argc != 2) return fail(out, WIFI_SHIELD_CLI_USAGE);
        out->kind = WIFI_SHIELD_COMMAND_STATUS;
        return WIFI_SHIELD_CLI_OK;
    }
    if (token_is(argv[1], "stop")) {
        if (argc != 2) return fail(out, WIFI_SHIELD_CLI_USAGE);
        out->kind = WIFI_SHIELD_COMMAND_STOP;
        return WIFI_SHIELD_CLI_OK;
    }
    if (token_is(argv[1], "report")) {
        if (argc != 2) return fail(out, WIFI_SHIELD_CLI_USAGE);
        out->kind = WIFI_SHIELD_COMMAND_REPORT;
        return WIFI_SHIELD_CLI_OK;
    }
    if (token_is(argv[1], "log")) {
        if (argc != 3 || !token_is(argv[2], "status"))
            return fail(out, WIFI_SHIELD_CLI_USAGE);
        out->kind = WIFI_SHIELD_COMMAND_LOG_STATUS;
        return WIFI_SHIELD_CLI_OK;
    }
    if (!token_is(argv[1], "start")) {
        return fail(out, WIFI_SHIELD_CLI_USAGE);
    }

    out->kind = WIFI_SHIELD_COMMAND_START;
    int i = 2;
    if (i < argc && token_is(argv[i], ONLY_TOKEN)) {
        out->only = true;
        out->first_index_arg = i + 1;
        ++i;
        while (i < argc && !token_is(argv[i], DEFENCE_TOKEN) &&
               !token_is(argv[i], PROTECT_ALL_TOKEN)) {
            if (token_is(argv[i], ONLY_TOKEN)) {
                return fail(out, WIFI_SHIELD_CLI_DUPLICATE_OPTION);
            }
            if (token_is(argv[i], PMKID_TOKEN)) {
                return fail(out, WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE);
            }
            if (token_is(argv[i], MULTI_VECTOR_TOKEN)) {
                return fail(out,
                            WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID);
            }
            if (!index_token(argv[i])) return fail(out, WIFI_SHIELD_CLI_USAGE);
            ++out->index_count;
            ++i;
        }
        if (out->index_count == 0) return fail(out, WIFI_SHIELD_CLI_USAGE);
    }

    if (i < argc && token_is(argv[i], PROTECT_ALL_TOKEN)) {
        if (!out->only)
            return fail(out, WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY);
        out->protect_all = true;
        out->defence = true;
        out->pmkid_decoy = true;
        out->multi_vector = true;
        ++i;
        if (i < argc && token_is(argv[i], PROTECT_ALL_TOKEN))
            return fail(out, WIFI_SHIELD_CLI_DUPLICATE_OPTION);
        if (i != argc)
            return fail(out, WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT);
        return WIFI_SHIELD_CLI_OK;
    }

    if (i < argc && token_is(argv[i], DEFENCE_TOKEN)) {
        out->defence = true;
        ++i;
        if (i >= argc || !token_is(argv[i], DEFENCE_VALUE)) {
            return fail(out, WIFI_SHIELD_CLI_DEFENCE_VALUE);
        }
        ++i;
        if (i < argc && token_is(argv[i], DEFENCE_TOKEN)) {
            return fail(out, WIFI_SHIELD_CLI_DUPLICATE_OPTION);
        }
        if (i < argc && token_is(argv[i], ONLY_TOKEN)) {
            return fail(out, WIFI_SHIELD_CLI_USAGE);
        }
        if (i < argc && token_is(argv[i], PMKID_TOKEN)) {
            out->pmkid_decoy = true;
            ++i;
            if (i < argc && token_is(argv[i], PMKID_TOKEN)) {
                return fail(out, WIFI_SHIELD_CLI_DUPLICATE_OPTION);
            }
        }
        if (i < argc && token_is(argv[i], MULTI_VECTOR_TOKEN)) {
            if (!out->pmkid_decoy) {
                return fail(out,
                            WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID);
            }
            out->multi_vector = true;
            ++i;
            if (i < argc && token_is(argv[i], MULTI_VECTOR_TOKEN)) {
                return fail(out, WIFI_SHIELD_CLI_DUPLICATE_OPTION);
            }
        }
        if (i < argc && token_is(argv[i], PROTECT_ALL_TOKEN))
            return fail(out, WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT);
        if (i != argc) return fail(out, WIFI_SHIELD_CLI_USAGE);
        if (!out->only) return fail(out, WIFI_SHIELD_CLI_DEFENCE_REQUIRES_ONLY);
        return WIFI_SHIELD_CLI_OK;
    }

    if (i < argc && token_is(argv[i], PMKID_TOKEN)) {
        return fail(out, WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE);
    }
    if (i < argc && token_is(argv[i], MULTI_VECTOR_TOKEN)) {
        return fail(out, WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID);
    }
    if (i < argc && token_is(argv[i], PROTECT_ALL_TOKEN)) {
        return fail(out, WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY);
    }
    if (i != argc) return fail(out, WIFI_SHIELD_CLI_USAGE);
    return WIFI_SHIELD_CLI_OK;
}

const char *wifi_shield_cli_error(wifi_shield_cli_result_t result)
{
    switch (result) {
        case WIFI_SHIELD_CLI_OK:
            return "";
        case WIFI_SHIELD_CLI_DEFENCE_REQUIRES_ONLY:
            return "Shield Defence requires --only protected scan indices.";
        case WIFI_SHIELD_CLI_DEFENCE_VALUE:
            return "Shield Defence value must be decoy-4way.";
        case WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE:
            return "--pmkid-decoy requires --defence decoy-4way.";
        case WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID:
            return "--multi-vector requires --defence decoy-4way and --pmkid-decoy.";
        case WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY:
            return "--protect-all requires --only protected scan indices.";
        case WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT:
            return "--protect-all cannot be combined with granular Defence options.";
        case WIFI_SHIELD_CLI_DUPLICATE_OPTION:
            return "Duplicate Shield option.";
        case WIFI_SHIELD_CLI_USAGE:
        default:
            return "Usage: wifi_shield start [--only indexes...] [--protect-all | --defence decoy-4way [--pmkid-decoy [--multi-vector]]] | status | report | log status | stop";
    }
}
