#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "wifi_shield_cli.h"

typedef struct {
    int argc;
    const char *const *argv;
    wifi_shield_cli_result_t result;
    wifi_shield_command_kind_t kind;
    bool only;
    bool defence;
    bool pmkid_decoy;
    int first_index_arg;
    int index_count;
} cli_case_t;

static wifi_shield_cli_result_t parse_case(const cli_case_t *test,
                                           wifi_shield_cli_t *out)
{
    char *argv[10] = {0};
    assert(test->argc > 0 && test->argc <= (int)(sizeof(argv) / sizeof(argv[0])));
    for (int i = 0; i < test->argc; ++i) argv[i] = (char *)test->argv[i];
    return wifi_shield_parse_cli(test->argc, argv, out);
}

int main(void)
{
    static const char *const start[] = {"wifi_shield", "start"};
    static const char *const only_one[] = {"wifi_shield", "start", "--only", "1"};
    static const char *const only_many[] = {"wifi_shield", "start", "--only", "1", "3", "7"};
    static const char *const defence[] = {"wifi_shield", "start", "--only", "2", "--defence", "decoy-4way"};
    static const char *const defence_pmkid[] = {"wifi_shield", "start", "--only", "2", "4", "--defence", "decoy-4way", "--pmkid-decoy"};
    static const char *const status[] = {"wifi_shield", "status"};
    static const char *const stop[] = {"wifi_shield", "stop"};
    static const char *const report[] = {"wifi_shield", "report"};
    static const char *const log_status[] = {"wifi_shield", "log", "status"};
    static const char *const report_extra[] = {"wifi_shield", "report", "extra"};
    static const char *const log_only[] = {"wifi_shield", "log"};
    static const char *const log_extra[] = {"wifi_shield", "log", "status", "extra"};
    static const char *const missing_only_index[] = {"wifi_shield", "start", "--only"};
    static const char *const missing_defence_value[] = {"wifi_shield", "start", "--only", "1", "--defence"};
    static const char *const duplicate_only[] = {"wifi_shield", "start", "--only", "1", "--only", "2"};
    static const char *const duplicate_defence[] = {"wifi_shield", "start", "--only", "1", "--defence", "decoy-4way", "--defence", "decoy-4way"};
    static const char *const duplicate_pmkid[] = {"wifi_shield", "start", "--only", "1", "--defence", "decoy-4way", "--pmkid-decoy", "--pmkid-decoy"};
    static const char *const reordered[] = {"wifi_shield", "start", "--defence", "decoy-4way", "--only", "1"};
    static const char *const pmkid_alone[] = {"wifi_shield", "start", "--pmkid-decoy"};
    static const char *const defence_without_only[] = {"wifi_shield", "start", "--defence", "decoy-4way"};
    static const char *const wrong_defence[] = {"wifi_shield", "start", "--only", "1", "--defence", "other"};
    static const char *const unknown[] = {"wifi_shield", "start", "--strange"};
    static const char *const status_extra[] = {"wifi_shield", "status", "extra"};
    static const char *const stop_extra[] = {"wifi_shield", "stop", "extra"};
    static const char *const multi_vector[] = {
        "wifi_shield", "start", "--only", "2", "--defence", "decoy-4way",
        "--pmkid-decoy", "--multi-vector"
    };
    static const char *const multi_vector_without_pmkid[] = {
        "wifi_shield", "start", "--only", "2", "--defence", "decoy-4way",
        "--multi-vector"
    };
    static const char *const duplicate_multi_vector[] = {
        "wifi_shield", "start", "--only", "2", "--defence", "decoy-4way",
        "--pmkid-decoy", "--multi-vector", "--multi-vector"
    };
    static const char *const protect_all[] = {
        "wifi_shield", "start", "--only", "2", "--protect-all"
    };
    static const char *const protect_all_without_only[] = {
        "wifi_shield", "start", "--protect-all"
    };
    static const char *const duplicate_protect_all[] = {
        "wifi_shield", "start", "--only", "2", "--protect-all",
        "--protect-all"
    };
    static const char *const mixed_protect_all[] = {
        "wifi_shield", "start", "--only", "2", "--protect-all",
        "--defence", "decoy-4way"
    };
    static const cli_case_t cases[] = {
        {2, start, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_START, false, false, false, 0, 0},
        {4, only_one, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_START, true, false, false, 3, 1},
        {6, only_many, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_START, true, false, false, 3, 3},
        {6, defence, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_START, true, true, false, 3, 1},
        {8, defence_pmkid, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_START, true, true, true, 3, 2},
        {2, status, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_STATUS, false, false, false, 0, 0},
        {2, stop, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_STOP, false, false, false, 0, 0},
        {2, report, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_REPORT, false, false, false, 0, 0},
        {3, log_status, WIFI_SHIELD_CLI_OK, WIFI_SHIELD_COMMAND_LOG_STATUS, false, false, false, 0, 0},
        {3, report_extra, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {2, log_only, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {4, log_extra, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {3, missing_only_index, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {5, missing_defence_value, WIFI_SHIELD_CLI_DEFENCE_VALUE, 0, false, false, false, 0, 0},
        {6, duplicate_only, WIFI_SHIELD_CLI_DUPLICATE_OPTION, 0, false, false, false, 0, 0},
        {8, duplicate_defence, WIFI_SHIELD_CLI_DUPLICATE_OPTION, 0, false, false, false, 0, 0},
        {8, duplicate_pmkid, WIFI_SHIELD_CLI_DUPLICATE_OPTION, 0, false, false, false, 0, 0},
        {6, reordered, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {3, pmkid_alone, WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE, 0, false, false, false, 0, 0},
        {4, defence_without_only, WIFI_SHIELD_CLI_DEFENCE_REQUIRES_ONLY, 0, false, false, false, 0, 0},
        {6, wrong_defence, WIFI_SHIELD_CLI_DEFENCE_VALUE, 0, false, false, false, 0, 0},
        {3, unknown, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {3, status_extra, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
        {3, stop_extra, WIFI_SHIELD_CLI_USAGE, 0, false, false, false, 0, 0},
    };
    static const char *const errors[] = {
        "Usage: wifi_shield start [--only indexes...] [--protect-all | --defence decoy-4way [--pmkid-decoy [--multi-vector]]] | status | report | log status | stop",
        "Shield Defence requires --only protected scan indices.",
        "Shield Defence value must be decoy-4way.",
        "--pmkid-decoy requires --defence decoy-4way.",
        "Duplicate Shield option.",
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wifi_shield_cli_t out = {0};
        const cli_case_t *test = &cases[i];
        wifi_shield_cli_result_t actual = parse_case(test, &out);
        if (actual != test->result) {
            fprintf(stderr, "case %lu: expected %d, got %d\n",
                    (unsigned long)i, (int)test->result, (int)actual);
        }
        assert(actual == test->result);
        if (test->result == WIFI_SHIELD_CLI_OK) {
            assert(out.kind == test->kind);
            assert(out.only == test->only);
            assert(out.defence == test->defence);
            assert(out.pmkid_decoy == test->pmkid_decoy);
            assert(!out.protect_all);
            assert(out.first_index_arg == test->first_index_arg);
            assert(out.index_count == test->index_count);
        }
    }

    wifi_shield_cli_t multi = {0};
    const cli_case_t multi_case = {.argc = 8, .argv = multi_vector};
    assert(parse_case(&multi_case, &multi) == WIFI_SHIELD_CLI_OK);
    assert(multi.only && multi.defence && multi.pmkid_decoy);
    assert(multi.multi_vector);

    wifi_shield_cli_t rejected = {0};
    const cli_case_t missing_pmkid = {
        .argc = 7, .argv = multi_vector_without_pmkid
    };
    assert(parse_case(&missing_pmkid, &rejected) ==
           WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID);
    const cli_case_t duplicate_multi = {
        .argc = 9, .argv = duplicate_multi_vector
    };
    assert(parse_case(&duplicate_multi, &rejected) ==
           WIFI_SHIELD_CLI_DUPLICATE_OPTION);

    const cli_case_t protect_all_case = {
        .argc = 5, .argv = protect_all
    };
    wifi_shield_cli_t preset = {0};
    assert(parse_case(&protect_all_case, &preset) == WIFI_SHIELD_CLI_OK);
    assert(preset.only && preset.protect_all);
    assert(preset.defence && preset.pmkid_decoy && preset.multi_vector);
    assert(preset.first_index_arg == 3 && preset.index_count == 1);

    const cli_case_t protect_all_unscoped = {
        .argc = 3, .argv = protect_all_without_only
    };
    assert(parse_case(&protect_all_unscoped, &rejected) ==
           WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY);
    const cli_case_t duplicate_preset = {
        .argc = 6, .argv = duplicate_protect_all
    };
    assert(parse_case(&duplicate_preset, &rejected) ==
           WIFI_SHIELD_CLI_DUPLICATE_OPTION);
    const cli_case_t mixed_preset = {
        .argc = 7, .argv = mixed_protect_all
    };
    assert(parse_case(&mixed_preset, &rejected) ==
           WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_USAGE), errors[0]) == 0);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_DEFENCE_REQUIRES_ONLY), errors[1]) == 0);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_DEFENCE_VALUE), errors[2]) == 0);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_PMKID_REQUIRES_DEFENCE), errors[3]) == 0);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_DUPLICATE_OPTION), errors[4]) == 0);
    assert(strcmp(wifi_shield_cli_error(
                      WIFI_SHIELD_CLI_MULTI_VECTOR_REQUIRES_PMKID),
                  "--multi-vector requires --defence decoy-4way and --pmkid-decoy.") == 0);
    assert(strcmp(wifi_shield_cli_error(
                      WIFI_SHIELD_CLI_PROTECT_ALL_REQUIRES_ONLY),
                  "--protect-all requires --only protected scan indices.") == 0);
    assert(strcmp(wifi_shield_cli_error(WIFI_SHIELD_CLI_PROTECT_ALL_CONFLICT),
                  "--protect-all cannot be combined with granular Defence options.") == 0);

    puts("wifi shield CLI: PASS");
    return 0;
}
