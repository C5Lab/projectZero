#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "deauth_defence_cli.h"

static deauth_cli_result_t parse(int argc, const char *const input[],
                                 bool details, deauth_detector_cli_t *out)
{
    char *argv[8] = {0};
    assert(argc > 0 && argc <= (int)(sizeof(argv) / sizeof(argv[0])));
    for (int i = 0; i < argc; ++i) {
        argv[i] = (char *)input[i];
    }
    return deauth_defence_parse_cli(argc, argv, details, out);
}
static void expect_ok(int argc, const char *const argv[], bool details,
                      bool trace, bool defence, bool pmkid_decoy,
                      bool watch_only, int argument_count)
{
    deauth_detector_cli_t options = {0};
    assert(parse(argc, argv, details, &options) == DEAUTH_CLI_OK);
    assert(options.trace == trace);
    assert(options.defence == defence);
    assert(options.pmkid_decoy == pmkid_decoy);
    assert(options.watch_only == watch_only);
    assert(options.argument_count == argument_count);
}

static void expect_error(int argc, const char *const argv[], bool details,
                         deauth_cli_result_t expected, const char *message)
{
    deauth_detector_cli_t options = {
        .trace = true,
        .defence = true,
        .pmkid_decoy = true,
        .watch_only = true,
        .argument_count = 99,
    };
    assert(parse(argc, argv, details, &options) == expected);
    assert(strcmp(deauth_defence_cli_error(expected), message) == 0);
    assert(!options.trace && !options.defence && !options.pmkid_decoy);
    assert(!options.watch_only && options.argument_count == 0);
}

int main(void)
{
    const char *bare[] = {"deauth_detector_v2"};
    const char *watch[] = {"deauth_detector_v2", "--only", "1", "2"};
    const char *trace[] = {"deauth_detector_v2", "trace"};
    const char *watch_trace[] = {
        "deauth_detector_v2", "--only", "1", "trace"
    };
    const char *watch_defence[] = {
        "deauth_detector_v2", "--only", "1", "defence"
    };
    const char *watch_trace_defence[] = {
        "deauth_detector_v2", "--only", "1", "2", "trace", "defence"
    };
    const char *watch_pmkid[] = {
        "deauth_detector_v2", "--only", "1", "trace", "defence",
        "pmkid-decoy"
    };

    expect_ok(1, bare, true, false, false, false, false, 1);
    expect_ok(4, watch, true, false, false, false, true, 4);
    expect_ok(2, trace, true, true, false, false, false, 1);
    expect_ok(4, watch_trace, true, true, false, false, true, 3);
    /* Defence implies fast Trace even when the trace token is omitted. */
    expect_ok(4, watch_defence, true, true, true, false, true, 3);
    expect_ok(6, watch_trace_defence, true, true, true, false, true, 4);
    expect_ok(6, watch_pmkid, true, true, true, true, true, 3);

    const char *all_defence[] = {"deauth_detector_v2", "defence"};
    const char *all_trace_defence[] = {
        "deauth_detector_v2", "trace", "defence"
    };
    expect_error(2, all_defence, true, DEAUTH_CLI_DEFENCE_REQUIRES_ONLY,
                 "Defence requires --only protected scan indices.");
    expect_error(3, all_trace_defence, true,
                 DEAUTH_CLI_DEFENCE_REQUIRES_ONLY,
                 "Defence requires --only protected scan indices.");

    const char *pmkid_alone[] = {
        "deauth_detector_v2", "--only", "1", "pmkid-decoy"
    };
    expect_error(4, pmkid_alone, true, DEAUTH_CLI_PMKID_REQUIRES_DEFENCE,
                 "pmkid-decoy requires defence.");

    const char *wrong_order[] = {
        "deauth_detector_v2", "--only", "1", "defence", "trace"
    };
    const char *duplicate_trace[] = {
        "deauth_detector_v2", "--only", "1", "trace", "trace"
    };
    const char *duplicate_defence[] = {
        "deauth_detector_v2", "--only", "1", "defence", "defence"
    };
    const char *misplaced[] = {
        "deauth_detector_v2", "--only", "1", "defence", "2"
    };
    const char *dashed[] = {
        "deauth_detector_v2", "--only", "1", "--trace"
    };
    const char *unknown_option[] = {
        "deauth_detector_v2", "--only", "1", "--active"
    };
    const char *const invalid_message =
        "Invalid detector option; use --only before scan indices.";
    expect_error(5, wrong_order, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);
    expect_error(5, duplicate_trace, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);
    expect_error(5, duplicate_defence, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);
    expect_error(5, misplaced, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);
    expect_error(4, dashed, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);
    expect_error(4, unknown_option, true, DEAUTH_CLI_INVALID_OPTION,
                 invalid_message);

    const char *legacy_trace[] = {"deauth_detector", "trace"};
    const char *legacy_defence[] = {
        "deauth_detector", "--only", "1", "defence"
    };
    expect_error(2, legacy_trace, false, DEAUTH_CLI_LEGACY_REJECTS_ACTIVE,
                 "Active Defence is unavailable in legacy deauth_detector.");
    expect_error(4, legacy_defence, false, DEAUTH_CLI_LEGACY_REJECTS_ACTIVE,
                 "Active Defence is unavailable in legacy deauth_detector.");

    assert(deauth_defence_parse_cli(0, NULL, true, NULL) ==
           DEAUTH_CLI_INVALID_OPTION);
    assert(strcmp(deauth_defence_cli_error(DEAUTH_CLI_OK), "") == 0);
    assert(strcmp(deauth_defence_cli_error((deauth_cli_result_t)99),
                  invalid_message) == 0);

    puts("deauth defence CLI: PASS");
    return 0;
}
