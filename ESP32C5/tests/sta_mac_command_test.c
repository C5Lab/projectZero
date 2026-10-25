#include "sta_mac_command.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

#define ARGC(arguments) ((int)(sizeof(arguments) / sizeof((arguments)[0])))

static void expect_set(const char *const argv[], int argc,
                       sta_mac_policy_mode_t expected_mode,
                       const uint8_t expected_mac[STA_MAC_SIZE])
{
    sta_mac_command_t command;
    memset(&command, 0xa5, sizeof(command));
    CHECK(sta_mac_command_parse(argc, argv, &command) == STA_MAC_COMMAND_OK);
    CHECK(command.kind == STA_MAC_COMMAND_SET);
    CHECK(command.policy.version == STA_MAC_POLICY_VERSION);
    CHECK(command.policy.mode == expected_mode);
    CHECK(memcmp(command.policy.mac, expected_mac, STA_MAC_SIZE) == 0);
    CHECK(sta_mac_policy_validate(&command.policy) == STA_MAC_POLICY_OK);
}

static void expect_error(const char *const argv[], int argc,
                         sta_mac_command_status_t expected_status)
{
    sta_mac_command_t command;
    sta_mac_command_t before;
    memset(&command, 0xa5, sizeof(command));
    memcpy(&before, &command, sizeof(command));
    CHECK(sta_mac_command_parse(argc, argv, &command) == expected_status);
    CHECK(memcmp(&command, &before, sizeof(command)) == 0);
}

static void test_accepted_commands(void)
{
    const char *status[] = {"sta_mac", "status"};
    const char *factory[] = {"sta_mac", "set", "factory"};
    const char *random[] = {"sta_mac", "set", "random"};
    const char *fixed[] = {"sta_mac", "set", "fixed", "02:11:22:33:44:55"};
    const char *mixed_case[] = {"sta_mac", "set", "fixed", "aA:bb:Cc:DD:ee:fF"};
    const uint8_t empty_mac[STA_MAC_SIZE] = {0};
    const uint8_t fixed_mac[STA_MAC_SIZE] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t mixed_mac[STA_MAC_SIZE] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    sta_mac_command_t command;

    memset(&command, 0xa5, sizeof(command));
    CHECK(sta_mac_command_parse(ARGC(status), status, &command) == STA_MAC_COMMAND_OK);
    CHECK(command.kind == STA_MAC_COMMAND_STATUS);
    expect_set(factory, ARGC(factory), STA_MAC_MODE_FACTORY, empty_mac);
    expect_set(random, ARGC(random), STA_MAC_MODE_RANDOM_PER_BOOT, empty_mac);
    expect_set(fixed, ARGC(fixed), STA_MAC_MODE_FIXED, fixed_mac);
    expect_set(mixed_case, ARGC(mixed_case), STA_MAC_MODE_FIXED, mixed_mac);
}

static void test_syntax_errors(void)
{
    const char *cases[][5] = {
        {"sta_mac"},
        {"sta_mac", "status", "extra"},
        {"sta_mac", "set"},
        {"sta_mac", "set", "factory", "extra"},
        {"sta_mac", "set", "random", "extra"},
        {"sta_mac", "set", "fixed"},
        {"sta_mac", "set", "fixed", "02:11:22:33:44:55", "extra"},
        {"sta_mac", "set", "other"},
        {"sta_mac", "Status"},
        {"sta_mac", "other"},
        {"other", "status"},
    };
    const int counts[] = {1, 3, 2, 4, 4, 3, 5, 3, 2, 2, 2};
    CHECK(sizeof(cases) / sizeof(cases[0]) == sizeof(counts) / sizeof(counts[0]));
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i)
        expect_error(cases[i], counts[i], STA_MAC_COMMAND_SYNTAX_ERROR);
    expect_error(cases[0], 0, STA_MAC_COMMAND_SYNTAX_ERROR);
}

static void test_invalid_fixed_mac(void)
{
    const char *bad_text[] = {
        "02:11:22:33:44", "2:11:22:33:44:55", "02-11-22-33-44-55",
        "02:11:22:33:44:5g", "02:11:22:33:44:55 "
    };
    const char *bad_address[] = {
        "00:11:22:33:44:55", "01:11:22:33:44:55", "03:11:22:33:44:55"
    };
    const char *argv[] = {"sta_mac", "set", "fixed", NULL};
    for (size_t i = 0; i < sizeof(bad_text) / sizeof(bad_text[0]); ++i) {
        argv[3] = bad_text[i];
        expect_error(argv, ARGC(argv), STA_MAC_COMMAND_INVALID_MAC);
    }
    for (size_t i = 0; i < sizeof(bad_address) / sizeof(bad_address[0]); ++i) {
        argv[3] = bad_address[i];
        expect_error(argv, ARGC(argv), STA_MAC_COMMAND_INVALID_MAC);
    }
}

static void test_invalid_arguments(void)
{
    const char *valid[] = {"sta_mac", "status"};
    const char *null_token[] = {"sta_mac", NULL};
    expect_error(NULL, ARGC(valid), STA_MAC_COMMAND_INVALID_ARGUMENT);
    expect_error(null_token, ARGC(null_token), STA_MAC_COMMAND_INVALID_ARGUMENT);
    expect_error(valid, -1, STA_MAC_COMMAND_INVALID_ARGUMENT);
    CHECK(sta_mac_command_parse(ARGC(valid), valid, NULL) == STA_MAC_COMMAND_INVALID_ARGUMENT);
}

int main(void)
{
    test_accepted_commands();
    test_syntax_errors();
    test_invalid_fixed_mac();
    test_invalid_arguments();
    puts("PASS: STA MAC command parser");
    return 0;
}
