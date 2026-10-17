#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "campaign_policy.h"

static void parses_bounded_commands(void) {
    campaign_command_t command;
    assert(campaign_parse_command("plan 68:ff:7b:cd:fc:40", &command));
    assert(command.type == CAMPAIGN_COMMAND_PLAN);
    assert(campaign_parse_command("plan b0:be:76:70:0e:90 LAB", &command));
    assert(strcmp(command.ssid, "LAB") == 0);
    assert(campaign_parse_command("verify 68:ff:7b:cd:fc:40 12345670", &command));
    assert(strcmp(command.pin, "12345670") == 0);
    assert(campaign_parse_command("campaign b0:be:76:70:0e:90 2 3 LAB", &command));
    assert(command.start_index == 2U && command.count == 3U);
}

static void rejects_unsafe_commands(void) {
    campaign_command_t command;
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 +0 1", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 0 +1", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 -0 1", &command));
    memset(&command, 0xAA, sizeof(command));
    assert(!campaign_parse_command("plan 68:ff:7b:cd:fc:40 123456789012345678901234567890123", &command));
    assert(command.type == CAMPAIGN_COMMAND_INVALID);
    assert(!campaign_parse_command("plan 69:ff:7b:cd:fc:40", &command));
    assert(!campaign_parse_command("verify 68:ff:7b:cd:fc:40 12345678", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 0 0", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 0 4", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 128 1", &command));
    assert(!campaign_parse_command("campaign 68:ff:7b:cd:fc:40 0 1 extra junk", &command));
}

static void advances_only_after_confirmed_pin_rejection(void) {
    assert(campaign_decide(WPS_SESSION_SUCCESS) == CAMPAIGN_DECISION_SUCCESS);
    assert(campaign_decide(WPS_SESSION_PIN_REJECTED) == CAMPAIGN_DECISION_ADVANCE);
    assert(campaign_decide(WPS_SESSION_SETUP_LOCKED) == CAMPAIGN_DECISION_LOCKED);
    assert(campaign_decide(WPS_SESSION_TIMEOUT) == CAMPAIGN_DECISION_PAUSE);
    assert(campaign_decide(WPS_SESSION_PRE_PIN_REJECTED) == CAMPAIGN_DECISION_PAUSE);
    assert(campaign_decide(WPS_SESSION_DISCONNECTED) == CAMPAIGN_DECISION_PAUSE);
    assert(campaign_decide(WPS_SESSION_IDENTITY_LOOP) == CAMPAIGN_DECISION_PAUSE);
    assert(campaign_decide(WPS_SESSION_FATAL) == CAMPAIGN_DECISION_FATAL);
}

static void parser_boundaries_and_atomic_failure(void) {
    const char *invalid[] = {
        "", "plan", "verify 68:ff:7b:cd:fc:40", "campaign 68:ff:7b:cd:fc:40 0",
        "PLAN 68:ff:7b:cd:fc:40", "unknown 68:ff:7b:cd:fc:40",
        "plan 68:ff:7b:cd:fc", "plan 68:ff:7b:cd:fc:4g",
        "plan 68:ff-7b:cd:fc:40", "plan 00:00:00:00:00:00",
        "plan ff:ff:ff:ff:ff:ff", "plan 68:ff:7b:cd:fc:40x",
        "verify 68:ff:7b:cd:fc:40 1234567", "verify 68:ff:7b:cd:fc:40 123456700",
        "verify 68:ff:7b:cd:fc:40 1234567a", "verify 68:ff:7b:cd:fc:40 12345670 junk",
        "plan 68:ff:7b:cd:fc:40 LAB junk", "campaign 68:ff:7b:cd:fc:40 0 1 LAB junk",
        "campaign 68:ff:7b:cd:fc:40 1x 1", "campaign 68:ff:7b:cd:fc:40 0 1x",
        "campaign 68:ff:7b:cd:fc:40 0 -1", "campaign 68:ff:7b:cd:fc:40 -1 1",
        "campaign 68:ff:7b:cd:fc:40 9999999999999999999999999999999999 1",
        "plan 68:ff:7b:cd:fc:40 123456789012345678901234567890123",
        "campaign 68:ff:7b:cd:fc:40 0 1 123456789012345678901234567890123",
        "plan 68:ff:7b:cd:fc:40 LAB\033",
    };
    campaign_command_t command, empty = {0};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(&command, 0xAA, sizeof(command));
        assert(!campaign_parse_command(invalid[i], &command));
        assert(memcmp(&command, &empty, sizeof(command)) == 0);
    }
    memset(&command, 0xAA, sizeof(command));
    assert(!campaign_parse_command(NULL, &command));
    assert(memcmp(&command, &empty, sizeof(command)) == 0);
    assert(!campaign_parse_command("plan 68:ff:7b:cd:fc:40", NULL));
    char too_long[129];
    memset(too_long, ' ', 128);
    memcpy(too_long, "plan 68:ff:7b:cd:fc:40", 22);
    too_long[128] = 0;
    assert(!campaign_parse_command(too_long, &command));
    assert(memcmp(&command, &empty, sizeof(command)) == 0);
    too_long[127] = 0;
    assert(campaign_parse_command(too_long, &command));
    assert(campaign_parse_command(" \tplan 68-FF-7B-CD-FC-40 12345678901234567890123456789012 \r\n", &command));
    assert(strlen(command.ssid) == 32);
    assert(campaign_parse_command("campaign 68:ff:7b:cd:fc:40 127 3", &command));
    assert(command.start_index == 127 && command.count == 3);
    assert(campaign_parse_command("campaign 68:ff:7b:cd:fc:40 0 1", &command));
}

int main(void) {
    parses_bounded_commands();
    rejects_unsafe_commands();
    parser_boundaries_and_atomic_failure();
    advances_only_after_confirmed_pin_rejection();
    puts("PASS: WPS campaign policy");
    return 0;
}
