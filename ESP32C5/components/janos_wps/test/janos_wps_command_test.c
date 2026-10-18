/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_command.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static janos_wps_command_t parse_ok(int argc, char **argv)
{
    janos_wps_command_t command;
    assert(janos_wps_command_parse(argc, argv, &command) == JANOS_WPS_PARSE_OK);
    return command;
}

static void rejects(int argc, char **argv)
{
    janos_wps_command_t command;
    memset(&command, 0xa5, sizeof(command));
    assert(janos_wps_command_parse(argc, argv, &command) != JANOS_WPS_PARSE_OK);
    for (size_t i = 0; i < sizeof(command); ++i)
        assert(((const unsigned char *)&command)[i] == 0U);
}

int main(void)
{
    char *verify[] = {"wps", "verify", "68:ff:7b:cd:fc:40", "12345670"};
    janos_wps_command_t command = parse_ok(4, verify);
    assert(command.operation == JANOS_WPS_OP_VERIFY);
    assert(strcmp(command.pin, "12345670") == 0);
    assert(janos_wps_operation_requires_radio(command.operation));

    char *pixie[] = {"wps", "pixie", "68:ff:7b:cd:fc:40", "4294967295"};
    command = parse_ok(4, pixie);
    assert(command.operation == JANOS_WPS_OP_PIXIE && command.epoch_set);
    assert(command.epoch == UINT32_MAX);
    char *epoch_overflow[] = {"wps", "pixie", "68:ff:7b:cd:fc:40", "4294967296"};
    rejects(4, epoch_overflow);

    char *plan_split[] = {"jwps", "plan", "68:ff:7b:cd:fc:40",
                          "Pure", "Rental", "Apartments"};
    command = parse_ok(6, plan_split);
    assert(command.operation == JANOS_WPS_OP_JWPS_PLAN);
    assert(strcmp(command.ssid, "Pure Rental Apartments") == 0);
    assert(!janos_wps_operation_requires_radio(command.operation));
    char *plan_quoted[] = {"jwps", "plan", "68:ff:7b:cd:fc:40",
                           "Pure Rental Apartments"};
    command = parse_ok(4, plan_quoted);
    assert(strcmp(command.ssid, "Pure Rental Apartments") == 0);

    char ssid32[] = "12345678901234567890123456789012";
    char ssid33[] = "123456789012345678901234567890123";
    char *plan32[] = {"jwps", "plan", "68:ff:7b:cd:fc:40", ssid32};
    char *plan33[] = {"jwps", "plan", "68:ff:7b:cd:fc:40", ssid33};
    assert(strcmp(parse_ok(4, plan32).ssid, ssid32) == 0);
    rejects(4, plan33);

    char *campaign1[] = {"jwps", "campaign", "68:ff:7b:cd:fc:40",
                         "0", "1", "Lab", "AP"};
    command = parse_ok(7, campaign1);
    assert(command.operation == JANOS_WPS_OP_JWPS_CAMPAIGN);
    assert(command.start_index == 0U && command.count == 1U);
    assert(strcmp(command.ssid, "Lab AP") == 0);
    assert(janos_wps_operation_requires_radio(command.operation));
    char *campaign3[] = {"jwps", "campaign", "68:ff:7b:cd:fc:40", "7", "3"};
    command = parse_ok(5, campaign3);
    assert(command.start_index == 7U && command.count == 3U);
    char *campaign0[] = {"jwps", "campaign", "68:ff:7b:cd:fc:40", "0", "0"};
    char *campaign4[] = {"jwps", "campaign", "68:ff:7b:cd:fc:40", "0", "4"};
    rejects(5, campaign0);
    rejects(5, campaign4);

    char *bad_bssid[] = {"jwps", "plan", "69:ff:7b:cd:fc:40"};
    char *space_bssid[] = {"jwps", "plan", "68: f:7b:cd:fc:40"};
    char *plus_bssid[] = {"jwps", "plan", "68:+f:7b:cd:fc:40"};
    char *bad_separator[] = {"jwps", "plan", "68-ff:7b:cd:fc:40"};
    char *local_bssid[] = {"jwps", "plan", "6a:ff:7b:cd:fc:40"};
    char *signed_epoch[] = {"wps", "pixie", "68:ff:7b:cd:fc:40", "-1"};
    char bad_control[] = {'a', '\n', 'b', '\0'};
    char *control_ssid[] = {"jwps", "plan", "68:ff:7b:cd:fc:40", bad_control};
    rejects(3, bad_bssid);
    rejects(3, space_bssid);
    rejects(3, plus_bssid);
    rejects(3, bad_separator);
    command = parse_ok(3, local_bssid);
    assert(command.operation == JANOS_WPS_OP_JWPS_PLAN);
    rejects(4, signed_epoch);
    rejects(4, control_ssid);

    char *selftest[] = {"selftest", "transport"};
    command = parse_ok(2, selftest);
    assert(command.operation == JANOS_WPS_OP_SELFTEST_TRANSPORT);
    assert(janos_wps_operation_requires_radio(command.operation));
    assert(strcmp(janos_wps_operation_name(command.operation),
                  "selftest_transport") == 0);

    janos_wps_command_wipe(&command);
    for (size_t i = 0; i < sizeof(command); ++i)
        assert(((const unsigned char *)&command)[i] == 0U);
    puts("PASS: JanOS WPS production command parser");
    return 0;
}
