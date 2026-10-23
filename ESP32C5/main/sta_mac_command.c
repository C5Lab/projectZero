#include "sta_mac_command.h"

#include <string.h>

sta_mac_command_status_t sta_mac_command_parse(int argc, const char *const argv[],
                                               sta_mac_command_t *out)
{
    if (argc < 0 || !argv || !out) return STA_MAC_COMMAND_INVALID_ARGUMENT;
    for (int i = 0; i < argc; ++i)
        if (!argv[i]) return STA_MAC_COMMAND_INVALID_ARGUMENT;

    if (argc < 2 || strcmp(argv[0], "sta_mac") != 0)
        return STA_MAC_COMMAND_SYNTAX_ERROR;

    sta_mac_command_t command = {0};
    if (strcmp(argv[1], "status") == 0) {
        if (argc != 2) return STA_MAC_COMMAND_SYNTAX_ERROR;
        command.kind = STA_MAC_COMMAND_STATUS;
    } else if (strcmp(argv[1], "set") == 0) {
        if (argc < 3) return STA_MAC_COMMAND_SYNTAX_ERROR;
        command.kind = STA_MAC_COMMAND_SET;
        command.policy.version = STA_MAC_POLICY_VERSION;
        if (strcmp(argv[2], "factory") == 0 && argc == 3) {
            command.policy.mode = STA_MAC_MODE_FACTORY;
        } else if (strcmp(argv[2], "random") == 0 && argc == 3) {
            command.policy.mode = STA_MAC_MODE_RANDOM_PER_BOOT;
        } else if (strcmp(argv[2], "fixed") == 0 && argc == 4) {
            command.policy.mode = STA_MAC_MODE_FIXED;
            if (sta_mac_fixed_parse(argv[3], command.policy.mac) != STA_MAC_POLICY_OK)
                return STA_MAC_COMMAND_INVALID_MAC;
        } else {
            return STA_MAC_COMMAND_SYNTAX_ERROR;
        }
    } else {
        return STA_MAC_COMMAND_SYNTAX_ERROR;
    }

    *out = command;
    return STA_MAC_COMMAND_OK;
}
