#ifndef STA_MAC_COMMAND_H
#define STA_MAC_COMMAND_H

#include "sta_mac_policy_core.h"

typedef enum {
    STA_MAC_COMMAND_STATUS = 0,
    STA_MAC_COMMAND_SET
} sta_mac_command_kind_t;

/* policy is populated only for STA_MAC_COMMAND_SET. */
typedef struct {
    sta_mac_command_kind_t kind;
    sta_mac_policy_record_t policy;
} sta_mac_command_t;

typedef enum {
    STA_MAC_COMMAND_OK = 0,
    STA_MAC_COMMAND_INVALID_ARGUMENT,
    STA_MAC_COMMAND_SYNTAX_ERROR,
    STA_MAC_COMMAND_INVALID_MAC
} sta_mac_command_status_t;

/* argc includes the "sta_mac" command name. out remains unchanged on error. */
sta_mac_command_status_t sta_mac_command_parse(int argc, const char *const argv[],
                                               sta_mac_command_t *out);

#endif
