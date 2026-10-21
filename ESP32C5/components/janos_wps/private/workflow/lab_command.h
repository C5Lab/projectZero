#ifndef LAB_COMMAND_H
#define LAB_COMMAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LAB_LINE_CAPACITY 160u

typedef enum {
    LAB_COMMAND_INVALID = 0,
    LAB_COMMAND_HELP,
    LAB_COMMAND_STATUS,
    LAB_COMMAND_STA_MAC_STATUS,
    LAB_COMMAND_STA_MAC_SET,
    LAB_COMMAND_JWPS_PLAN,
    LAB_COMMAND_WPS_VERIFY,
    LAB_COMMAND_WPS_CAMPAIGN,
    LAB_COMMAND_WPS_PIXIE,
    LAB_COMMAND_SELFTEST_DB,
    LAB_COMMAND_SELFTEST_FRAGMENT,
    LAB_COMMAND_SELFTEST_TRANSPORT,
    LAB_COMMAND_SELFTEST_PIXIE,
    LAB_COMMAND_SECRET_STATUS,
    LAB_COMMAND_SECRET_REVEAL,
    LAB_COMMAND_SECRET_ERASE,
    LAB_COMMAND_REBOOT,
} lab_command_kind_t;

typedef enum {
    LAB_MAC_FACTORY = 0,
    LAB_MAC_RANDOM,
    LAB_MAC_FIXED,
} lab_mac_mode_t;

typedef struct {
    lab_command_kind_t kind;
    uint8_t bssid[6];
    uint8_t fixed_mac[6];
    lab_mac_mode_t mac_mode;
    char ssid[33];
    char pin[9];
    unsigned start_index;
    unsigned count;
    uint32_t epoch;
    bool epoch_set;
} lab_command_t;

typedef enum { LAB_LINE_PENDING, LAB_LINE_READY, LAB_LINE_INVALID } lab_line_result_t;
typedef enum { LAB_ECHO_NONE, LAB_ECHO_BYTE, LAB_ECHO_NEWLINE, LAB_ECHO_ERASE } lab_echo_action_t;

typedef struct {
    char data[LAB_LINE_CAPACITY];
    size_t length;
    bool overflow;
    bool cr_pending;
} lab_line_t;

bool lab_command_parse(const char *line, size_t length, lab_command_t *out);
lab_line_result_t lab_line_feed(lab_line_t *line, unsigned char byte,
                                lab_echo_action_t *echo);
lab_line_result_t lab_line_idle(lab_line_t *line);
bool lab_command_is_secret_input(const lab_line_t *line);
void lab_command_wipe(lab_command_t *command);

#endif
