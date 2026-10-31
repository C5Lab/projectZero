#ifndef LAB_C5_WEB_MODULE_H
#define LAB_C5_WEB_MODULE_H

#include <stdint.h>

#define C5_WEB_LAUNCH_VERSION 1u
#define C5_WEB_SELECT_COMMAND_CAPACITY 256u

typedef enum {
    C5WebModePortal,
    C5WebModeEvilTwin,
    C5WebModeKarma,
} C5WebMode;

/* Small persistent selection metadata; Web list/status/QR allocations stay in FAL. */
typedef struct {
    char portal_ssid[33];
    /* All Web modes share the JanOS HTML selection. */
    uint8_t selected_html_id;
    char selected_html_name[32];
    /* Mirror of the shared selection for the host's existing session layout. */
    uint8_t evil_html_id;
    char evil_html_name[32];
    uint8_t selected_probe_id;
    char selected_probe_name[48];
    uint8_t portal_menu_index;
    uint8_t evil_menu_index;
    uint8_t karma_menu_index;
} C5WebSessionPrefs;

/* A one-time copy of host selection/configuration. No pointers into SimpleApp. */
typedef struct {
    uint32_t version;
    uint32_t size;
    C5WebMode mode;
    uint32_t selected_count;
    char first_selected_ssid[33];
    char select_networks[C5_WEB_SELECT_COMMAND_CAPACITY];
    uint32_t karma_duration_sec;
    uint32_t ticks_per_second;
    uint32_t probe_refresh_delay_ticks;
    C5WebSessionPrefs prefs;
} C5WebLaunchContext;

#endif
