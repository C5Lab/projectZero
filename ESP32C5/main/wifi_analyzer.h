#ifndef WIFI_ANALYZER_H
#define WIFI_ANALYZER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_wifi.h"

typedef struct {
    /* Called with JanOS command admission serialized, before any radio change. */
    const char *(*busy_reason)(void);
    esp_err_t (*prepare_wifi)(void);
    uint32_t (*baud_rate)(void);
    void (*tx_activity)(void);
} wifi_analyzer_hooks_t;

void wifi_analyzer_init(const wifi_analyzer_hooks_t *hooks);
int wifi_analyzer_command(int argc, char **argv);
bool wifi_analyzer_busy(void);
/* Must be the FIRST branch in WIFI_EVENT_SCAN_DONE; true consumes the event. */
bool wifi_analyzer_on_scan_done(const wifi_event_sta_scan_done_t *event);
/* Cooperative cancel/join, no forced task deletion. False keeps the radio reserved. */
bool wifi_analyzer_stop(uint32_t timeout_ms);

#endif
