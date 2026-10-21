#ifndef WIFI_ANALYZER_H
#define WIFI_ANALYZER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_wifi.h"

typedef struct {
    /* Called with the shared lease reserved, before any radio change.
     * No command/admission or lease mutation lock is held during this probe. */
    const char *(*busy_reason)(void);
    esp_err_t (*prepare_wifi)(void);
    uint32_t (*baud_rate)(void);
    void (*tx_activity)(void);
    /* Shared JanOS radio admission. Mutations are serialized by the host. */
    bool (*lease_acquire)(uint32_t *generation);
    bool (*lease_mark_running)(uint32_t generation);
    bool (*lease_cancel)(uint32_t generation);
    bool (*lease_release)(uint32_t generation, bool restored);
} wifi_analyzer_hooks_t;

void wifi_analyzer_init(const wifi_analyzer_hooks_t *hooks);
int wifi_analyzer_command(int argc, char **argv);
/* Short console startup transaction. Begin runs before admission unlock;
 * end rolls back only an unconsumed owner+generation announcement. */
uint32_t wifi_analyzer_startup_begin(void);
bool wifi_analyzer_startup_end(uint32_t generation);
int wifi_analyzer_command_with_startup(int argc, char **argv,
                                       const uint32_t *startup_generation);
bool wifi_analyzer_busy(void);
/* Must be the FIRST branch in WIFI_EVENT_SCAN_DONE; true consumes the event. */
bool wifi_analyzer_on_scan_done(const wifi_event_sta_scan_done_t *event);
/* Cooperative cancel/join, no forced task deletion. False keeps the radio reserved. */
bool wifi_analyzer_stop(uint32_t timeout_ms);

#endif
