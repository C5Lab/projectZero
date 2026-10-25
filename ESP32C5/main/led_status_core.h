#ifndef JANOS_LED_STATUS_CORE_H
#define JANOS_LED_STATUS_CORE_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    LED_STATUS_IDLE = 0,
    LED_STATUS_SCAN,
    LED_STATUS_MONITOR,
    LED_STATUS_CAPTURE,
    LED_STATUS_TRANSMIT,
    LED_STATUS_PORTAL,
    LED_STATUS_WPS,
    LED_STATUS_TRANSFER,
    LED_STATUS_OTA,
    LED_STATUS_ACTIVITY_COUNT
} led_status_activity_t;

typedef enum {
    LED_STATUS_EVENT_HANDSHAKE_SAVED = 0,
    LED_STATUS_EVENT_WPS_VERIFIED,
    LED_STATUS_EVENT_NEW_TARGET,
    LED_STATUS_EVENT_THREAT,
    LED_STATUS_EVENT_COUNT
} led_status_event_t;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} led_status_rgb_t;

#define LED_STATUS_EVENT_QUEUE_CAPACITY 4

typedef struct {
    uint32_t activities;
    uint64_t activity_start_ms[LED_STATUS_ACTIVITY_COUNT];
    bool enabled;
    led_status_event_t events[LED_STATUS_EVENT_QUEUE_CAPACITY];
    uint8_t event_count;
    uint64_t event_start_ms;
    uint64_t last_new_target_ms;
    uint64_t last_threat_ms;
    bool saw_new_target;
    bool saw_threat;
} led_status_t;

void led_status_init(led_status_t *status);
bool led_status_set_activity(led_status_t *status, led_status_activity_t activity,
                             bool active, uint64_t now_ms);
void led_status_clear(led_status_t *status);
uint32_t led_status_active_mask(const led_status_t *status);
void led_status_set_enabled(led_status_t *status, bool enabled);
bool led_status_is_enabled(const led_status_t *status);
bool led_status_queue_event(led_status_t *status, led_status_event_t event, uint64_t now_ms);
led_status_rgb_t led_status_render(led_status_t *status, uint64_t now_ms);

#endif
