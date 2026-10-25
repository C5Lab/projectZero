#include "led_status_core.h"

#include <string.h>

static led_status_rgb_t rgb(uint8_t red, uint8_t green, uint8_t blue)
{
    return (led_status_rgb_t){.r = red, .g = green, .b = blue};
}

static uint32_t activity_bit(led_status_activity_t activity)
{
    return UINT32_C(1) << (uint32_t)activity;
}

static uint8_t pulse_level(uint64_t elapsed_ms)
{
    uint32_t phase = (uint32_t)(elapsed_ms % UINT64_C(2000));
    uint32_t rise = phase <= 1000U ? phase : 2000U - phase;
    return (uint8_t)(64U + (191U * rise) / 1000U);
}

static uint64_t elapsed_since(uint64_t now_ms, uint64_t start_ms)
{
    return now_ms >= start_ms ? now_ms - start_ms : 0;
}

void led_status_init(led_status_t *status)
{
    if (status == NULL) {
        return;
    }
    memset(status, 0, sizeof(*status));
    status->enabled = true;
}

bool led_status_set_activity(led_status_t *status, led_status_activity_t activity,
                             bool active, uint64_t now_ms)
{
    if (status == NULL || activity <= LED_STATUS_IDLE || activity >= LED_STATUS_ACTIVITY_COUNT) {
        return false;
    }
    uint32_t bit = activity_bit(activity);
    if (active) {
        if ((status->activities & bit) == 0) {
            status->activity_start_ms[activity] = now_ms;
        }
        status->activities |= bit;
    } else {
        status->activities &= ~bit;
    }
    return true;
}

void led_status_clear(led_status_t *status)
{
    if (status == NULL) {
        return;
    }
    status->activities = 0;
    status->event_count = 0;
    status->saw_new_target = false;
    status->saw_threat = false;
}

uint32_t led_status_active_mask(const led_status_t *status)
{
    return status == NULL ? 0 : status->activities;
}

void led_status_set_enabled(led_status_t *status, bool enabled)
{
    if (status == NULL) {
        return;
    }
    status->enabled = enabled;
    if (!enabled) {
        status->event_count = 0;
    }
}

bool led_status_is_enabled(const led_status_t *status)
{
    return status != NULL && status->enabled;
}

static uint32_t event_duration_ms(led_status_event_t event)
{
    switch (event) {
        case LED_STATUS_EVENT_HANDSHAKE_SAVED:
        case LED_STATUS_EVENT_THREAT:
            return 600U;
        case LED_STATUS_EVENT_WPS_VERIFIED:
            return 600U;
        case LED_STATUS_EVENT_NEW_TARGET:
            return 200U;
        default:
            return 0;
    }
}

static void advance_events(led_status_t *status, uint64_t now_ms)
{
    while (status->event_count != 0 && now_ms >= status->event_start_ms &&
           now_ms - status->event_start_ms >= event_duration_ms(status->events[0])) {
        status->event_start_ms += event_duration_ms(status->events[0]);
        --status->event_count;
        for (uint8_t i = 0; i < status->event_count; ++i) {
            status->events[i] = status->events[i + 1];
        }
    }
}

bool led_status_queue_event(led_status_t *status, led_status_event_t event, uint64_t now_ms)
{
    if (status == NULL || !status->enabled || event < 0 || event >= LED_STATUS_EVENT_COUNT) {
        return false;
    }
    advance_events(status, now_ms);
    if (status->event_count >= LED_STATUS_EVENT_QUEUE_CAPACITY) {
        return false;
    }
    if (event == LED_STATUS_EVENT_NEW_TARGET && status->saw_new_target &&
        now_ms >= status->last_new_target_ms &&
        now_ms - status->last_new_target_ms < UINT64_C(2000)) {
        return false;
    }
    if (event == LED_STATUS_EVENT_THREAT && status->saw_threat &&
        now_ms >= status->last_threat_ms &&
        now_ms - status->last_threat_ms < UINT64_C(2000)) {
        return false;
    }
    if (status->event_count == 0) {
        status->event_start_ms = now_ms;
    }
    status->events[status->event_count++] = event;
    if (event == LED_STATUS_EVENT_NEW_TARGET) {
        status->saw_new_target = true;
        status->last_new_target_ms = now_ms;
    } else if (event == LED_STATUS_EVENT_THREAT) {
        status->saw_threat = true;
        status->last_threat_ms = now_ms;
    }
    return true;
}

static led_status_rgb_t render_event(led_status_event_t event, uint64_t elapsed_ms)
{
    uint32_t on_ms = event == LED_STATUS_EVENT_WPS_VERIFIED ? 150U : 100U;
    if ((elapsed_ms % (2U * on_ms)) >= on_ms) {
        return rgb(0, 0, 0);
    }
    switch (event) {
        case LED_STATUS_EVENT_WPS_VERIFIED:
            return rgb(0, 255, 0);
        case LED_STATUS_EVENT_THREAT:
            return rgb(255, 0, 0);
        case LED_STATUS_EVENT_HANDSHAKE_SAVED:
        case LED_STATUS_EVENT_NEW_TARGET:
            return rgb(255, 255, 255);
        default:
            return rgb(0, 0, 0);
    }
}

led_status_rgb_t led_status_render(led_status_t *status, uint64_t now_ms)
{
    if (status == NULL || !status->enabled) {
        return rgb(0, 0, 0);
    }

    advance_events(status, now_ms);
    if ((status->activities & activity_bit(LED_STATUS_OTA)) == 0 &&
        status->event_count != 0 && now_ms >= status->event_start_ms) {
        return render_event(status->events[0], now_ms - status->event_start_ms);
    }

    static const led_status_activity_t priority[] = {
        LED_STATUS_OTA, LED_STATUS_TRANSMIT, LED_STATUS_PORTAL,
        LED_STATUS_CAPTURE, LED_STATUS_WPS, LED_STATUS_MONITOR,
        LED_STATUS_SCAN, LED_STATUS_TRANSFER
    };
    led_status_activity_t activity = LED_STATUS_IDLE;
    for (unsigned i = 0; i < sizeof(priority) / sizeof(priority[0]); ++i) {
        if ((status->activities & activity_bit(priority[i])) != 0) {
            activity = priority[i];
            break;
        }
    }
    if (activity == LED_STATUS_IDLE) {
        return rgb(0, 255, 0);
    }

    uint64_t elapsed = elapsed_since(now_ms, status->activity_start_ms[activity]);
    uint32_t phase;
    uint8_t level;
    switch (activity) {
        case LED_STATUS_SCAN:
            return rgb(0, 0, pulse_level(elapsed));
        case LED_STATUS_MONITOR:
            phase = (uint32_t)(elapsed % 500U);
            return phase < 250U ? rgb(0, 255, 255) : rgb(0, 0, 0);
        case LED_STATUS_CAPTURE:
            phase = (uint32_t)(elapsed % 2000U);
            return (phase < 120U || (phase >= 240U && phase < 360U))
                       ? rgb(0, 255, 255) : rgb(0, 0, 0);
        case LED_STATUS_TRANSMIT:
            phase = (uint32_t)(elapsed % 300U);
            return phase < 150U ? rgb(255, 0, 0) : rgb(0, 0, 0);
        case LED_STATUS_PORTAL:
            level = pulse_level(elapsed);
            return rgb(level, 0, level);
        case LED_STATUS_WPS:
            level = pulse_level(elapsed);
            return rgb(level, (uint8_t)(((uint32_t)level * 128U + 127U) / 255U), 0);
        case LED_STATUS_TRANSFER:
            phase = (uint32_t)(elapsed % 500U);
            return phase < 250U ? rgb(255, 128, 0) : rgb(0, 0, 0);
        case LED_STATUS_OTA:
            return rgb(pulse_level(elapsed), 0, 0);
        default:
            return rgb(0, 255, 0);
    }
}
