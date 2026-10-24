#include "led_status_core.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static void expect_rgb(led_status_rgb_t actual, uint8_t red, uint8_t green, uint8_t blue)
{
    assert(actual.r == red);
    assert(actual.g == green);
    assert(actual.b == blue);
}

static void idle_and_manual_off(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_is_enabled(&status));
    assert(led_status_active_mask(&status) == 0);
    expect_rgb(led_status_render(&status, 0), 0, 255, 0);
    led_status_set_enabled(&status, false);
    expect_rgb(led_status_render(&status, 1), 0, 0, 0);
    led_status_set_enabled(&status, true);
    expect_rgb(led_status_render(&status, 2), 0, 255, 0);
}

static void base_patterns_and_priority(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(!led_status_set_activity(&status, LED_STATUS_IDLE, true, 0));
    assert(led_status_set_activity(&status, LED_STATUS_SCAN, true, 100));
    expect_rgb(led_status_render(&status, 100), 0, 0, 64);
    expect_rgb(led_status_render(&status, 1100), 0, 0, 255);
    expect_rgb(led_status_render(&status, 2100), 0, 0, 64);
    assert(led_status_set_activity(&status, LED_STATUS_MONITOR, true, 1100));
    expect_rgb(led_status_render(&status, 1100), 0, 255, 255);
    expect_rgb(led_status_render(&status, 1350), 0, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_CAPTURE, true, 1500));
    expect_rgb(led_status_render(&status, 1500), 0, 255, 255);
    expect_rgb(led_status_render(&status, 1620), 0, 0, 0);
    expect_rgb(led_status_render(&status, 1740), 0, 255, 255);
    expect_rgb(led_status_render(&status, 1860), 0, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_PORTAL, true, 2000));
    expect_rgb(led_status_render(&status, 2000), 64, 0, 64);
    assert(led_status_set_activity(&status, LED_STATUS_TRANSMIT, true, 2200));
    expect_rgb(led_status_render(&status, 2200), 255, 0, 0);
    expect_rgb(led_status_render(&status, 2350), 0, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_OTA, true, 2400));
    expect_rgb(led_status_render(&status, 2400), 64, 0, 0);
    expect_rgb(led_status_render(&status, 3400), 255, 0, 0);
    led_status_set_enabled(&status, false);
    expect_rgb(led_status_render(&status, 3500), 0, 0, 0);
    led_status_set_enabled(&status, true);
    expect_rgb(led_status_render(&status, 4400), 64, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_OTA, false, 4600));
    assert(led_status_set_activity(&status, LED_STATUS_TRANSMIT, false, 4600));
    expect_rgb(led_status_render(&status, 5000), 255, 0, 255);
    led_status_clear(&status);
    assert(led_status_active_mask(&status) == 0);
    expect_rgb(led_status_render(&status, 5001), 0, 255, 0);
}

static void lower_priority_families(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_set_activity(&status, LED_STATUS_TRANSFER, true, 0));
    expect_rgb(led_status_render(&status, 0), 255, 128, 0);
    expect_rgb(led_status_render(&status, 250), 0, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_WPS, true, 500));
    expect_rgb(led_status_render(&status, 500), 64, 32, 0);
    expect_rgb(led_status_render(&status, 1500), 255, 128, 0);
    assert(led_status_set_activity(&status, LED_STATUS_WPS, false, 1500));
    expect_rgb(led_status_render(&status, 1500), 255, 128, 0);
    assert(led_status_set_activity(&status, LED_STATUS_TRANSFER, false, 1500));
    expect_rgb(led_status_render(&status, 1500), 0, 255, 0);
}

static void handshake_flash_restores_latest_activity(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_set_activity(&status, LED_STATUS_SCAN, true, 0));
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_HANDSHAKE_SAVED, 100));
    expect_rgb(led_status_render(&status, 100), 255, 255, 255);
    expect_rgb(led_status_render(&status, 199), 255, 255, 255);
    expect_rgb(led_status_render(&status, 200), 0, 0, 0);
    expect_rgb(led_status_render(&status, 300), 255, 255, 255);
    expect_rgb(led_status_render(&status, 500), 255, 255, 255);
    expect_rgb(led_status_render(&status, 600), 0, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_MONITOR, true, 650));
    expect_rgb(led_status_render(&status, 700), 0, 255, 255);
}

static void events_queue_in_order(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_HANDSHAKE_SAVED, 100));
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_WPS_VERIFIED, 150));
    expect_rgb(led_status_render(&status, 500), 255, 255, 255);
    expect_rgb(led_status_render(&status, 700), 0, 255, 0);
    expect_rgb(led_status_render(&status, 849), 0, 255, 0);
    expect_rgb(led_status_render(&status, 850), 0, 0, 0);
    expect_rgb(led_status_render(&status, 1000), 0, 255, 0);
    expect_rgb(led_status_render(&status, 1300), 0, 255, 0);
}

static void rate_limit_and_manual_override(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_NEW_TARGET, 0));
    expect_rgb(led_status_render(&status, 0), 255, 255, 255);
    assert(!led_status_queue_event(&status, LED_STATUS_EVENT_NEW_TARGET, 1999));
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_NEW_TARGET, 2000));
    expect_rgb(led_status_render(&status, 2000), 255, 255, 255);
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_THREAT, 2200));
    expect_rgb(led_status_render(&status, 2200), 255, 0, 0);
    assert(!led_status_queue_event(&status, LED_STATUS_EVENT_THREAT, 4199));
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_THREAT, 4200));
    led_status_set_enabled(&status, false);
    assert(!led_status_queue_event(&status, LED_STATUS_EVENT_HANDSHAKE_SAVED, 4201));
    expect_rgb(led_status_render(&status, 4201), 0, 0, 0);
    led_status_set_enabled(&status, true);
    expect_rgb(led_status_render(&status, 4202), 0, 255, 0);
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_HANDSHAKE_SAVED, 4300));
    led_status_clear(&status);
    expect_rgb(led_status_render(&status, 4300), 0, 255, 0);
}

static void ota_masks_transient_flash(void)
{
    led_status_t status;
    led_status_init(&status);
    assert(led_status_set_activity(&status, LED_STATUS_OTA, true, 0));
    assert(led_status_queue_event(&status, LED_STATUS_EVENT_HANDSHAKE_SAVED, 100));
    expect_rgb(led_status_render(&status, 100), 83, 0, 0);
    assert(led_status_set_activity(&status, LED_STATUS_OTA, false, 1000));
    expect_rgb(led_status_render(&status, 1000), 0, 255, 0);
}

int main(void)
{
    idle_and_manual_off();
    base_patterns_and_priority();
    lower_priority_families();
    handshake_flash_restores_latest_activity();
    events_queue_in_order();
    rate_limit_and_manual_override();
    ota_masks_transient_flash();
    puts("LED_STATUS_CORE_PASS");
    return 0;
}
