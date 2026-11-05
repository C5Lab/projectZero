#ifndef WIFI_SHIELD_OUTPUT_PLATFORM_H
#define WIFI_SHIELD_OUTPUT_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct {
    void *context;
    bool (*lock)(void *context, uint32_t timeout_ms);
    void (*unlock)(void *context);
    uint64_t (*monotonic_us)(void *context);
} wifi_shield_output_platform_hooks_t;

typedef struct {
    wifi_shield_output_platform_hooks_t hooks;
    atomic_bool admission;
    atomic_bool closed;
    atomic_uint pending;
    atomic_uint failures;
} wifi_shield_output_platform_t;

bool wifi_shield_output_platform_init(
    wifi_shield_output_platform_t *platform,
    const wifi_shield_output_platform_hooks_t *hooks);
void wifi_shield_output_platform_open(wifi_shield_output_platform_t *platform);
bool wifi_shield_output_platform_admitted(
    const wifi_shield_output_platform_t *platform);
void wifi_shield_output_platform_accepted(
    wifi_shield_output_platform_t *platform);
bool wifi_shield_output_platform_rejected(
    wifi_shield_output_platform_t *platform);
bool wifi_shield_output_platform_published(
    wifi_shield_output_platform_t *platform, size_t expected, int written);
bool wifi_shield_output_platform_close(
    wifi_shield_output_platform_t *platform, uint32_t timeout_ms,
    uint32_t *remaining_ms);
bool wifi_shield_output_platform_is_closed(
    const wifi_shield_output_platform_t *platform);
unsigned wifi_shield_output_platform_pending(
    const wifi_shield_output_platform_t *platform);
uint32_t wifi_shield_output_platform_take_failures(
    wifi_shield_output_platform_t *platform);
bool wifi_shield_output_platform_should_sync_status(
    const char *line, size_t length, bool queue_ready, bool admitted);

#endif
