#ifndef WIFI_TRUST_WIRE_H
#define WIFI_TRUST_WIRE_H

#include "wifi_trust_store.h"

#include <stddef.h>
#include <stdint.h>

/* Includes the terminating NUL. A published record is therefore at most
 * 1023 bytes including its final CRLF. */
#define WIFI_TRUST_LINE_MAX 1024U

typedef enum {
    WIFI_TRUST_MODE_IDLE = 0,
    WIFI_TRUST_MODE_CAPTURE,
    WIFI_TRUST_MODE_MONITOR,
    WIFI_TRUST_MODE_COUNT
} wifi_trust_mode_t;

/* Wire-facing booleans use uint8_t so non-canonical values can be rejected.
 * boot_known denotes a canonical loaded store meta snapshot. */
typedef struct {
    wifi_trust_mode_t mode;
    uint8_t channel; /* Zero means unknown. */
    uint8_t baseline_loaded;
    uint32_t baseline_count;
    uint8_t boot_known;
    uint8_t boot_id[8];
    uint8_t created_unix_known;
    uint64_t created_unix;
    wifi_trust_store_result_t store;
    wifi_trust_recovery_action_t recovery;
    uint32_t received;
    uint32_t filtered;
    uint32_t unrelated;
    uint32_t accepted;
    uint32_t invalid;
    uint32_t profiles;
    uint32_t conflicts;
    uint32_t events_info;
    uint32_t events_warn;
    uint32_t events_alert;
    uint32_t capacity_drops;
    uint32_t rx_drops;
    uint32_t output_failures;
    uint32_t storage_failures;
    uint8_t running;
    uint8_t stopping;
} wifi_trust_status_t;

/* Successful calls return record bytes excluding NUL and including CRLF.
 * Invalid input or insufficient capacity returns -1 and leaves every
 * destination byte unchanged. Caller-controlled free-form text is never
 * accepted by event, baseline, or status formatters. */
int wifi_trust_format_event(char *out, size_t capacity,
                            const wifi_trust_event_t *event);
int wifi_trust_format_baseline(char *out, size_t capacity,
                               const wifi_trust_profile_t *profile,
                               const wifi_trust_store_meta_t *meta);
int wifi_trust_format_status(char *out, size_t capacity,
                             const wifi_trust_status_t *status);

/* Exact outcome whitelist: ok, stopped, busy, invalid, timeout,
 * queue_overflow, restore_failed, storage_failed, storage_uncertain and
 * output_failed. Task 5 must resolve terminal causes in this precedence:
 * output_failed > restore_failed/timeout > storage_uncertain/storage_failed
 * > queue_overflow > stopped/ok. RX_DROPS changes only an otherwise
 * successful stopped/ok result to queue_overflow. */
int wifi_trust_format_terminal(char *out, size_t capacity,
                               const wifi_trust_status_t *status,
                               const char *outcome);

#endif
