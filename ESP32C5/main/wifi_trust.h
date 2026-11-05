#ifndef WIFI_TRUST_H
#define WIFI_TRUST_H

#include "wifi_security_runtime.h"
#include "wifi_shield.h"
#include "wifi_trust_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_TRUST_SCAN_TIMEOUT_MS 250U
#define WIFI_TRUST_OUTPUT_TIMEOUT_MS 250U
#define WIFI_TRUST_ARENA_MAX_BYTES (384U * 1024U)

/* The platform guarantees that this callback runs in its dedicated control
 * task. A timer/RX/worker callback must only enqueue the epoch. */
typedef void (*wifi_trust_deadline_fn)(void *context, uint64_t epoch);

typedef struct {
    void *context;
    void (*enter)(void *context);
    void (*leave)(void *context);
    bool (*current_channel)(void *context, uint8_t *channel);
    bool (*scan_snapshot)(void *context, wifi_shield_target_t *entries,
                          size_t capacity, size_t *count);
    uint64_t (*monotonic_us)(void *context);
    void (*status_snapshot)(void *context,
                            wifi_security_runtime_status_t *status);
    wifi_security_session_result_t (*start)(
        void *context, const wifi_shield_target_t *targets,
        size_t target_count, const wifi_security_session_config_t *config);
    bool (*stop)(void *context, uint32_t timeout_ms);
    bool (*deadline_arm)(void *context, uint64_t epoch, uint32_t seconds,
                         wifi_trust_deadline_fn callback,
                         void *callback_context);
    void (*deadline_cancel)(void *context, uint64_t epoch);
} wifi_trust_runtime_hooks_t;

typedef struct {
    void *context;
    bool (*arena_acquire)(void *context, size_t size, void **arena);
    void (*arena_release)(void *context, void *arena, size_t size);
    bool (*meta_snapshot)(void *context, wifi_trust_store_meta_t *meta);
    wifi_trust_store_ops_t store;
} wifi_trust_storage_hooks_t;

typedef struct {
    void *context;
    bool (*enter)(void *context, uint32_t timeout_ms);
    void (*leave)(void *context);
    bool (*write)(void *context, const char *line, size_t length);
    bool (*write_terminal)(void *context, const wifi_trust_status_t *status,
                           const char *outcome);
    void (*complete)(void *context, bool accepted);
    bool (*idle)(void *context);
} wifi_trust_output_hooks_t;

bool wifi_trust_init(const wifi_trust_runtime_hooks_t *runtime_hooks,
                     const wifi_trust_storage_hooks_t *storage_hooks,
                     const wifi_trust_output_hooks_t *output_hooks);
int wifi_trust_command(int argc, char **argv);
bool wifi_trust_busy(void);
bool wifi_trust_stop(uint32_t timeout_ms);
void wifi_trust_report_output_failure(void);
int wifi_trust_format_terminal_for_output(char *out, size_t capacity,
                                          const wifi_trust_status_t *status,
                                          const char *outcome);

#endif
