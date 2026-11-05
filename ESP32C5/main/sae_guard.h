#ifndef SAE_GUARD_H
#define SAE_GUARD_H

#include "wifi_security_runtime.h"
#include "wifi_shield_channel.h"
#include "sae_guard_wire.h"

#define SAE_GUARD_SCAN_TIMEOUT_MS 250U
#define SAE_GUARD_OUTPUT_TIMEOUT_MS 250U

typedef struct {
    void *context;
    void (*enter)(void *context);
    void (*leave)(void *context);
    bool (*scan_snapshot)(void *context, wifi_shield_target_t **targets,
                          size_t *count);
    void (*scan_release)(void *context, wifi_shield_target_t *targets,
                         size_t count);
    uint64_t (*monotonic_us)(void *context);
    void (*status_snapshot)(void *context,
                            wifi_security_runtime_status_t *status);
    wifi_security_session_result_t (*start)(
        void *context, const wifi_shield_target_t *targets, size_t count,
        const wifi_security_session_config_t *config);
    bool (*stop)(void *context, uint32_t timeout_ms);
} sae_guard_runtime_hooks_t;

typedef struct {
    void *context;
    bool (*enter)(void *context, uint32_t timeout_ms);
    void (*leave)(void *context);
    bool (*write)(void *context, const char *line, size_t length);
    bool (*write_terminal)(void *context, const sae_guard_status_t *status,
                           const char *outcome);
    void (*complete)(void *context, bool accepted);
    bool (*idle)(void *context);
} sae_guard_output_hooks_t;

bool sae_guard_init(const sae_guard_runtime_hooks_t *runtime_hooks,
                    const sae_guard_output_hooks_t *output_hooks);
int sae_guard_command(int argc, char **argv);
bool sae_guard_busy(void);
bool sae_guard_stop(uint32_t timeout_ms);
void sae_guard_report_output_failure(void);
int sae_guard_format_terminal_for_output(char *out, size_t capacity,
                                         const sae_guard_status_t *status,
                                         const char *outcome);

#endif
