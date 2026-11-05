#ifndef WPS_GUARD_H
#define WPS_GUARD_H

#include "wifi_security_runtime.h"
#include "wifi_shield_channel.h"
#include "wps_guard_wire.h"

#define WPS_GUARD_SCAN_TIMEOUT_MS 250U
#define WPS_GUARD_OUTPUT_TIMEOUT_MS 250U

/* The snapshot hook returns one owned, immutable full-scan BSSID array. The
 * release hook receives the original allocation count after the adapter has
 * zeroized every byte. All hooks and their contexts have static lifetime. */
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
} wps_guard_runtime_hooks_t;

typedef struct {
    void *context;
    /* Bounded serialization for complete records. Static lifetime; never
     * shares the feature state critical section and is never entered by RX.
     * false means the gate was not acquired and leave must not be called. */
    bool (*enter)(void *context, uint32_t timeout_ms);
    void (*leave)(void *context);
    bool (*write)(void *context, const char *line, size_t length);
    /* Lifecycle terminals are formatted at sink time, after earlier records. */
    bool (*write_terminal)(void *context, const wps_guard_status_t *status,
                           const char *outcome);
    /* Called under output serialization after write failure has been recorded.
     * An async adapter may retain an admission token until this boundary. */
    void (*complete)(void *context, bool accepted);
    /* Nonblocking: false prevents a new session crossing old publications. */
    bool (*idle)(void *context);
} wps_guard_output_hooks_t;

bool wps_guard_init(const wps_guard_runtime_hooks_t *runtime_hooks,
                    const wps_guard_output_hooks_t *output_hooks);
int wps_guard_command(int argc, char **argv);
bool wps_guard_busy(void);
bool wps_guard_stop(uint32_t timeout_ms);
/* Dedicated output publishers report an asynchronous sink failure here. */
void wps_guard_report_output_failure(void);
int wps_guard_format_terminal_for_output(char *out, size_t capacity,
                                         const wps_guard_status_t *status,
                                         const char *outcome);

#endif
