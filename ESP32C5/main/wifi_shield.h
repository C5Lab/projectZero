#ifndef WIFI_SHIELD_H
#define WIFI_SHIELD_H

#include "wifi_security_runtime.h"
#include "wifi_shield_journal.h"
#include "wifi_shield_summary.h"
#include "wifi_shield_channel.h"
#include "wifi_shield_core.h"
#include "wifi_trust_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_SHIELD_OUTPUT_TIMEOUT_MS 250U
#define WIFI_SHIELD_CHANNEL_DWELL_US UINT64_C(250000)
#define WIFI_SHIELD_PRESENTATION_SOURCE_COUNT 4U
#define WIFI_SHIELD_OLED_LINE_COUNT 4U
#define WIFI_SHIELD_OLED_LINE_BYTES 22U
#define WIFI_SHIELD_HELP_TEXT \
    "Wi-Fi Shield: start [--only indexes...] [--protect-all | --defence decoy-4way [--pmkid-decoy [--multi-vector]]] | status | report | log status | stop"

typedef struct wifi_shield_state wifi_shield_state_t;

typedef enum {
    WIFI_SHIELD_PRESENTATION_INFO = 0,
    WIFI_SHIELD_PRESENTATION_WARN,
    WIFI_SHIELD_PRESENTATION_ALERT,
    WIFI_SHIELD_PRESENTATION_DECOY_TX,
    WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT
} wifi_shield_presentation_indicator_t;

typedef struct {
    uint32_t session_id;
    uint32_t revision;
    uint32_t indicator_counts[WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT];
    uint32_t source_events[WIFI_SHIELD_PRESENTATION_SOURCE_COUNT];
    wifi_shield_event_type_t latest_alert_type;
    uint8_t target_count;
    uint8_t current_channel;
    bool armed;
    bool running;
    bool stopping;
    bool latest_alert_valid;
} wifi_shield_presentation_snapshot_t;

typedef struct {
    char line[WIFI_SHIELD_OLED_LINE_COUNT][WIFI_SHIELD_OLED_LINE_BYTES];
} wifi_shield_oled_lines_t;

typedef struct {
    void *context;
    bool (*storage_acquire)(void *context, size_t state_bytes,
                            void **state_storage);
    void (*storage_release)(void *context, void **state_storage,
                            size_t state_bytes);
    bool (*scan_all)(void *context,
        wifi_shield_target_t *targets, size_t capacity, size_t *count);
    bool (*scan_snapshot)(void *context,
        const size_t *indices, size_t index_count,
        wifi_shield_target_t *targets, size_t capacity, size_t *count);
    bool (*trust_snapshot)(void *context,
        wifi_trust_profile_t *profiles, size_t capacity, size_t *count);
    /* Bare Start owns one continuous SHIELD/PREPARING reservation while its
     * bounded scan runs. start_radio adopts it without changing generation. */
    bool (*reserve_scan)(void *context);
    bool (*abort_prepare)(void *context, uint32_t timeout_ms);
    wifi_security_session_result_t (*start_radio)(
        void *context, const wifi_security_session_config_t *config);
    /* Portable pre-start handshake only: validate and stage the desired
     * initial channel without changing radio state. start_radio consumes the
     * staged value and performs the hardware tune after its baseline/channel/
     * filter snapshot, before promiscuous RX and lease RUNNING. */
    bool (*tune)(void *context, uint8_t channel);
    /* Running-session retune, called only by the Shield worker scheduler and
     * never while the Shield state mutex is held. */
    bool (*retune)(void *context, uint8_t channel);
    /* Serializes running radio operations with lock/release and Stop. This is
     * a dedicated internal-SRAM mutex, distinct from the state mutex. */
    bool (*radio_enter)(void *context, uint32_t timeout_ms);
    void (*radio_leave)(void *context);
    /* Dedicated bounded internal-SRAM state mutex. */
    void (*state_enter)(void *context);
    void (*state_leave)(void *context);
    void (*runtime_status)(void *context,
                           wifi_security_runtime_status_t *status);
    /* Phase 1: close callback/active-TX admission, unregister the callback,
     * stop TX/security workers and join every producer. It must not restore
     * radio state, wipe feature context or release the lease. */
    bool (*quiesce_radio)(void *context, uint32_t timeout_ms);
    /* Phase 3: after the output publisher has drained, restore filter/channel/
     * mode, invoke the feature wipe callback and finish lease cleanup. */
    bool (*finish_radio_cleanup)(void *context, uint32_t timeout_ms);
    uint64_t (*monotonic_us)(void *context);
    bool (*defence_random)(void *context, uint8_t *out, size_t length);
    int (*defence_tx)(void *context, const uint8_t *frame,
                      size_t length, bool en_sys_seq);
    /* Raw shared-runtime lifecycle used by passive legacy profiles. The
     * profile owns its parser, detector, status and output; Shield owns only
     * channel scheduling and the radio fence around running retunes. */
    wifi_security_session_result_t (*profile_start_radio)(
        void *context, const wifi_security_session_config_t *config);
    bool (*profile_stop_radio)(void *context, uint32_t timeout_ms);
    bool (*profile_retune)(void *context, wifi_security_module_t module,
                           uint32_t generation, uint8_t channel);
    bool (*profile_gate_enter)(void *context, uint32_t timeout_ms);
    void (*profile_gate_leave)(void *context);
    bool (*profile_reserve_scan)(void *context,
                                 wifi_security_module_t module);
    bool (*profile_abort_prepare)(void *context,
                                  wifi_security_module_t module,
                                  uint32_t timeout_ms);
    /* Optional fail-open V2 journal. Supply the complete set or none. Hooks
     * never receive frame pointers and submission must copy without waiting. */
    uint32_t (*journal_boot_id)(void *context);
    bool (*journal_start)(void *context, uint32_t boot_id,
                           uint32_t session_id, uint64_t quota_bytes,
                           const wifi_shield_summary_metadata_t *metadata);
    bool (*journal_submit)(void *context,
                           const wifi_shield_journal_record_t *record);
    wifi_shield_journal_status_t (*journal_status)(void *context);
    void (*journal_acknowledge_degraded)(void *context);
    /* Waits only for records already accepted by journal_submit. A successful
     * return means the dedicated writer completed their store checkpoints. */
    bool (*journal_drain)(void *context, uint32_t timeout_ms);
    bool (*journal_finish)(void *context, bool clean, uint32_t timeout_ms);
} wifi_shield_runtime_hooks_t;

typedef struct {
    unsigned packed_lifecycle;
    uint32_t runtime_generation;
    uint8_t channel;
    bool held;
} wifi_shield_deauth_radio_token_t;

typedef struct {
    unsigned packed_lifecycle;
    bool held;
} wifi_shield_deauth_scan_token_t;

typedef struct {
    void *context;
    bool (*enter)(void *context, uint32_t timeout_ms);
    void (*leave)(void *context);
    bool (*write)(void *context, const char *line, size_t length);
    bool (*write_terminal)(void *context,
                           const wifi_shield_status_t *status,
                           const char *outcome);
    void (*complete)(void *context, bool accepted);
    bool (*idle)(void *context);
    /* Phase 2: drain/account queued output and stop/join its publisher. */
    bool (*drain)(void *context, uint32_t timeout_ms);
    /* Called once after a successful drain. Returns and clears asynchronous
     * publisher failures (for example partial UART writes). */
    uint32_t (*take_failures)(void *context);
} wifi_shield_output_hooks_t;

size_t wifi_shield_state_size(void);
/* Caller-owned retained V2 summary storage. It must be exactly this size,
 * naturally aligned, zeroable and live for every command after init. The
 * production owner places it in permanent PSRAM, disjoint from each session
 * bundle. No internal-RAM or heap fallback is permitted. */
size_t wifi_shield_retained_size(void);
bool wifi_shield_init(const wifi_shield_runtime_hooks_t *runtime,
                      const wifi_shield_output_hooks_t *output,
                      void *retained_storage, size_t retained_bytes);
int wifi_shield_command(int argc, char **argv);
bool wifi_shield_busy(void);
bool wifi_shield_stop(uint32_t timeout_ms);
wifi_security_session_result_t wifi_shield_start_wps_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config);
bool wifi_shield_stop_wps_profile(uint32_t timeout_ms);
wifi_security_session_result_t wifi_shield_start_sae_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config);
bool wifi_shield_stop_sae_profile(uint32_t timeout_ms);
wifi_security_session_result_t wifi_shield_start_trust_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config);
bool wifi_shield_stop_trust_profile(uint32_t timeout_ms);
wifi_security_session_result_t wifi_shield_start_deauth_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const uint8_t *channels, size_t channel_count,
    const wifi_security_session_config_t *config,
    wifi_shield_deauth_scan_token_t *scan_token);
bool wifi_shield_stop_deauth_profile(uint32_t timeout_ms);
bool wifi_shield_deauth_profile_pending(void);
bool wifi_shield_reserve_deauth_scan(
    wifi_shield_deauth_scan_token_t *token);
bool wifi_shield_abort_deauth_scan(
    wifi_shield_deauth_scan_token_t *token, uint32_t timeout_ms);
bool wifi_shield_deauth_profile_retune(uint8_t channel);
bool wifi_shield_deauth_profile_generation(uint32_t *generation);
bool wifi_shield_deauth_profile_radio_enter(
    uint8_t channel, wifi_shield_deauth_radio_token_t *token);
bool wifi_shield_deauth_profile_radio_leave(
    wifi_shield_deauth_radio_token_t *token);

/* Presentation is a pull-only scalar view. It retains no frame bytes,
 * identities, credentials or borrowed session pointers. UART remains the
 * authoritative evidence stream. */
bool wifi_shield_presentation_indicator(
    wifi_shield_event_type_t event,
    wifi_shield_presentation_indicator_t *indicator);
void wifi_shield_presentation_get(
    wifi_shield_presentation_snapshot_t *snapshot);
bool wifi_shield_presentation_format_oled(
    const wifi_shield_presentation_snapshot_t *snapshot,
    wifi_shield_oled_lines_t *lines);

/* Platform worker adapters. Views are borrowed only for each call. */
bool wifi_shield_consume_compact(void *token,
                                 const wifi_shield_compact_event_t *event);
void wifi_shield_worker_poll(void);
bool wifi_shield_channel_lock_running(void *token, const uint8_t bssid[6],
                                      uint8_t channel);
bool wifi_shield_channel_release_running(void *token);

#endif
