#ifndef WPS_GUARD_WIRE_H
#define WPS_GUARD_WIRE_H

#include "wps_guard_core.h"

#define WPS_GUARD_LINE_MAX 512U

typedef enum {
    WPS_GUARD_SEVERITY_INFO = 0,
    WPS_GUARD_SEVERITY_WARN,
    WPS_GUARD_SEVERITY_ALERT
} wps_guard_severity_t;

/* Returns published bytes excluding NUL, including the final CRLF. Suppressed
 * NONE/RETRANSMISSION/COMPLETE events return 0 without touching out. Invalid
 * arguments, unknown enum/outcome tokens, or insufficient capacity return -1
 * without touching any destination byte. Capacity must also include the NUL.
 * No caller string or fragment payload/hash/EAP identifier is published.
 * Call only for recognizable WSC metadata, never unrelated/non-WSC traffic.
 * Reasons describe observed evidence/uncertainty, never router exploitability.
 */
int wps_guard_format_event(char *out, size_t capacity,
                           const wps_guard_event_t *event);

/* STATUS and TERMINAL carry identical ordered counter/state fields. REASONS
 * is exactly WPS_GUARD_REASON_COUNT decimal counters in the core enum's order,
 * including NONE, RETRANSMISSION and COMPLETE; no reason names are repeated.
 * ACTIVE is the core's bounded live-session gauge. RX_DROPS is the saturated
 * shared-runtime pool-plus-queue loss aggregate and is distinct from the core's
 * per-flow CAPACITY_DROPS. Adapter fields are supplied by its serialized
 * snapshot, with uint32_t saturation and boolean state.
 */
int wps_guard_format_status(char *out, size_t capacity,
                            const wps_guard_status_t *status);

/* Exact public outcome whitelist: ok, stopped, busy, invalid, timeout,
 * queue_overflow, restore_failed, output_failed. Internal lifecycle failures
 * must be mapped by the adapter; arbitrary labels are rejected, not escaped.
 */
int wps_guard_format_terminal(char *out, size_t capacity,
                              const wps_guard_status_t *status,
                              const char *outcome);

#endif
