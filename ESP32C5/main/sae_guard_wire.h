#ifndef SAE_GUARD_WIRE_H
#define SAE_GUARD_WIRE_H

#include "sae_guard_core.h"

#define SAE_GUARD_LINE_MAX 512U

typedef enum {
    SAE_GUARD_SEVERITY_INFO = 0,
    SAE_GUARD_SEVERITY_WARN,
    SAE_GUARD_SEVERITY_ALERT
} sae_guard_severity_t;

/* Returns published bytes excluding NUL and including the final CRLF. A NONE
 * event with an empty mask is suppressed and returns 0 without touching out.
 * Every non-NONE bit in reason_mask is emitted in enum order; reason must be
 * the first set reason for compatibility with the core's primary field.
 * Invalid arguments/masks or insufficient capacity return -1 without touching
 * any destination byte. Capacity includes the NUL terminator.
 *
 * Only bounded metadata is published. No SAE scalar, element, token, password
 * identifier, payload byte, compromise claim, or attribution is accepted from
 * a caller or available to this formatter.
 */
int sae_guard_format_event(char *out, size_t capacity,
                           const sae_guard_event_t *event);

/* STATUS and TERMINAL carry identical ordered fields. REASONS is exactly
 * SAE_GUARD_EVENT_REASON_COUNT decimal counters in enum order, including NONE.
 * ACTIVE is the saturated sum of live pair and malformed-BSSID table rows.
 * RX_DROPS is adapter-owned pool-plus-queue loss; CAPACITY_DROPS is the core's
 * aggregate bounded-table loss. PAIR_DROPS and MALFORMED_DROPS preserve the
 * two independent table losses without deriving or reconciling the aggregate;
 * saturation may make their arithmetic differ. OUTPUT_FAILURES is adapter-
 * owned publication loss. Boolean lifecycle fields are rendered as 0 or 1.
 */
int sae_guard_format_status(char *out, size_t capacity,
                            const sae_guard_status_t *status);

/* Exact public outcome whitelist: ok, stopped, busy, invalid, timeout,
 * queue_overflow, restore_failed, output_failed. Arbitrary caller strings are
 * rejected rather than escaped or copied into a record.
 */
int sae_guard_format_terminal(char *out, size_t capacity,
                              const sae_guard_status_t *status,
                              const char *outcome);

#endif
