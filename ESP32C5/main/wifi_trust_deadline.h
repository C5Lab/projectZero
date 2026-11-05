#ifndef WIFI_TRUST_DEADLINE_H
#define WIFI_TRUST_DEADLINE_H

#include <stdbool.h>
#include <stdint.h>

/* Caller-owned state. Every access must use the adapter's deadline-state lock. */
typedef struct {
    uint64_t owner_epoch;
    uint64_t due_us;
    uint64_t pending_epoch;
} wifi_trust_deadline_state_t;

void wifi_trust_deadline_state_init(wifi_trust_deadline_state_t *state);

bool wifi_trust_deadline_state_arm(wifi_trust_deadline_state_t *state,
                                   uint64_t epoch, uint64_t now_us,
                                   uint64_t delay_us);

/* Returns true only when this epoch owns the physical timer operation. */
bool wifi_trust_deadline_state_cancel(wifi_trust_deadline_state_t *state,
                                      uint64_t epoch);

/* Latches one due owner. Early/stale callbacks are notification-only no-ops. */
bool wifi_trust_deadline_state_timer_fired(
    wifi_trust_deadline_state_t *state, uint64_t now_us,
    uint64_t *notify_epoch);

/* Control-task polling consumes a latched epoch exactly once. */
bool wifi_trust_deadline_state_take_pending(
    wifi_trust_deadline_state_t *state, uint64_t *epoch);

#endif
