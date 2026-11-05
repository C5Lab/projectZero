#include "wifi_trust_deadline.h"

#include <limits.h>
#include <stddef.h>

static void clear_state(wifi_trust_deadline_state_t *state)
{
    state->owner_epoch = 0U;
    state->due_us = 0U;
    state->pending_epoch = 0U;
}

void wifi_trust_deadline_state_init(wifi_trust_deadline_state_t *state)
{
    if (state != NULL) clear_state(state);
}

bool wifi_trust_deadline_state_arm(wifi_trust_deadline_state_t *state,
                                   uint64_t epoch, uint64_t now_us,
                                   uint64_t delay_us)
{
    if (state == NULL || epoch == 0U || delay_us == 0U ||
        now_us > UINT64_MAX - delay_us)
        return false;
    state->owner_epoch = epoch;
    state->due_us = now_us + delay_us;
    state->pending_epoch = 0U;
    return true;
}

bool wifi_trust_deadline_state_cancel(wifi_trust_deadline_state_t *state,
                                      uint64_t epoch)
{
    if (state == NULL || epoch == 0U || state->owner_epoch != epoch)
        return false;
    clear_state(state);
    return true;
}

bool wifi_trust_deadline_state_timer_fired(
    wifi_trust_deadline_state_t *state, uint64_t now_us,
    uint64_t *notify_epoch)
{
    if (notify_epoch != NULL) *notify_epoch = 0U;
    if (state == NULL || notify_epoch == NULL || state->owner_epoch == 0U ||
        state->pending_epoch != 0U || now_us < state->due_us)
        return false;
    state->pending_epoch = state->owner_epoch;
    *notify_epoch = state->pending_epoch;
    return true;
}

bool wifi_trust_deadline_state_take_pending(
    wifi_trust_deadline_state_t *state, uint64_t *epoch)
{
    if (epoch != NULL) *epoch = 0U;
    if (state == NULL || epoch == NULL || state->pending_epoch == 0U ||
        state->pending_epoch != state->owner_epoch)
        return false;
    *epoch = state->pending_epoch;
    clear_state(state);
    return true;
}
