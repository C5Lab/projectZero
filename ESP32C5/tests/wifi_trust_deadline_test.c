#include "wifi_trust_deadline.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_delayed_callback_cannot_expire_rearm(void)
{
    wifi_trust_deadline_state_t state;
    wifi_trust_deadline_state_init(&state);
    assert(wifi_trust_deadline_state_arm(&state, 1U, 100U, 50U));

    /* Epoch 1 is physically due, but its callback has not run yet. */
    assert(wifi_trust_deadline_state_arm(&state, 2U, 151U, 50U));
    uint64_t epoch = 0U;
    assert(!wifi_trust_deadline_state_timer_fired(&state, 151U, &epoch));
    assert(epoch == 0U);
    assert(!wifi_trust_deadline_state_take_pending(&state, &epoch));

    assert(!wifi_trust_deadline_state_timer_fired(&state, 200U, &epoch));
    assert(wifi_trust_deadline_state_timer_fired(&state, 201U, &epoch));
    assert(epoch == 2U);
    assert(wifi_trust_deadline_state_take_pending(&state, &epoch));
    assert(epoch == 2U);
}

static void test_stale_cancel_cannot_disarm_rearm(void)
{
    wifi_trust_deadline_state_t state;
    wifi_trust_deadline_state_init(&state);
    assert(wifi_trust_deadline_state_arm(&state, 7U, 0U, 10U));
    assert(wifi_trust_deadline_state_arm(&state, 8U, 1U, 10U));

    unsigned physical_stop_calls = 0U;
    if (wifi_trust_deadline_state_cancel(&state, 7U))
        ++physical_stop_calls;
    assert(physical_stop_calls == 0U);

    uint64_t epoch = 0U;
    assert(wifi_trust_deadline_state_timer_fired(&state, 11U, &epoch));
    assert(epoch == 8U);
    assert(wifi_trust_deadline_state_take_pending(&state, &epoch));
    assert(epoch == 8U);
}

static void test_queue_full_latch_is_fenced_by_rearm(void)
{
    wifi_trust_deadline_state_t state;
    wifi_trust_deadline_state_init(&state);
    uint64_t epoch = 0U;
    assert(wifi_trust_deadline_state_arm(&state, 20U, 0U, 10U));
    assert(wifi_trust_deadline_state_timer_fired(&state, 10U, &epoch));
    assert(epoch == 20U); /* Nonblocking queue admission is modeled as full. */

    assert(wifi_trust_deadline_state_arm(&state, 21U, 10U, 10U));
    assert(!wifi_trust_deadline_state_take_pending(&state, &epoch));
    assert(!wifi_trust_deadline_state_timer_fired(&state, 11U, &epoch));

    assert(wifi_trust_deadline_state_timer_fired(&state, 20U, &epoch));
    assert(epoch == 21U); /* Queue is full again; the latch must retain it. */
    assert(wifi_trust_deadline_state_take_pending(&state, &epoch));
    assert(epoch == 21U);
    assert(!wifi_trust_deadline_state_take_pending(&state, &epoch));
}

static void test_surviving_epoch_completes_once(void)
{
    wifi_trust_deadline_state_t state;
    wifi_trust_deadline_state_init(&state);
    assert(wifi_trust_deadline_state_arm(&state, 42U, 1000U, 5U));
    uint64_t notified = 0U;
    assert(wifi_trust_deadline_state_timer_fired(&state, 1005U, &notified));
    assert(notified == 42U);
    assert(!wifi_trust_deadline_state_timer_fired(&state, 1006U, &notified));

    unsigned terminals = 0U;
    uint64_t delivered = 0U;
    for (unsigned poll = 0U; poll < 8U; ++poll) {
        if (wifi_trust_deadline_state_take_pending(&state, &delivered)) {
            assert(delivered == 42U);
            ++terminals;
        }
    }
    assert(terminals == 1U);
    assert(!wifi_trust_deadline_state_cancel(&state, 42U));
}

int main(void)
{
    test_delayed_callback_cannot_expire_rearm();
    test_stale_cancel_cannot_disarm_rearm();
    test_queue_full_latch_is_fenced_by_rearm();
    test_surviving_epoch_completes_once();
    puts("PASS: Wi-Fi Trust deadline ownership and delivery fences");
    return 0;
}
