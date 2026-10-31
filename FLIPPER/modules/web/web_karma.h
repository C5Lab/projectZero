#ifndef LAB_C5_WEB_KARMA_H
#define LAB_C5_WEB_KARMA_H

#include <stdbool.h>
#include <stdint.h>

#define C5_WEB_KARMA_DEFAULT_DURATION_SEC 15u
#define C5_WEB_KARMA_MIN_DURATION_SEC 5u
#define C5_WEB_KARMA_MAX_DURATION_SEC 180u
#define C5_WEB_KARMA_DURATION_STEP_SEC 5

typedef enum {
    C5WebKarmaActionNone = 0,
    C5WebKarmaActionStop = 1u << 0,
    C5WebKarmaActionStart = 1u << 1,
    C5WebKarmaActionListProbes = 1u << 2,
} C5WebKarmaAction;

typedef struct {
    uint32_t duration_sec;
    uint32_t stop_tick;
    uint32_t refresh_tick;
    uint32_t refresh_delay_ticks;
    bool collecting;
    bool pending_probe_refresh;
} C5WebKarma;

/* Initial startup default is 15 s. Apply a saved setting separately so a
 * present value of zero clamps to 5 s, as in the prior host implementation.
 */
void c5_web_karma_init(C5WebKarma* karma);
bool c5_web_karma_set_duration(C5WebKarma* karma, uint32_t seconds);
bool c5_web_karma_adjust_duration(C5WebKarma* karma, int32_t delta_seconds);

/* tick_rate_hz and refresh_delay_ticks are supplied by the host; pass
 * furi_ms_to_ticks(500) for the latter. Durations must fit half the uint32_t
 * tick range for wrap-safe deadline comparison. On Stop|Start, send Stop first.
 */
uint32_t c5_web_karma_start_collect(
    C5WebKarma* karma,
    uint32_t now_ticks,
    uint32_t tick_rate_hz,
    uint32_t refresh_delay_ticks,
    bool listing_active);
uint32_t c5_web_karma_tick(
    C5WebKarma* karma,
    uint32_t now_ticks,
    bool probe_listing_active);
uint32_t c5_web_karma_cancel(C5WebKarma* karma);

#endif
