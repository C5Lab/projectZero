#include "web_karma.h"

#include <limits.h>
#include <string.h>

static uint32_t c5_web_karma_clamp(uint32_t seconds) {
    if(seconds < C5_WEB_KARMA_MIN_DURATION_SEC) return C5_WEB_KARMA_MIN_DURATION_SEC;
    if(seconds > C5_WEB_KARMA_MAX_DURATION_SEC) return C5_WEB_KARMA_MAX_DURATION_SEC;
    return seconds;
}

void c5_web_karma_init(C5WebKarma* karma) {
    if(!karma) return;
    memset(karma, 0, sizeof(*karma));
    karma->duration_sec = C5_WEB_KARMA_DEFAULT_DURATION_SEC;
}

bool c5_web_karma_set_duration(C5WebKarma* karma, uint32_t seconds) {
    if(!karma) return false;
    uint32_t value = c5_web_karma_clamp(seconds);
    bool changed = value != karma->duration_sec;
    karma->duration_sec = value;
    return changed;
}

bool c5_web_karma_adjust_duration(C5WebKarma* karma, int32_t delta_seconds) {
    if(!karma || !delta_seconds) return false;
    int64_t value = (int64_t)karma->duration_sec + delta_seconds;
    if(value < C5_WEB_KARMA_MIN_DURATION_SEC) value = C5_WEB_KARMA_MIN_DURATION_SEC;
    if(value > C5_WEB_KARMA_MAX_DURATION_SEC) value = C5_WEB_KARMA_MAX_DURATION_SEC;
    return c5_web_karma_set_duration(karma, (uint32_t)value);
}

static bool c5_web_karma_deadline_reached(uint32_t now, uint32_t deadline) {
    return (uint32_t)(now - deadline) < (UINT32_C(1) << 31);
}

uint32_t c5_web_karma_start_collect(
    C5WebKarma* karma,
    uint32_t now_ticks,
    uint32_t tick_rate_hz,
    uint32_t refresh_delay_ticks,
    bool listing_active) {
    if(!karma || !tick_rate_hz || !refresh_delay_ticks ||
       refresh_delay_ticks >= (UINT32_C(1) << 31)) {
        return C5WebKarmaActionNone;
    }

    uint64_t duration_ticks = (uint64_t)c5_web_karma_clamp(karma->duration_sec) * tick_rate_hz;
    if(duration_ticks >= (UINT32_C(1) << 31)) return C5WebKarmaActionNone;

    uint32_t actions = C5WebKarmaActionStart;
    if(karma->collecting || listing_active) actions |= C5WebKarmaActionStop;
    karma->duration_sec = c5_web_karma_clamp(karma->duration_sec);
    karma->stop_tick = now_ticks + (uint32_t)duration_ticks;
    karma->refresh_delay_ticks = refresh_delay_ticks;
    karma->collecting = true;
    karma->pending_probe_refresh = false;
    return actions;
}

uint32_t c5_web_karma_tick(
    C5WebKarma* karma,
    uint32_t now_ticks,
    bool probe_listing_active) {
    if(!karma) return C5WebKarmaActionNone;
    if(karma->collecting && c5_web_karma_deadline_reached(now_ticks, karma->stop_tick)) {
        karma->collecting = false;
        karma->pending_probe_refresh = true;
        karma->refresh_tick = now_ticks + karma->refresh_delay_ticks;
        return C5WebKarmaActionStop;
    }
    if(karma->pending_probe_refresh &&
       c5_web_karma_deadline_reached(now_ticks, karma->refresh_tick)) {
        if(probe_listing_active) {
            karma->refresh_tick = now_ticks + karma->refresh_delay_ticks;
        } else {
            karma->pending_probe_refresh = false;
            return C5WebKarmaActionListProbes;
        }
    }
    return C5WebKarmaActionNone;
}

uint32_t c5_web_karma_cancel(C5WebKarma* karma) {
    if(!karma) return C5WebKarmaActionNone;
    uint32_t action = karma->collecting ? C5WebKarmaActionStop : C5WebKarmaActionNone;
    karma->collecting = false;
    karma->pending_probe_refresh = false;
    return action;
}
