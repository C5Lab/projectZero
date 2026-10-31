#include "../modules/web/web_karma.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_default_collect_stop_and_refresh(void) {
    C5WebKarma karma;
    c5_web_karma_init(&karma);
    assert(karma.duration_sec == 15);
    assert(!karma.collecting && !karma.pending_probe_refresh);

    assert(c5_web_karma_start_collect(&karma, 1000, 1000, 500, false) == C5WebKarmaActionStart);
    assert(karma.collecting && karma.stop_tick == 16000);
    assert(c5_web_karma_tick(&karma, 15999, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 16000, false) == C5WebKarmaActionStop);
    assert(!karma.collecting && karma.pending_probe_refresh && karma.refresh_tick == 16500);
    assert(c5_web_karma_tick(&karma, 16499, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 16500, false) == C5WebKarmaActionListProbes);
    assert(!karma.pending_probe_refresh);
    assert(c5_web_karma_tick(&karma, 16501, false) == C5WebKarmaActionNone);
}

static void test_config_roundtrip_and_adjustment(void) {
    C5WebKarma karma;
    c5_web_karma_init(&karma);
    assert(c5_web_karma_set_duration(&karma, 17));
    assert(karma.duration_sec == 17);
    assert(c5_web_karma_adjust_duration(&karma, 5) && karma.duration_sec == 22);
    assert(c5_web_karma_adjust_duration(&karma, -1) && karma.duration_sec == 21);
    assert(c5_web_karma_set_duration(&karma, 0) && karma.duration_sec == 5);
    assert(!c5_web_karma_adjust_duration(&karma, -5) && karma.duration_sec == 5);
    assert(c5_web_karma_set_duration(&karma, 200) && karma.duration_sec == 180);
    assert(!c5_web_karma_adjust_duration(&karma, 5) && karma.duration_sec == 180);
    assert(!c5_web_karma_set_duration(&karma, 180));
}

static void test_restart_cancel_and_delayed_list(void) {
    C5WebKarma karma;
    c5_web_karma_init(&karma);
    assert(c5_web_karma_start_collect(&karma, 0, 1000, 500, true) ==
           (C5WebKarmaActionStop | C5WebKarmaActionStart));
    assert(c5_web_karma_start_collect(&karma, 100, 1000, 500, false) ==
           (C5WebKarmaActionStop | C5WebKarmaActionStart));
    assert(c5_web_karma_tick(&karma, 15099, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 15100, false) == C5WebKarmaActionStop);
    assert(c5_web_karma_tick(&karma, 15600, true) == C5WebKarmaActionNone);
    assert(karma.pending_probe_refresh && karma.refresh_tick == 16100);
    assert(c5_web_karma_tick(&karma, 16099, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 16100, false) == C5WebKarmaActionListProbes);

    assert(c5_web_karma_start_collect(&karma, 20000, 1000, 500, false) == C5WebKarmaActionStart);
    assert(c5_web_karma_cancel(&karma) == C5WebKarmaActionStop);
    assert(!karma.collecting && !karma.pending_probe_refresh);
    assert(c5_web_karma_cancel(&karma) == C5WebKarmaActionNone);
}

static void test_tick_wrap_and_invalid_clock(void) {
    C5WebKarma karma;
    c5_web_karma_init(&karma);
    c5_web_karma_set_duration(&karma, 5);
    assert(c5_web_karma_start_collect(&karma, 1, 0, 500, false) == C5WebKarmaActionNone);
    assert(!karma.collecting);
    assert(c5_web_karma_start_collect(&karma, 1, 100, 0, false) == C5WebKarmaActionNone);
    assert(!karma.collecting);

    uint32_t start = UINT32_MAX - 100;
    assert(c5_web_karma_start_collect(&karma, start, 100, 50, false) == C5WebKarmaActionStart);
    assert(c5_web_karma_tick(&karma, 398, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 399, false) == C5WebKarmaActionStop);
    assert(c5_web_karma_tick(&karma, 448, false) == C5WebKarmaActionNone);
    assert(c5_web_karma_tick(&karma, 449, false) == C5WebKarmaActionListProbes);
}

int main(void) {
    test_default_collect_stop_and_refresh();
    test_config_roundtrip_and_adjustment();
    test_restart_cancel_and_delayed_list();
    test_tick_wrap_and_invalid_clock();
    puts("Web Karma tests passed");
    return 0;
}
