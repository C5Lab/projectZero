#include "../attack_rx_guard.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void feed(C5AttackRxGuard* guard, const char* text) {
    c5_attack_rx_guard_feed(guard, (const uint8_t*)text, strlen(text));
}

int main(void) {
    C5AttackRxGuard guard = {0};
    assert(c5_attack_rx_guard_should_log(&guard));
    c5_attack_rx_guard_begin(&guard);
    assert(!c5_attack_rx_guard_should_log(&guard));
    feed(&guard, "Password: secret\n");
    assert(!c5_attack_rx_guard_should_log(&guard));

    c5_attack_rx_guard_end(&guard);
    feed(&guard, "Password: pong\nshow_pass done\n");
    assert(guard.pongs_remaining == 2);
    feed(&guard, "pong\r\n"); /* At most one old menu ping may be outstanding. */
    assert(guard.pongs_remaining == 1);
    assert(!c5_attack_rx_guard_should_log(&guard));
    feed(&guard, "late secret\npong");
    assert(guard.pongs_remaining == 1);
    feed(&guard, "\r\n");
    assert(c5_attack_rx_guard_should_log(&guard));

    c5_attack_rx_guard_begin(&guard);
    c5_attack_rx_guard_end(&guard);
    feed(&guard, "pongs\npong suffix\npong\n");
    assert(guard.pongs_remaining == 1);
    c5_attack_rx_guard_begin(&guard); /* New lookup cancels an older barrier. */
    assert(guard.pongs_remaining == 0);
    assert(!c5_attack_rx_guard_should_log(&guard));
    puts("Attack RX guard tests passed");
    return 0;
}
