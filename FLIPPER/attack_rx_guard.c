#include "attack_rx_guard.h"
#include "secure_clear.h"

#include <string.h>

static void c5_attack_rx_guard_reset_line(C5AttackRxGuard* guard) {
    c5_secure_clear(guard->line, sizeof(guard->line));
    guard->line_length = 0;
    guard->discard_line = false;
}

void c5_attack_rx_guard_begin(C5AttackRxGuard* guard) {
    if(!guard) return;
    guard->suppress = true;
    guard->pongs_remaining = 0;
    c5_attack_rx_guard_reset_line(guard);
}

void c5_attack_rx_guard_end(C5AttackRxGuard* guard) {
    if(!guard || !guard->suppress) return;
    guard->pongs_remaining = 2;
    c5_attack_rx_guard_reset_line(guard);
}

void c5_attack_rx_guard_feed(C5AttackRxGuard* guard, const uint8_t* bytes, size_t length) {
    if(!guard || !bytes || !guard->suppress || guard->pongs_remaining == 0) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!guard->discard_line && guard->line_length == sizeof(guard->line) &&
               memcmp(guard->line, "pong", sizeof(guard->line)) == 0) {
                guard->pongs_remaining--;
            }
            c5_attack_rx_guard_reset_line(guard);
            if(guard->pongs_remaining == 0) {
                guard->suppress = false;
                break;
            }
        } else if(!guard->discard_line) {
            if(guard->line_length < sizeof(guard->line)) {
                guard->line[guard->line_length++] = ch;
            } else {
                c5_attack_rx_guard_reset_line(guard);
                guard->discard_line = true;
            }
        }
    }
}

bool c5_attack_rx_guard_should_log(const C5AttackRxGuard* guard) {
    return !guard || !guard->suppress;
}
