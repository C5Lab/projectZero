#ifndef LAB_C5_ATTACK_RX_GUARD_H
#define LAB_C5_ATTACK_RX_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool suppress;
    bool discard_line;
    uint8_t pongs_remaining;
    uint8_t line_length;
    char line[4];
} C5AttackRxGuard;

void c5_attack_rx_guard_begin(C5AttackRxGuard* guard);
void c5_attack_rx_guard_end(C5AttackRxGuard* guard);
void c5_attack_rx_guard_feed(C5AttackRxGuard* guard, const uint8_t* bytes, size_t length);
bool c5_attack_rx_guard_should_log(const C5AttackRxGuard* guard);

#endif
