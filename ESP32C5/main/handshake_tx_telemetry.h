#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct {
    atomic_uint_least32_t tx_done_success;
    atomic_uint_least32_t tx_done_fail;
} handshake_tx_telemetry_t;

#define HANDSHAKE_TX_TELEMETRY_INITIALIZER { \
    ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0) \
}

typedef struct {
    uint32_t tx_done_success;
    uint32_t tx_done_fail;
} handshake_tx_telemetry_snapshot_t;

void handshake_tx_telemetry_reset(handshake_tx_telemetry_t *telemetry);
void handshake_tx_telemetry_record(handshake_tx_telemetry_t *telemetry,
                                   bool success);
handshake_tx_telemetry_snapshot_t handshake_tx_telemetry_snapshot(
    const handshake_tx_telemetry_t *telemetry);
