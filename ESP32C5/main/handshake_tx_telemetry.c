#include "handshake_tx_telemetry.h"

void handshake_tx_telemetry_reset(handshake_tx_telemetry_t *telemetry)
{
    atomic_store_explicit(&telemetry->tx_done_success, 0,
                          memory_order_release);
    atomic_store_explicit(&telemetry->tx_done_fail, 0,
                          memory_order_release);
}

void handshake_tx_telemetry_record(handshake_tx_telemetry_t *telemetry,
                                   bool success)
{
    atomic_uint_least32_t *counter = success
        ? &telemetry->tx_done_success
        : &telemetry->tx_done_fail;
    atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}

handshake_tx_telemetry_snapshot_t handshake_tx_telemetry_snapshot(
    const handshake_tx_telemetry_t *telemetry)
{
    handshake_tx_telemetry_snapshot_t snapshot = {
        .tx_done_success = (uint32_t)atomic_load_explicit(
            &telemetry->tx_done_success, memory_order_acquire),
        .tx_done_fail = (uint32_t)atomic_load_explicit(
            &telemetry->tx_done_fail, memory_order_acquire),
    };
    return snapshot;
}
