#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "handshake_tx_telemetry.h"

int main(void)
{
    handshake_tx_telemetry_t telemetry = HANDSHAKE_TX_TELEMETRY_INITIALIZER;

    handshake_tx_telemetry_record(&telemetry, true);
    handshake_tx_telemetry_record(&telemetry, true);
    handshake_tx_telemetry_record(&telemetry, false);

    handshake_tx_telemetry_snapshot_t snapshot =
        handshake_tx_telemetry_snapshot(&telemetry);
    assert(snapshot.tx_done_success == 2U);
    assert(snapshot.tx_done_fail == 1U);

    handshake_tx_telemetry_reset(&telemetry);
    snapshot = handshake_tx_telemetry_snapshot(&telemetry);
    assert(snapshot.tx_done_success == 0U);
    assert(snapshot.tx_done_fail == 0U);

    return 0;
}
