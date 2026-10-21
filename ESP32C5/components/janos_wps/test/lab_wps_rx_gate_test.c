#include <assert.h>
#include <stdio.h>

#include "lab_wps_rx_gate.h"

static void test_retains_one_pending_m3_and_coalesces_retransmissions(void)
{
    lab_wps_rx_gate_t gate;
    lab_wps_rx_gate_init(&gate);

    assert(lab_wps_rx_gate_admit(&gate, true));
    for (unsigned index = 0; index < 32; ++index)
        assert(!lab_wps_rx_gate_admit(&gate, true));
    assert(lab_wps_rx_gate_coalesced_m3(&gate) == 32U);

    lab_wps_rx_gate_consumed(&gate, true);
    assert(lab_wps_rx_gate_admit(&gate, true));
}

static void test_non_m3_frames_are_never_coalesced(void)
{
    lab_wps_rx_gate_t gate;
    lab_wps_rx_gate_init(&gate);

    for (unsigned index = 0; index < 32; ++index)
        assert(lab_wps_rx_gate_admit(&gate, false));
    assert(lab_wps_rx_gate_coalesced_m3(&gate) == 0U);
}

int main(void)
{
    test_retains_one_pending_m3_and_coalesces_retransmissions();
    test_non_m3_frames_are_never_coalesced();
    puts("PASS: WPS RX retransmission gate");
    return 0;
}
