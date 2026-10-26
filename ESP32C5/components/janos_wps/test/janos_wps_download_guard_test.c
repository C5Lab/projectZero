/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_runtime.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    janos_radio_lease_snapshot_t lease = {
        .owner = JANOS_RADIO_OWNER_WPS,
        .state = JANOS_RADIO_LEASE_QUARANTINED,
        .generation = 7U,
    };
    assert(janos_wps_runtime_download_quiescent(true, false, 7U, lease));
    assert(!janos_wps_runtime_download_quiescent(true, true, 7U, lease));
    assert(!janos_wps_runtime_download_quiescent(false, false, 7U, lease));
    assert(!janos_wps_runtime_download_quiescent(true, false, 8U, lease));
    lease.callbacks_open = true;
    assert(!janos_wps_runtime_download_quiescent(true, false, 7U, lease));
    lease.callbacks_open = false;
    lease.owner = JANOS_RADIO_OWNER_ANALYZER;
    assert(!janos_wps_runtime_download_quiescent(true, false, 7U, lease));
    lease.owner = JANOS_RADIO_OWNER_WPS;
    lease.state = JANOS_RADIO_LEASE_RUNNING;
    assert(!janos_wps_runtime_download_quiescent(true, false, 7U, lease));
    lease.state = JANOS_RADIO_LEASE_QUARANTINED;
    lease.generation = 0U;
    assert(!janos_wps_runtime_download_quiescent(true, false, 0U, lease));
    puts("PASS: JanOS WPS quarantined download guard");
    return 0;
}
