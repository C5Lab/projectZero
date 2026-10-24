#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "janos_wps_runtime_result.h"

static janos_wps_service_status_t verified_status(const char *result)
{
    janos_wps_service_status_t status = {0};
    status.phase = JANOS_WPS_SERVICE_IDLE;
    status.operation_id = 17U;
    status.secret.state = LAB_SECRET_AVAILABLE;
    status.secret.operation_id = 17U;
    strcpy(status.cleanup_result, "restored");
    strcpy(status.operation_result, result);
    return status;
}

int main(void)
{
    const char *successes[] = {
        "success", "pin_and_m7_verified", "pixie_pin_and_m7_verified"
    };
    for (size_t i = 0; i < sizeof(successes) / sizeof(successes[0]); ++i) {
        janos_wps_service_status_t status = verified_status(successes[i]);
        assert(janos_wps_runtime_result_verified(&status));
    }

    janos_wps_service_status_t status = verified_status("pin_and_m7_verified");
    status.phase = JANOS_WPS_SERVICE_RUNNING;
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("pin_and_m7_verified");
    strcpy(status.cleanup_result, "failed");
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("pin_and_m7_verified");
    status.secret.state = LAB_SECRET_EMPTY;
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("pin_and_m7_verified");
    status.secret.operation_id = 16U;
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("pin_and_m7_verified");
    status.operation_id = 0U;
    status.secret.operation_id = 0U;
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("selftest_verified");
    assert(!janos_wps_runtime_result_verified(&status));

    status = verified_status("cancelled");
    assert(!janos_wps_runtime_result_verified(&status));
    assert(!janos_wps_runtime_result_verified(NULL));

    puts("PASS: JanOS WPS verified runtime result gate");
    return 0;
}
