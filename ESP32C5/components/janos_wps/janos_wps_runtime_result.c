/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_runtime_result.h"

#include <string.h>

bool janos_wps_runtime_result_verified(
    const janos_wps_service_status_t *status)
{
    if (status == NULL || status->phase != JANOS_WPS_SERVICE_IDLE ||
        status->operation_id == 0U ||
        strcmp(status->cleanup_result, "restored") != 0 ||
        status->secret.state != LAB_SECRET_AVAILABLE ||
        status->secret.operation_id != status->operation_id) {
        return false;
    }

    return strcmp(status->operation_result, "success") == 0 ||
           strcmp(status->operation_result, "pin_and_m7_verified") == 0 ||
           strcmp(status->operation_result, "pixie_pin_and_m7_verified") == 0;
}
