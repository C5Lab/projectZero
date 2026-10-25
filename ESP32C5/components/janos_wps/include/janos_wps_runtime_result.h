/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>

#include "janos_wps_service.h"

bool janos_wps_runtime_result_verified(
    const janos_wps_service_status_t *status);
