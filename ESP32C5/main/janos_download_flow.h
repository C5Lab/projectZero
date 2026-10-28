/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "janos_radio_lease.h"

typedef enum {
    JANOS_DOWNLOAD_UNSUPPORTED = 1,
    JANOS_DOWNLOAD_REFUSED_OWNER,
    JANOS_DOWNLOAD_INVALID_HOOKS,
    JANOS_DOWNLOAD_WPS_NOT_QUIESCENT,
    JANOS_DOWNLOAD_STOP_FAILED,
    JANOS_DOWNLOAD_ARM_FAILED,
    JANOS_DOWNLOAD_WIPE_FAILED,
    JANOS_DOWNLOAD_RESET_RETURNED,
} janos_download_result_t;

typedef struct {
    void *context;
    bool rom_supported;
    bool (*wait_wps_quarantined)(void *context, uint32_t timeout_ms);
    int (*stop_all)(void *context);
    void (*stop_wifi)(void *context);
    void (*drain_uart)(void *context);
    bool (*arm_rom)(void *context);
    void (*restore_rom)(void *context);
    /* Required for quarantined WPS; ignored for normal download. */
    bool (*terminal_wipe)(void *context);
    void (*reset_rom)(void *context);
} janos_download_flow_ops_t;

/* Admission runs first and supplies the reserved lease snapshot. The ROM
 * reset callback must not return on device; if it does, the flag is restored
 * and RESET_RETURNED is reported. No branch releases a quarantined lease. */
janos_download_result_t janos_download_flow_run(
    janos_radio_lease_snapshot_t lease,
    const janos_download_flow_ops_t *ops,
    uint32_t wps_wait_ms);
