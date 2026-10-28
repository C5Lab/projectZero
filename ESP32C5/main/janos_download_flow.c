/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_download_flow.h"

janos_download_result_t janos_download_flow_run(
    janos_radio_lease_snapshot_t lease,
    const janos_download_flow_ops_t *ops,
    uint32_t wps_wait_ms)
{
    if (!ops || !ops->rom_supported) return JANOS_DOWNLOAD_UNSUPPORTED;
    if (!ops->wait_wps_quarantined || !ops->stop_all || !ops->stop_wifi ||
        !ops->drain_uart || !ops->arm_rom || !ops->restore_rom ||
        !ops->reset_rom)
        return JANOS_DOWNLOAD_INVALID_HOOKS;

    bool quarantined_wps = lease.owner == JANOS_RADIO_OWNER_WPS &&
                           lease.state == JANOS_RADIO_LEASE_QUARANTINED &&
                           lease.generation != 0U && !lease.callbacks_open;
    bool normal_startup = lease.owner == JANOS_RADIO_OWNER_LEGACY &&
                          lease.state == JANOS_RADIO_LEASE_PREPARING &&
                          lease.generation != 0U;
    if (!quarantined_wps && !normal_startup)
        return JANOS_DOWNLOAD_REFUSED_OWNER;
    if (quarantined_wps && !ops->terminal_wipe)
        return JANOS_DOWNLOAD_INVALID_HOOKS;

    if (quarantined_wps) {
        if (!ops->wait_wps_quarantined(ops->context, wps_wait_ms))
            return JANOS_DOWNLOAD_WPS_NOT_QUIESCENT;
    } else {
        if (ops->stop_all(ops->context) != 0)
            return JANOS_DOWNLOAD_STOP_FAILED;
        ops->stop_wifi(ops->context);
    }

    ops->drain_uart(ops->context);
    if (!ops->arm_rom(ops->context)) return JANOS_DOWNLOAD_ARM_FAILED;
    if (quarantined_wps && !ops->terminal_wipe(ops->context)) {
        ops->restore_rom(ops->context);
        return JANOS_DOWNLOAD_WIPE_FAILED;
    }
    ops->reset_rom(ops->context);
    ops->restore_rom(ops->context);
    return JANOS_DOWNLOAD_RESET_RETURNED;
}
