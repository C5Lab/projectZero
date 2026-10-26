/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "janos_radio_lease.h"

typedef struct {
    const char *(*busy_reason)(void);
    esp_err_t (*prepare_wifi)(void);
    esp_err_t (*mount_sd)(void);
    void (*tx_activity)(void);
    void (*verified)(void);
} janos_wps_runtime_hooks_t;

bool janos_wps_runtime_init(janos_radio_lease_t *lease,
                            const janos_wps_runtime_hooks_t *hooks,
                            const uint8_t effective_boot_mac[6]);
int janos_wps_command(int argc, char **argv);
int janos_jwps_command(int argc, char **argv);
int janos_wps_selftest_command(int argc, char **argv);
int janos_wps_secret_command(int argc, char **argv);
bool janos_wps_runtime_stop(uint32_t timeout_ms);
bool janos_wps_runtime_busy(void);

/* A ROM reset may discard a quarantined lease only after the runtime worker
 * has finished terminal output and its shared epilogue. This does not restore
 * Wi-Fi, release the lease, or make another radio command safe. */
static inline bool janos_wps_runtime_download_quiescent(
    bool service_quarantined, bool worker_active, uint32_t service_generation,
    janos_radio_lease_snapshot_t lease)
{
    return service_quarantined && !worker_active &&
           service_generation != 0U &&
           lease.owner == JANOS_RADIO_OWNER_WPS &&
           lease.state == JANOS_RADIO_LEASE_QUARANTINED &&
           lease.generation == service_generation && !lease.callbacks_open;
}

bool janos_wps_runtime_wait_quarantined_download(uint32_t timeout_ms);

