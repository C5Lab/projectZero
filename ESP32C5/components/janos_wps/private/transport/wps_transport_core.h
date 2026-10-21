/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct wps_transport_ops {
    /* deinit must be safe after a failed/partially completed init. */
    int (*init)(void *context);
    int (*start)(void *context);
    int (*stop)(void *context);
    int (*deinit)(void *context);
    int (*set_mac)(void *context, const uint8_t mac[6]);
    int (*callbacks)(void *context, bool enabled);
    int (*appie)(void *context, bool enabled);
    int (*wps)(void *context, bool enabled);
    int (*disconnect)(void *context);
} wps_transport_ops_t;

typedef struct {
    const wps_transport_ops_t *ops;
    void *context;
    uint8_t original_mac[6];
    bool initialized;
    bool mac_changed;
    bool started;
    bool disconnect_pending;
    bool callbacks_set;
    bool appie_set;
    bool wps_enabled;
    bool active;
} wps_transport_t;

void wps_transport_init(wps_transport_t *transport,
                        const wps_transport_ops_t *ops, void *context);
bool wps_transport_begin(wps_transport_t *transport,
                         const uint8_t session_mac[6],
                         const uint8_t original_mac[6]);
/* False retains the failed step and its dependencies for another cancel call. */
bool wps_transport_cancel(wps_transport_t *transport);
bool wps_transport_cleanup_pending(const wps_transport_t *transport);
bool wps_transport_active(const wps_transport_t *transport);
