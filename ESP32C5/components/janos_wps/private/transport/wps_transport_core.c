/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "wps_transport_core.h"

#include <string.h>

void wps_transport_init(wps_transport_t *transport,
                        const wps_transport_ops_t *ops, void *context)
{
    if (transport == NULL) return;
    memset(transport, 0, sizeof(*transport));
    transport->ops = ops;
    transport->context = context;
}

static bool valid_ops(const wps_transport_ops_t *ops)
{
    return ops != NULL && ops->init != NULL && ops->start != NULL &&
           ops->stop != NULL && ops->deinit != NULL && ops->set_mac != NULL &&
           ops->callbacks != NULL && ops->appie != NULL && ops->wps != NULL &&
           ops->disconnect != NULL;
}

bool wps_transport_cleanup_pending(const wps_transport_t *transport)
{
    return transport != NULL && (transport->initialized || transport->mac_changed ||
           transport->started || transport->disconnect_pending ||
           transport->callbacks_set || transport->appie_set || transport->wps_enabled);
}

bool wps_transport_cancel(wps_transport_t *transport)
{
    if (transport == NULL || !valid_ops(transport->ops)) return false;
    const wps_transport_ops_t *ops = transport->ops;
    transport->active = false;
    if (transport->wps_enabled) {
        if (ops->wps(transport->context, false) != 0) return false;
        transport->wps_enabled = false;
    }
    if (transport->disconnect_pending) {
        if (ops->disconnect(transport->context) != 0) return false;
        transport->disconnect_pending = false;
    }
    if (transport->appie_set) {
        if (ops->appie(transport->context, false) != 0) return false;
        transport->appie_set = false;
    }
    if (transport->callbacks_set) {
        if (ops->callbacks(transport->context, false) != 0) return false;
        transport->callbacks_set = false;
    }
    if (transport->started) {
        if (ops->stop(transport->context) != 0) return false;
        transport->started = false;
    }
    if (transport->mac_changed) {
        if (ops->set_mac(transport->context, transport->original_mac) != 0) return false;
        transport->mac_changed = false;
    }
    if (transport->initialized) {
        if (ops->deinit(transport->context) != 0) return false;
        transport->initialized = false;
    }
    return true;
}

bool wps_transport_begin(wps_transport_t *transport,
                         const uint8_t session_mac[6],
                         const uint8_t original_mac[6])
{
    if (transport == NULL || session_mac == NULL || original_mac == NULL ||
        transport->active || wps_transport_cleanup_pending(transport) ||
        !valid_ops(transport->ops)) return false;
    const wps_transport_ops_t *ops = transport->ops;
    memcpy(transport->original_mac, original_mac, sizeof(transport->original_mac));
    transport->initialized = true;
    if (ops->init(transport->context) != 0) goto fail;
    if (ops->set_mac(transport->context, session_mac) != 0) goto fail;
    transport->mac_changed = true;
    if (ops->start(transport->context) != 0) goto fail;
    transport->started = true;
    transport->disconnect_pending = true;
    if (ops->callbacks(transport->context, true) != 0) goto fail;
    transport->callbacks_set = true;
    if (ops->appie(transport->context, true) != 0) goto fail;
    transport->appie_set = true;
    /* Enabling WPS is composite: even a failure may need rollback. */
    transport->wps_enabled = true;
    if (ops->wps(transport->context, true) != 0) goto fail;
    transport->active = true;
    return true;

fail:
    wps_transport_cancel(transport);
    return false;
}

bool wps_transport_active(const wps_transport_t *transport)
{
    return transport != NULL && transport->active;
}
