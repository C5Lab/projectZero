/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_transport.h"
#include "janos_wps_build.h"
#include "private/transport/wps_transport_core.h"

#include <stdlib.h>
#include <string.h>

#include "esp_idf_version.h"
#include "esp_private/wifi.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "utils/common.h"
#include "esp_wifi_driver.h"
#include "esp_wps.h"

#if ESP_IDF_VERSION_MAJOR != JANOS_WPS_IDF_MAJOR || \
    ESP_IDF_VERSION_MINOR != JANOS_WPS_IDF_MINOR || \
    ESP_IDF_VERSION_PATCH < JANOS_WPS_IDF_PATCH_MIN || \
    ESP_IDF_VERSION_PATCH > JANOS_WPS_IDF_PATCH_MAX
#error "JanOS WPS private API adapter does not support this ESP-IDF version"
#endif

static bool ignore_scan(struct wps_scan_ie *scan) { (void)scan; return false; }
static int ignore_start(void) { return ESP_OK; }
static int ignore_rx(u8 *source, u8 *buffer, u32 length)
{ (void)source; (void)buffer; (void)length; return ESP_OK; }
static int ignore_pending(void) { return ESP_OK; }

static struct {
    bool known;
    bool running;
    wifi_storage_t storage;
} host_wifi;

esp_err_t janos_wps_wifi_init(const wifi_init_config_t *config)
{
    esp_err_t error = esp_wifi_init(config);
    if (error == ESP_OK) {
        host_wifi.known = true;
        host_wifi.running = false;
        host_wifi.storage = WIFI_STORAGE_FLASH;
    }
    return error;
}

esp_err_t janos_wps_wifi_deinit(void)
{
    esp_err_t error = esp_wifi_deinit();
    if (error == ESP_OK) host_wifi.known = false;
    return error;
}

esp_err_t janos_wps_wifi_start(void)
{
    esp_err_t error = esp_wifi_start();
    if (error == ESP_OK) host_wifi.running = true;
    return error;
}

esp_err_t janos_wps_wifi_stop(void)
{
    esp_err_t error = esp_wifi_stop();
    if (error == ESP_OK) host_wifi.running = false;
    return error;
}

esp_err_t janos_wps_wifi_set_storage(wifi_storage_t storage)
{
    esp_err_t error = esp_wifi_set_storage(storage);
    if (error == ESP_OK) host_wifi.storage = storage;
    return error;
}

struct janos_wps_wifi_snapshot {
    wifi_config_t config;
    wifi_config_t readback;
    wifi_mode_t mode;
    wifi_storage_t storage;
    uint8_t primary;
    wifi_second_chan_t secondary;
    uint8_t mac[6];
};

enum {
    RESTORE_STOP, RESTORE_RAM, RESTORE_MODE, RESTORE_CONFIG, RESTORE_MAC,
    RESTORE_START, RESTORE_CHANNEL, RESTORE_STORAGE, RESTORE_VERIFY
};

static void wipe(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (size--) *bytes++ = 0;
}

static void discard_snapshot(janos_wps_transport_context_t *context)
{
    if (!context->snapshot) return;
    wipe(context->snapshot, sizeof(*context->snapshot));
    heap_caps_free(context->snapshot);
    context->snapshot = NULL;
}

void janos_wps_transport_reset(janos_wps_transport_context_t *context)
{
    if (!context) return;
    discard_snapshot(context);
    wipe(context, sizeof(*context));
    context->terminal_failure = true;
}

static int borrowed_init(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || context->borrowed) return ESP_ERR_INVALID_STATE;
    context->restore_verified = false;
    context->rejected_baseline = false;
    if (context->terminal_failure || !host_wifi.known)
        return ESP_ERR_INVALID_STATE;
    /* Channel readback is only public while started. Stopped/AP baselines are
     * outside this first iteration and are rejected before any mutation. */
    if (!host_wifi.running) {
        context->rejected_baseline = true;
        return ESP_ERR_INVALID_STATE;
    }
    struct janos_wps_wifi_snapshot *snapshot = heap_caps_calloc(
        1U, sizeof(*snapshot), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!snapshot) {
        context->terminal_failure = true;
        return ESP_ERR_NO_MEM;
    }
    context->snapshot = snapshot;
    snapshot->storage = host_wifi.storage;
    esp_err_t error = esp_wifi_get_mode(&snapshot->mode);
    if (error == ESP_OK && snapshot->mode != WIFI_MODE_STA) {
        discard_snapshot(context);
        context->rejected_baseline = true;
        return ESP_ERR_INVALID_STATE;
    }
    if (error == ESP_OK) error = esp_wifi_get_config(WIFI_IF_STA, &snapshot->config);
    if (error == ESP_OK) error = esp_wifi_get_channel(&snapshot->primary, &snapshot->secondary);
    if (error == ESP_OK) error = esp_wifi_get_mac(WIFI_IF_STA, snapshot->mac);
    if (error != ESP_OK) {
        discard_snapshot(context);
        context->terminal_failure = true;
        return error;
    }
    context->borrowed = true;
    context->driver_running = true;
    context->restore_phase = RESTORE_STOP;
    error = janos_wps_wifi_stop();
    if (error == ESP_OK) context->driver_running = false;
    if (error == ESP_OK) error = janos_wps_wifi_set_storage(WIFI_STORAGE_RAM);
    if (error == ESP_OK) error = esp_wifi_set_mode(WIFI_MODE_STA);
    return error;
}

static int borrowed_start(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed || context->driver_running)
        return ESP_ERR_INVALID_STATE;
    esp_err_t error = janos_wps_wifi_start();
    if (error == ESP_OK) context->driver_running = true;
    return error;
}

static int borrowed_stop(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed) return ESP_ERR_INVALID_STATE;
    if (!context->driver_running) return ESP_OK;
    esp_err_t error = janos_wps_wifi_stop();
    if (error == ESP_OK) context->driver_running = false;
    return error;
}

/* A failed phase is retried without losing baseline credentials. Configuration
 * writes always use RAM; FLASH policy is reinstated only after all writes.
 * Readback failures restart restoration, including stopping a running driver. */
static int borrowed_restore(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || context->terminal_failure) return ESP_ERR_INVALID_STATE;
    if (context->rejected_baseline) return ESP_OK;
    if (!context->borrowed || !context->snapshot)
        return ESP_ERR_INVALID_STATE;
    struct janos_wps_wifi_snapshot *snapshot = context->snapshot;
    esp_err_t error = ESP_OK;
    while (context->restore_phase < RESTORE_VERIFY) {
        switch (context->restore_phase) {
        case RESTORE_STOP:
            if (context->driver_running) error = borrowed_stop(context);
            break;
        case RESTORE_RAM: error = janos_wps_wifi_set_storage(WIFI_STORAGE_RAM); break;
        case RESTORE_MODE: error = esp_wifi_set_mode(snapshot->mode); break;
        case RESTORE_CONFIG: error = esp_wifi_set_config(WIFI_IF_STA, &snapshot->config); break;
        case RESTORE_MAC: error = esp_wifi_set_mac(WIFI_IF_STA, snapshot->mac); break;
        case RESTORE_START: error = borrowed_start(context); break;
        case RESTORE_CHANNEL: error = esp_wifi_set_channel(snapshot->primary, snapshot->secondary); break;
        case RESTORE_STORAGE: error = janos_wps_wifi_set_storage(snapshot->storage); break;
        }
        if (error != ESP_OK) return error;
        context->restore_phase++;
    }
    wifi_mode_t mode = 0;
    uint8_t primary = 0;
    wifi_second_chan_t secondary = WIFI_SECOND_CHAN_NONE;
    error = esp_wifi_get_mode(&mode);
    if (error == ESP_OK) error = esp_wifi_get_config(WIFI_IF_STA, &snapshot->readback);
    if (error == ESP_OK) error = esp_wifi_get_channel(&primary, &secondary);
    if (error == ESP_OK) error = esp_wifi_get_mac(WIFI_IF_STA, context->restored_mac);
    bool equal = error == ESP_OK && mode == snapshot->mode &&
        memcmp(&snapshot->config, &snapshot->readback, sizeof(snapshot->config)) == 0 &&
        primary == snapshot->primary && secondary == snapshot->secondary &&
        memcmp(context->restored_mac, snapshot->mac, 6U) == 0 &&
        host_wifi.known && host_wifi.running && host_wifi.storage == snapshot->storage;
    wipe(&snapshot->readback, sizeof(snapshot->readback));
    if (!equal) {
        context->restore_phase = RESTORE_STOP;
        return error == ESP_OK ? ESP_ERR_INVALID_STATE : error;
    }
    discard_snapshot(context);
    context->restore_verified = true;
    context->borrowed = false;
    return ESP_OK;
}

static int borrowed_set_mac(void *opaque, const uint8_t mac[6])
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed || context->driver_running || !mac)
        return ESP_ERR_INVALID_STATE;
    esp_err_t error = esp_wifi_set_mac(WIFI_IF_STA, mac);
    if (error == ESP_OK) context->session_mac_set = true;
    return error;
}

static int borrowed_callbacks(void *opaque, bool enabled)
{
    (void)opaque;
    if (!enabled) return esp_wifi_set_wps_cb_internal(NULL);
    struct wps_funcs *callbacks = calloc(1U, sizeof(*callbacks));
    if (!callbacks) return ESP_ERR_NO_MEM;
    callbacks->wps_parse_scan_result = ignore_scan;
    callbacks->wifi_station_wps_start = ignore_start;
    callbacks->wps_sm_rx_eapol = ignore_rx;
    callbacks->wps_start_pending = ignore_pending;
    esp_err_t error = esp_wifi_set_wps_cb_internal(callbacks);
    if (error != ESP_OK) free(callbacks);
    return error;
}

static int borrowed_appie(void *opaque, bool enabled)
{
    (void)opaque;
    static uint8_t ie[] = {
        0xdd,0x17,0,0x50,0xf2,4,0x10,0x4a,0,1,0x10,0x10,0x3a,0,1,2,
        0x10,0x49,0,6,0,0x37,0x2a,0,1,0x20
    };
    return enabled ? esp_wifi_set_appie_internal(WIFI_APPIE_WPS_AR, ie,
                                                  sizeof(ie), 0)
                   : esp_wifi_unset_appie_internal(WIFI_APPIE_WPS_AR);
}

static int borrowed_wps(void *opaque, bool enabled)
{
    (void)opaque;
    if (!enabled) {
        esp_err_t first = esp_wifi_set_wps_start_flag_internal(false);
        esp_err_t second = esp_wifi_set_wps_type_internal(WPS_TYPE_DISABLE);
        esp_err_t third = esp_wifi_set_wps_status_internal(WPS_STATUS_DISABLE);
        return first != ESP_OK ? first : (second != ESP_OK ? second : third);
    }
    esp_err_t error = esp_wifi_set_wps_type_internal(WPS_TYPE_PIN);
    if (error == ESP_OK) error = esp_wifi_set_wps_status_internal(WPS_STATUS_PENDING);
    if (error == ESP_OK) error = esp_wifi_set_wps_start_flag_internal(true);
    return error;
}

static int borrowed_disconnect(void *opaque)
{
    (void)opaque;
    esp_err_t error = esp_wifi_disconnect();
    return error == ESP_ERR_WIFI_NOT_CONNECT ? ESP_OK : error;
}

const wps_transport_ops_t janos_wps_transport_ops = {
    borrowed_init, borrowed_start, borrowed_stop, borrowed_restore,
    borrowed_set_mac, borrowed_callbacks, borrowed_appie, borrowed_wps,
    borrowed_disconnect,
};

