/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_transport.h"
#include "janos_wps_build.h"

#include <stdlib.h>
#include <string.h>

#include "esp_idf_version.h"
#include "esp_private/wifi.h"
#include "esp_wifi.h"
#include "utils/common.h"
#include "esp_wifi_driver.h"
#include "esp_wps.h"

#if ESP_IDF_VERSION_MAJOR != JANOS_WPS_IDF_MAJOR || \
    ESP_IDF_VERSION_MINOR != JANOS_WPS_IDF_MINOR || \
    ESP_IDF_VERSION_PATCH != JANOS_WPS_IDF_PATCH
#error "JanOS WPS private API adapter does not support this ESP-IDF version"
#endif

static bool ignore_scan(struct wps_scan_ie *scan) { (void)scan; return false; }
static int ignore_start(void) { return ESP_OK; }
static int ignore_rx(u8 *source, u8 *buffer, u32 length)
{ (void)source; (void)buffer; (void)length; return ESP_OK; }
static int ignore_pending(void) { return ESP_OK; }

static int borrowed_init(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || context->borrowed) return ESP_ERR_INVALID_STATE;
    context->restore_verified = false;
    esp_err_t error = esp_wifi_stop();
    if (error != ESP_OK) return error;
    context->borrowed = true;
    context->driver_running = false;
    error = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (error == ESP_OK) error = esp_wifi_set_mode(WIFI_MODE_STA);
    return error;
}

static int borrowed_start(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed || context->driver_running)
        return ESP_ERR_INVALID_STATE;
    esp_err_t error = esp_wifi_start();
    if (error == ESP_OK) context->driver_running = true;
    return error;
}

static int borrowed_stop(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed) return ESP_ERR_INVALID_STATE;
    if (!context->driver_running) return ESP_OK;
    esp_err_t error = esp_wifi_stop();
    if (error == ESP_OK) context->driver_running = false;
    return error;
}

/* wps_transport_core calls deinit last. For a borrowed driver this means
 * restore the baseline running state; shared infrastructure remains alive. */
static int borrowed_restore(void *opaque)
{
    janos_wps_transport_context_t *context = opaque;
    if (!context || !context->borrowed || context->driver_running)
        return ESP_ERR_INVALID_STATE;
    esp_err_t error = esp_wifi_start();
    if (error != ESP_OK) return error;
    context->driver_running = true;
    error = esp_wifi_get_mac(WIFI_IF_STA, context->restored_mac);
    if (error == ESP_OK) context->restore_verified = true;
    if (error == ESP_OK) context->borrowed = false;
    return error;
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

