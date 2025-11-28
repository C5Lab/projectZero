/**
 * @file sniffer.c
 * @brief Implements sniffer events
 */
#include "sniffer.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "sniffer"; 

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);

/**
 * @brief Callback for promiscuous receiver. 
 * 
 * It forwards captured frames into event pool and sorts them based on their type
 */
static void frame_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    ESP_LOGV(TAG, "Captured frame %d.", (int) type);

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;

    int32_t event_id;
    switch (type) {
        case WIFI_PKT_DATA:
            event_id = SNIFFER_EVENT_CAPTURED_DATA;
            break;
        case WIFI_PKT_MGMT:
            event_id = SNIFFER_EVENT_CAPTURED_MGMT;
            break;
        case WIFI_PKT_CTRL:
            event_id = SNIFFER_EVENT_CAPTURED_CTRL;
            break;
        default:
            return;
    }

    ESP_ERROR_CHECK(esp_event_post(SNIFFER_EVENTS, event_id, frame, frame->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t), portMAX_DELAY));
}

/**
 * @brief Initialize sniffer and register promiscuous callback
 */
void sniffer_init(void) {
    // Set filter to capture both DATA and MGMT frames
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&frame_handler);
}

