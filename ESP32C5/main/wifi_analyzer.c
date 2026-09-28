#include "wifi_analyzer.h"
#include "wifi_analyzer_core.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define WFA_PSRAM_RESERVE (64U * 1024U)
#define WFA_PSRAM_CEILING (192U * 1024U)
#define WFA_STACK_BYTES 6144U
#define WFA_CANCEL_GRACE_MS 2000U

typedef enum {
    WFA_IDLE, WFA_PREPARING, WFA_SCANNING, WFA_COLLECTING,
    WFA_PUBLISHING, WFA_CANCELLING, WFA_QUARANTINED
} wfa_state_t;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static wifi_analyzer_hooks_t s_hooks;
static bool s_initialized;
static wfa_state_t s_state;
static TaskHandle_t s_worker;
static bool s_cancel, s_armed, s_done;
static uint32_t s_driver_status;
static uint8_t s_driver_scan_id;
static const char *s_last_error;
static uint32_t s_scan, s_last_success;
static char s_boot[17];
static uint64_t s_started_ms;
static wfa_options_t s_options;
static wifi_scan_config_t s_scan_config;
static wifi_ap_record_t *s_working, *s_committed;
static uint16_t s_capacity, s_last_count;
static size_t s_psram_bytes;
static wifi_band_mode_t s_saved_band;
static uint8_t s_saved_primary;
static wifi_second_chan_t s_saved_secondary;
static bool s_saved_radio;

static uint64_t now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static const char *state_name(wfa_state_t state)
{
    static const char *const names[] = {
        "idle", "preparing", "scanning", "collecting", "publishing",
        "cancelling", "quarantined"
    };
    return names[(unsigned)state];
}

static void set_state(wfa_state_t state)
{
    portENTER_CRITICAL(&s_lock);
    s_state = state;
    portEXIT_CRITICAL(&s_lock);
}

static void set_error(const char *error)
{
    portENTER_CRITICAL(&s_lock);
    s_last_error = error;
    portEXIT_CRITICAL(&s_lock);
}

bool wifi_analyzer_busy(void)
{
    portENTER_CRITICAL(&s_lock);
    bool busy = s_state != WFA_IDLE;
    portEXIT_CRITICAL(&s_lock);
    return busy;
}

static bool cancelled(void)
{
    portENTER_CRITICAL(&s_lock);
    bool cancel = s_cancel;
    portEXIT_CRITICAL(&s_lock);
    return cancel;
}

static bool scan_done(uint32_t *status)
{
    portENTER_CRITICAL(&s_lock);
    bool done = s_done;
    if (status) *status = s_driver_status;
    portEXIT_CRITICAL(&s_lock);
    return done;
}

bool wifi_analyzer_on_scan_done(const wifi_event_sta_scan_done_t *event)
{
    portENTER_CRITICAL(&s_lock);
    bool owned = s_state != WFA_IDLE;
    if (owned && s_armed && !s_done && event) {
        s_driver_status = event->status;
        s_driver_scan_id = event->scan_id;
        s_done = true;
    }
    portEXIT_CRITICAL(&s_lock);
    /* No allocation, output, driver calls or task handles in the event callback. */
    return owned;
}

/* stdout's stream lock also excludes the existing printf-based console writers.
 * Leading LF separates asynchronous records from the REPL's unterminated prompt.
 * Each bounded line is one fwrite; no global UART setting or legacy pacing changes.
 * A physically blocked VFS write cannot be preempted here; stop never frees a
 * still-running writer. Time budgets are checked before/after each record.
 */
static bool emit_line(const char *line, int length)
{
    if (length <= 0 || length > (int)WFA_MAX_LINE_BYTES + 1) return false;
    if (s_hooks.tx_activity) s_hooks.tx_activity();
    flockfile(stdout);
    bool ok = fputc('\n', stdout) != EOF;
    size_t sent = 0;
    while (ok && sent < (size_t)length) {
        size_t n = fwrite(line + sent, 1, (size_t)length - sent, stdout);
        if (n == 0) ok = false;
        else sent += n;
    }
    if (fflush(stdout) != 0) ok = false;
    funlockfile(stdout);
    return ok;
}

static void control_error(const char *command, const char *code, const char *reason)
{
    char line[320];
    /* All three strings are internal tokens, never unescaped command arguments. */
    int n = snprintf(line, sizeof(line),
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"%s\",\"code\":\"%s\",\"reason\":\"%s\"}\n",
        command, code, reason ? reason : code);
    if (n > 0 && (size_t)n < sizeof(line)) (void)emit_line(line, n);
}

void wifi_analyzer_init(const wifi_analyzer_hooks_t *hooks)
{
    if (s_initialized || !hooks) return;
    s_hooks = *hooks;
    snprintf(s_boot, sizeof(s_boot), "%08" PRIx32 "%08" PRIx32, esp_random(), esp_random());
    s_initialized = true;
}

static bool reserve(void)
{
    portENTER_CRITICAL(&s_lock);
    bool ok = s_state == WFA_IDLE;
    if (ok) {
        s_state = WFA_PREPARING;
        s_cancel = false;
        s_armed = false;
        s_done = false;
        s_last_error = NULL;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

static void release(bool fault)
{
    portENTER_CRITICAL(&s_lock);
    s_armed = false;
    s_worker = NULL;
    s_state = fault ? WFA_QUARANTINED : WFA_IDLE;
    portEXIT_CRITICAL(&s_lock);
}

static bool allocate_buffers(uint16_t capacity)
{
    if (s_capacity >= capacity) return true;
    const uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    size_t one = (size_t)capacity * sizeof(wifi_ap_record_t);
    size_t new_total = 2U * one;
    /* During growth the old good snapshot remains allocated until both new
     * buffers exist. Account for this transient peak, not just the final size. */
    if (new_total + s_psram_bytes > WFA_PSRAM_CEILING ||
        heap_caps_get_free_size(caps) < new_total + WFA_PSRAM_RESERVE ||
        heap_caps_get_largest_free_block(caps) < one) return false;
    wifi_ap_record_t *working = heap_caps_calloc(capacity, sizeof(*working), caps);
    if (!working) return false;
    wifi_ap_record_t *committed = heap_caps_calloc(capacity, sizeof(*committed), caps);
    if (!committed) {
        heap_caps_free(working);
        return false;
    }
    if (heap_caps_get_free_size(caps) < WFA_PSRAM_RESERVE) {
        heap_caps_free(working);
        heap_caps_free(committed);
        return false;
    }
    if (s_committed && s_last_count) {
        memcpy(committed, s_committed, (size_t)s_last_count * sizeof(*committed));
    }
    heap_caps_free(s_working);
    heap_caps_free(s_committed);
    s_working = working;
    s_committed = committed;
    portENTER_CRITICAL(&s_lock);
    s_capacity = capacity;
    s_psram_bytes = new_total;
    portEXIT_CRITICAL(&s_lock);
    return true;
}

static uint32_t channel_5_bit(uint8_t channel)
{
    unsigned index = 1;
    for (unsigned ch = 36; ch <= 177; ++ch) {
        if (wfa_channel_band(ch) != WFA_BAND_5) continue;
        if (ch == channel) return UINT32_C(1) << index;
        ++index;
    }
    return 0;
}

static const char *configure_scan(void)
{
    wifi_country_t country = {0};
    if (esp_wifi_get_country(&country) != ESP_OK) return "radio_config_failed";
    uint8_t count = 0;
    for (uint8_t i = 0; i < s_options.channel_count; ++i) {
        uint8_t channel = s_options.channels[i];
        bool allowed;
        if (wfa_channel_band(channel) == WFA_BAND_24) {
            allowed = channel >= country.schan &&
                      (unsigned)channel < (unsigned)country.schan + country.nchan;
        } else {
            /* Zero/AUTO masks are resolved internally by IDF. Keep the requested
             * candidate set and describe it as driver-filtered, not measured
             * coverage. Never invent a country table or change country policy. */
            allowed = country.policy != WIFI_COUNTRY_POLICY_MANUAL ||
                      country.wifi_5g_channel_mask == 0 ||
                      (country.wifi_5g_channel_mask & channel_5_bit(channel)) != 0;
        }
        if (!allowed && s_options.explicit_channels) return "unsupported_channel";
        if (allowed) s_options.channels[count++] = channel;
    }
    s_options.channel_count = count;
    if (!count) return "unsupported_channel";

    if (esp_wifi_get_band_mode(&s_saved_band) != ESP_OK ||
        esp_wifi_get_channel(&s_saved_primary, &s_saved_secondary) != ESP_OK) {
        return "radio_config_failed";
    }
    s_saved_radio = true;
    wifi_band_mode_t mode = s_options.band == WFA_BAND_24 ? WIFI_BAND_MODE_2G_ONLY :
                            s_options.band == WFA_BAND_5 ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_AUTO;
    if (esp_wifi_set_band_mode(mode) != ESP_OK) return "radio_config_failed";

    memset(&s_scan_config, 0, sizeof(s_scan_config));
    s_scan_config.show_hidden = true;
    s_scan_config.scan_type = s_options.profile == WFA_PASSIVE ? WIFI_SCAN_TYPE_PASSIVE : WIFI_SCAN_TYPE_ACTIVE;
    if (s_options.profile == WFA_PASSIVE) s_scan_config.scan_time.passive = 600;
    else {
        s_scan_config.scan_time.active.min = s_options.profile == WFA_QUICK ? 100 : 300;
        s_scan_config.scan_time.active.max = s_options.profile == WFA_QUICK ? 300 : 600;
    }
    for (uint8_t i = 0; i < count; ++i) {
        uint8_t channel = s_options.channels[i];
        if (wfa_channel_band(channel) == WFA_BAND_24)
            s_scan_config.channel_bitmap.ghz_2_channels |= (uint16_t)(UINT16_C(1) << channel);
        else s_scan_config.channel_bitmap.ghz_5_channels |= channel_5_bit(channel);
    }
    /* bit0 explicitly bypasses a band; zero must not accidentally mean 'all'. */
    if (!s_scan_config.channel_bitmap.ghz_2_channels) s_scan_config.channel_bitmap.ghz_2_channels = 1;
    if (!s_scan_config.channel_bitmap.ghz_5_channels) s_scan_config.channel_bitmap.ghz_5_channels = 1;
    return NULL;
}

static bool restore_radio(void)
{
    if (!s_saved_radio) return true;
    esp_err_t band_err = esp_wifi_set_band_mode(s_saved_band);
    esp_err_t channel_err = band_err == ESP_OK ?
        esp_wifi_set_channel(s_saved_primary, s_saved_secondary) : band_err;
    if (band_err != ESP_OK || channel_err != ESP_OK) return false;
    s_saved_radio = false;
    return true;
}

static const char *auth_name(wifi_auth_mode_t auth)
{
    switch (auth) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA_WPA2_PSK";
    case WIFI_AUTH_ENTERPRISE: return "WPA2_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2_WPA3_PSK";
    case WIFI_AUTH_WAPI_PSK: return "WAPI_PSK";
    case WIFI_AUTH_OWE: return "OWE";
    case WIFI_AUTH_WPA3_ENT_192: return "WPA3_ENT_192";
    case WIFI_AUTH_DPP: return "DPP";
    case WIFI_AUTH_WPA3_ENTERPRISE: return "WPA3_ENTERPRISE";
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE: return "WPA2_WPA3_ENTERPRISE";
    case WIFI_AUTH_WPA_ENTERPRISE: return "WPA_ENTERPRISE";
    default: return "UNKNOWN";
    }
}

static void normalize_ap(const wifi_ap_record_t *raw, wfa_ap_t *ap)
{
    memset(ap, 0, sizeof(*ap));
    memcpy(ap->bssid, raw->bssid, 6);
    ap->ssid_len = (uint8_t)strnlen((const char *)raw->ssid, 32);
    memcpy(ap->ssid, raw->ssid, ap->ssid_len);
    ap->primary = raw->primary;
    ap->rssi = raw->rssi;
    ap->band = wfa_channel_band(raw->primary);
    ap->auth = auth_name(raw->authmode);
    ap->phy_mask = (raw->phy_11a ? WFA_PHY_A : 0) | (raw->phy_11b ? WFA_PHY_B : 0) |
        (raw->phy_11g ? WFA_PHY_G : 0) | (raw->phy_11n ? WFA_PHY_N : 0) |
        (raw->phy_11ac ? WFA_PHY_AC : 0) | (raw->phy_11ax ? WFA_PHY_AX : 0) |
        (raw->phy_lr ? WFA_PHY_LR : 0);
    ap->secondary = raw->second == WIFI_SECOND_CHAN_NONE ? WFA_SECOND_NONE :
                    raw->second == WIFI_SECOND_CHAN_ABOVE ? WFA_SECOND_ABOVE :
                    raw->second == WIFI_SECOND_CHAN_BELOW ? WFA_SECOND_BELOW : WFA_SECOND_UNKNOWN;
    unsigned primary_mhz = wfa_primary_frequency(raw->primary);
    switch (raw->bandwidth) {
    case WIFI_BW20:
        ap->width = WFA_WIDTH_20;
        ap->center1_mhz = (uint16_t)primary_mhz;
        break;
    case WIFI_BW40:
        ap->width = WFA_WIDTH_40;
        if (ap->secondary == WFA_SECOND_ABOVE) ap->center1_mhz = (uint16_t)(primary_mhz + 10U);
        else if (ap->secondary == WFA_SECOND_BELOW && primary_mhz >= 10U)
            ap->center1_mhz = (uint16_t)(primary_mhz - 10U);
        break;
    case WIFI_BW80: ap->width = WFA_WIDTH_80; break;
    case WIFI_BW160: ap->width = WFA_WIDTH_160; break;
    case WIFI_BW80_BW80: ap->width = WFA_WIDTH_80P80; break;
    default: ap->width = WFA_WIDTH_UNKNOWN; break;
    }
    if (ap->width == WFA_WIDTH_80 || ap->width == WFA_WIDTH_160 || ap->width == WFA_WIDTH_80P80) {
        if (raw->vht_ch_freq1) ap->center1_mhz = (uint16_t)(5000U + 5U * raw->vht_ch_freq1);
        if (ap->width == WFA_WIDTH_80P80 && raw->vht_ch_freq2)
            ap->center2_mhz = (uint16_t)(5000U + 5U * raw->vht_ch_freq2);
    }
    wfa_normalize_geometry(ap);
}

static bool validate_records(uint16_t count)
{
    for (uint16_t i = 0; i < count; ++i) {
        bool in_scope = false;
        for (uint8_t j = 0; j < s_options.channel_count; ++j)
            if (s_working[i].primary == s_options.channels[j]) in_scope = true;
        if (!in_scope || s_working[i].rssi < -127 || s_working[i].rssi > 20) return false;
        for (uint16_t j = 0; j < i; ++j)
            if (!memcmp(s_working[i].bssid, s_working[j].bssid, 6)) return false;
    }
    return true;
}

static void terminal(char *line, const char *status, int32_t found, uint16_t sent, const char *code)
{
    int n = wfa_format_end(line, WFA_LINE_CAPACITY, s_boot, s_scan, status, found, sent,
                           now_ms() - s_started_ms, code);
    if (!emit_line(line, n)) set_error("tx_failed");
}

static void analyzer_worker(void *unused)
{
    (void)unused;
    /* The creator publishes our handle before letting us run. */
    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    char line[WFA_LINE_CAPACITY];
    const char *status = "error", *error = NULL;
    uint16_t found = 0, count = 0, sent = 0;
    bool fault = false, list_owned = false, began = false;
    int n = wfa_format_begin(line, sizeof(line), s_boot, s_scan, &s_options, s_started_ms);
    if (!emit_line(line, n)) { error = "tx_failed"; goto finish; }
    began = true;
    if (cancelled()) { status = "cancelled"; error = "stopped"; goto finish; }

    portENTER_CRITICAL(&s_lock);
    s_state = WFA_SCANNING;
    s_armed = true;
    s_done = false;
    portEXIT_CRITICAL(&s_lock);
    esp_err_t scan_err = esp_wifi_scan_start(&s_scan_config, false);
    if (scan_err != ESP_OK) { error = "scan_start_failed"; goto finish; }
    list_owned = true;
    uint64_t deadline = now_ms() + wfa_scan_deadline_ms(&s_options);
    while (!scan_done(NULL) && !cancelled() && now_ms() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (cancelled() || !scan_done(NULL)) {
        status = cancelled() ? "cancelled" : "timeout";
        error = cancelled() ? "stopped" : "scan_timeout";
        set_state(WFA_CANCELLING);
        if (!scan_done(NULL)) (void)esp_wifi_scan_stop();
        uint64_t stop_deadline = now_ms() + WFA_CANCEL_GRACE_MS;
        while (!scan_done(NULL) && now_ms() < stop_deadline) vTaskDelay(pdMS_TO_TICKS(20));
        if (!scan_done(NULL)) {
            set_error("radio_fault");
            set_state(WFA_QUARANTINED);
            terminal(line, status, -1, 0, "radio_fault");
            began = false;  /* One terminal only, even if the event arrives later. */
            while (!scan_done(NULL)) vTaskDelay(pdMS_TO_TICKS(100));
        }
        goto finish;
    }
    uint32_t driver_status;
    (void)scan_done(&driver_status);
    if (driver_status != 0) { error = "scan_failed"; goto finish; }
    set_state(WFA_COLLECTING);
    if (esp_wifi_scan_get_ap_num(&found) != ESP_OK) { error = "records_failed"; goto finish; }
    count = found < s_options.limit ? found : s_options.limit;
    if (count) {
        uint16_t retrieved = count;
        if (esp_wifi_scan_get_ap_records(&retrieved, s_working) != ESP_OK) {
            error = "records_failed"; goto finish;
        }
        list_owned = false;  /* IDF bulk retrieval released its complete list. */
        if (retrieved != count || !validate_records(count)) { error = "invalid_record"; goto finish; }
    } else {
        if (esp_wifi_clear_ap_list() != ESP_OK) { error = "records_failed"; goto finish; }
        list_owned = false;
    }
    if (!restore_radio()) { error = "restore_failed"; fault = true; goto finish; }
    set_state(WFA_PUBLISHING);
    uint32_t baud = s_hooks.baud_rate ? s_hooks.baud_rate() : 115200U;
    if (!baud) baud = 115200U;
    uint64_t tx_deadline = now_ms() + 5000U +
        ((uint64_t)(count + 1U) * (WFA_MAX_LINE_BYTES + 3U) * 10000U + baud - 1U) / baud;
    for (uint16_t i = 0; i < count; ++i) {
        if (cancelled()) { status = "cancelled"; error = "stopped"; goto finish; }
        if (now_ms() >= tx_deadline) { status = "timeout"; error = "tx_timeout"; goto finish; }
        wfa_ap_t ap;
        normalize_ap(&s_working[i], &ap);
        n = wfa_format_ap(line, sizeof(line), s_boot, s_scan, i, &ap);
        if (n < 0) { error = "invalid_record"; goto finish; }
        if (!emit_line(line, n)) { error = "tx_failed"; goto finish; }
        ++sent;
        vTaskDelay(1);
    }
    if (cancelled()) { status = "cancelled"; error = "stopped"; goto finish; }
    if (now_ms() >= tx_deadline) { status = "timeout"; error = "tx_timeout"; goto finish; }
    n = wfa_format_end(line, sizeof(line), s_boot, s_scan, "ok", found, sent,
                       now_ms() - s_started_ms, NULL);
    began = false;  /* Never append a second terminal after a possibly partial end. */
    if (!emit_line(line, n)) { error = "tx_failed"; goto finish; }
    wifi_ap_record_t *old = s_committed;
    s_committed = s_working;
    s_working = old;
    portENTER_CRITICAL(&s_lock);
    s_last_count = count;
    s_last_success = s_scan;
    s_last_error = NULL;
    portEXIT_CRITICAL(&s_lock);
    release(false);
    vTaskDelete(NULL);
    return;

finish:
    if (list_owned && esp_wifi_clear_ap_list() != ESP_OK) {
        fault = true;
        error = "radio_fault";
    }
    if (!restore_radio()) { fault = true; error = "restore_failed"; }
    set_error(error ? error : "scan_failed");
    if (began) terminal(line, status, -1, sent, error ? error : "scan_failed");
    release(fault);
    vTaskDelete(NULL);
}

bool wifi_analyzer_stop(uint32_t timeout_ms)
{
    portENTER_CRITICAL(&s_lock);
    bool busy = s_state != WFA_IDLE;
    if (busy) s_cancel = true;
    portEXIT_CRITICAL(&s_lock);
    if (!busy) return true;
    uint64_t deadline = now_ms() + timeout_ms;
    while (wifi_analyzer_busy() && now_ms() < deadline) vTaskDelay(pdMS_TO_TICKS(20));
    return !wifi_analyzer_busy();
}

static void show_status(void)
{
    char line[640], active[24], last[24], error[80];
    portENTER_CRITICAL(&s_lock);
    wfa_state_t state = s_state;
    uint32_t scan = s_scan, success = s_last_success;
    const char *last_error = s_last_error;
    size_t bytes = s_psram_bytes;
    uint16_t capacity = s_capacity;
    uint8_t driver_id = s_driver_scan_id;
    portEXIT_CRITICAL(&s_lock);
    /* Preparation can quarantine the radio before the first scan is admitted. */
    if (state == WFA_IDLE || scan == 0) strcpy(active, "null");
    else snprintf(active, sizeof(active), "%" PRIu32, scan);
    if (!success) strcpy(last, "null");
    else snprintf(last, sizeof(last), "%" PRIu32, success);
    if (!last_error) strcpy(error, "null");
    else snprintf(error, sizeof(error), "\"%s\"", last_error);
    int n = snprintf(line, sizeof(line),
        "[WFACTL1] {\"v\":1,\"type\":\"status\",\"state\":\"%s\",\"boot\":\"%s\","
        "\"active_scan\":%s,\"last_success_scan\":%s,\"last_error\":%s,\"psram_bytes\":%u,"
        "\"capacity\":%u,\"driver_scan_id\":%u}\n",
        state_name(state), s_boot, active, last, error, (unsigned)bytes,
        (unsigned)capacity, (unsigned)driver_id);
    if (n > 0 && (size_t)n < sizeof(line)) (void)emit_line(line, n);
}

int wifi_analyzer_command(int argc, char **argv)
{
    if (!s_initialized) { control_error("wifi_analyzer", "unavailable", NULL); return 1; }
    if (argc < 2) { control_error("wifi_analyzer", "invalid_argument", "expected_subcommand"); return 1; }
    if (!strcmp(argv[1], "caps") && argc == 2) {
        static const char caps[] =
            "[WFACTL1] {\"v\":1,\"type\":\"caps\",\"protocol\":\"WFA/1\","
            "\"default_records\":64,\"max_records\":128,\"max_line_bytes\":1024,"
            "\"bands\":[\"2.4\",\"5\"],\"profiles\":[\"quick\",\"detailed\",\"passive\"],"
            "\"width_metadata\":\"sdk_unverified\",\"channel_scope\":\"requested_driver_filtered\"}\n";
        return emit_line(caps, (int)sizeof(caps) - 1) ? 0 : 1;
    }
    if (!strcmp(argv[1], "status") && argc == 2) { show_status(); return 0; }
    if (!strcmp(argv[1], "stop") && argc == 2) {
        if (!wifi_analyzer_stop(5000)) { control_error("stop", "radio_fault", "not_quiescent"); return 1; }
        static const char stopped[] = "[WFACTL1] {\"v\":1,\"type\":\"stopped\",\"state\":\"idle\"}\n";
        return emit_line(stopped, (int)sizeof(stopped) - 1) ? 0 : 1;
    }
    if (!strcmp(argv[1], "clear") && argc == 2) {
        if (wifi_analyzer_busy()) { control_error("clear", "busy", "wifi_analyzer"); return 1; }
        heap_caps_free(s_working);
        heap_caps_free(s_committed);
        s_working = s_committed = NULL;
        portENTER_CRITICAL(&s_lock);
        s_capacity = s_last_count = 0;
        s_psram_bytes = 0;
        s_last_success = 0;
        s_last_error = NULL;
        portEXIT_CRITICAL(&s_lock);
        static const char cleared[] = "[WFACTL1] {\"v\":1,\"type\":\"cleared\",\"state\":\"idle\"}\n";
        return emit_line(cleared, (int)sizeof(cleared) - 1) ? 0 : 1;
    }
    if (strcmp(argv[1], "scan")) { control_error("wifi_analyzer", "invalid_argument", "unknown_or_extra_arguments"); return 1; }
    wfa_options_t options;
    const char *reason = NULL;
    if (!wfa_parse_scan_args(argc, argv, &options, &reason)) {
        control_error("scan", "invalid_argument", reason); return 1;
    }
    if (wifi_analyzer_busy()) { control_error("scan", "busy", "wifi_analyzer"); return 1; }
    if (s_scan == UINT32_MAX) { control_error("scan", "radio_fault", "scan_id_exhausted"); return 1; }
    reason = s_hooks.busy_reason ? s_hooks.busy_reason() : "missing_host_hooks";
    if (reason) { control_error("scan", "busy", reason); return 1; }
    if (!reserve()) { control_error("scan", "busy", "wifi_analyzer"); return 1; }
    s_options = options;
    s_saved_radio = false;
    const char *error = NULL;
    if (!allocate_buffers(options.limit)) error = "no_psram";
    else if (!s_hooks.prepare_wifi || s_hooks.prepare_wifi() != ESP_OK) error = "wifi_init_failed";
    else {
        wifi_mode_t mode;
        wifi_ap_record_t connected;
        bool promiscuous = false;
        if (esp_wifi_get_mode(&mode) != ESP_OK || mode != WIFI_MODE_STA ||
            esp_wifi_sta_get_ap_info(&connected) == ESP_OK ||
            esp_wifi_get_promiscuous(&promiscuous) != ESP_OK || promiscuous) error = "radio_busy";
        else error = configure_scan();
    }
    if (error) {
        bool restored = restore_radio();
        set_error(restored ? error : "restore_failed");
        release(!restored);
        const char *code = !restored ? "restore_failed" :
                           !strcmp(error, "radio_busy") ? "busy" : error;
        control_error("scan", code, restored ? error : "restore_failed");
        return 1;
    }
    s_started_ms = now_ms();
    portENTER_CRITICAL(&s_lock);
    ++s_scan;
    portEXIT_CRITICAL(&s_lock);
    TaskHandle_t worker = NULL;
    if (xTaskCreate(analyzer_worker, "wifi_analyzer", WFA_STACK_BYTES, NULL, 4, &worker) != pdPASS) {
        bool restored = restore_radio();
        set_error(restored ? "no_internal_memory" : "restore_failed");
        release(!restored);
        control_error("scan", restored ? "no_internal_memory" : "restore_failed", NULL);
        return 1;
    }
    portENTER_CRITICAL(&s_lock);
    s_worker = worker;
    portEXIT_CRITICAL(&s_lock);
    xTaskNotifyGive(worker);
    return 0;
}
