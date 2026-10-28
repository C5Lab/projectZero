/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdk.h"
#include "janos_wps_transport.h"
#include "lab_radio.h"

/* JanOS borrows an initialized, running driver. No path may destroy it. */
static bool initialized = true, started = true, ignore_restore_write;
static char failure, second_failure, fail_once;
static unsigned init_calls, deinit_calls, completed, callback_installs, callback_clears;
static struct wps_funcs *installed;
static const uint8_t original[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
static uint8_t current_mac[6] = {0x02, 1, 2, 3, 4, 5};
static size_t leak_per_cycle;
static wifi_storage_t storage = WIFI_STORAGE_FLASH;
static wifi_mode_t mode = WIFI_MODE_STA;
static wifi_config_t station_config;
_Static_assert(offsetof(wifi_config_t, sta.bssid) == 101U,
               "host BSSID layout must match IDF 6.0.1");
_Static_assert(sizeof(wifi_config_t) == 184U,
               "host config size must match IDF 6.0.1");
static uint8_t primary = 11;
static wifi_second_chan_t secondary = WIFI_SECOND_CHAN_ABOVE;
static char trace[8192];
static size_t trace_length;
static char wrong_field;
static bool allocation_failure;
static size_t snapshot_size;
static unsigned snapshot_allocations, snapshot_wipes;
static bool canonical_prepare;
static bool preserve_disabled_bssid;
static wifi_config_t *last_config_output;
static char last_esp_error_log[200];
static char all_esp_error_logs[1024];
static size_t all_esp_error_logs_length;
static unsigned esp_error_log_count;

void test_esp_log_error(const char *tag, const char *format, ...)
{
    assert(strcmp(tag, "WPS_RESTORE") == 0);
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(last_esp_error_log, sizeof(last_esp_error_log),
                            format, arguments);
    va_end(arguments);
    assert(written > 0 && (size_t)written < sizeof(last_esp_error_log));
    assert(all_esp_error_logs_length + (size_t)written + 2U <
           sizeof(all_esp_error_logs));
    memcpy(all_esp_error_logs + all_esp_error_logs_length,
           last_esp_error_log, (size_t)written);
    all_esp_error_logs_length += (size_t)written;
    all_esp_error_logs[all_esp_error_logs_length++] = '\n';
    all_esp_error_logs[all_esp_error_logs_length] = '\0';
    esp_error_log_count++;
}

static int operation(char code)
{
    if (trace_length + 1U < sizeof(trace)) {
        trace[trace_length++] = code;
        trace[trace_length] = 0;
    }
    if (fail_once == code) { fail_once = 0; return ESP_FAIL; }
    return failure == code || second_failure == code ? ESP_FAIL : ESP_OK;
}

esp_err_t esp_wifi_init(const wifi_init_config_t *config)
{ (void)config; init_calls++; initialized = true; storage = WIFI_STORAGE_FLASH; return ESP_OK; }
esp_err_t esp_wifi_deinit(void)
{ assert(!started); deinit_calls++; initialized = false; return ESP_OK; }
esp_err_t esp_wifi_set_storage(int value)
{ int result = operation(value == WIFI_STORAGE_RAM ? 'R' : 'F');
  if (!result) storage = value;
  return result; }
esp_err_t esp_wifi_set_mode(int value)
{ assert(!started); int result = operation('O');
  if (!result) mode = value;
  return result; }
esp_err_t esp_wifi_get_mode(wifi_mode_t *out)
{ int result = operation('o'); if (!result) *out = wrong_field == 'o' ? WIFI_MODE_AP : mode; return result; }
esp_err_t esp_wifi_get_config(int interface, wifi_config_t *out)
{ assert(interface == WIFI_IF_STA); int result = operation('g');
  if (!result) *out = station_config;
  last_config_output = out;
  if (!result && (wrong_field == 'g' || wrong_field == 'm'))
      out->sta.password[0] ^= 1;
  if (!result && wrong_field == 's') out->sta.ssid[0] ^= 1;
  if (!result && wrong_field == 'B') out->sta.bssid[0] ^= 1;
  if (!result && wrong_field == 'f') out->sta.bssid_set = !out->sta.bssid_set;
  if (!result && (wrong_field == 'b' || wrong_field == 'm'))
      out->bytes[183] ^= 1;
  return result; }
esp_err_t esp_wifi_set_config(int interface, wifi_config_t *value)
{ assert(interface == WIFI_IF_STA && !started &&
         (storage == WIFI_STORAGE_RAM || canonical_prepare));
  int result = operation('K');
  if (!result) {
      uint8_t previous_bssid[6];
      memcpy(previous_bssid, station_config.sta.bssid, sizeof(previous_bssid));
      station_config = *value;
      if (preserve_disabled_bssid && !station_config.sta.bssid_set)
          memcpy(station_config.sta.bssid, previous_bssid,
                 sizeof(previous_bssid));
  }
  return result; }
esp_err_t esp_wifi_get_channel(uint8_t *out, wifi_second_chan_t *second)
{ assert(started); int result = operation('h');
  if (!result) { *out = primary; *second = secondary;
    if (wrong_field == 'h') (*out)++;
    if (wrong_field == 'j') *second ^= 1;
  } return result; }
esp_err_t esp_wifi_set_channel(uint8_t value, wifi_second_chan_t second)
{ assert(started); int result = operation('H');
  if (!result) { primary = value; secondary = second; } return result; }
void *heap_caps_calloc(size_t count, size_t size, unsigned caps)
{
    assert(caps == (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    if (allocation_failure) return NULL;
    snapshot_size = count * size;
    snapshot_allocations++;
    return calloc(count, size);
}
void heap_caps_free(void *memory)
{
    const unsigned char *bytes = memory;
    for (size_t i = 0; i < snapshot_size; ++i) assert(bytes[i] == 0);
    snapshot_wipes++;
    free(memory);
}
esp_err_t esp_wifi_start(void)
{
    assert(initialized && !started);
    if (operation('S')) return ESP_FAIL;
    started = true;
    if (memcmp(current_mac, original, 6) == 0) completed++;
    return ESP_OK;
}
esp_err_t esp_wifi_stop(void)
{
    assert(initialized && started);
    if (operation('s')) return ESP_FAIL;
    started = false;
    return ESP_OK;
}
esp_err_t esp_wifi_set_mac(int interface, const uint8_t *mac)
{
    assert(interface == WIFI_IF_STA && initialized && !started);
    if (operation('M')) return ESP_FAIL;
    if (!(ignore_restore_write && memcmp(mac, original, 6) == 0))
        memcpy(current_mac, mac, 6);
    return ESP_OK;
}
esp_err_t esp_wifi_get_mac(int interface, uint8_t *mac)
{
    assert(interface == WIFI_IF_STA && initialized);
    if (operation('G')) return ESP_FAIL;
    memcpy(mac, current_mac, 6);
    if (wrong_field == 'G') mac[5] ^= 1;
    return ESP_OK;
}
esp_err_t esp_wifi_set_wps_cb_internal(struct wps_funcs *callbacks)
{
    if (operation(callbacks ? 'C' : 'c')) return ESP_FAIL;
    free(installed);
    installed = callbacks;
    if (callbacks) callback_installs++;
    else callback_clears++;
    return ESP_OK;
}
esp_err_t esp_wifi_set_appie_internal(uint8_t type, uint8_t *ie, uint16_t length, uint8_t flags)
{ (void)type; (void)ie; (void)length; (void)flags; return operation('A'); }
esp_err_t esp_wifi_unset_appie_internal(uint8_t type)
{ (void)type; return operation('a'); }
esp_err_t esp_wifi_set_wps_start_flag_internal(bool enabled)
{ return operation(enabled ? 'T' : 't'); }
esp_err_t esp_wifi_set_wps_type_internal(uint32_t type)
{ return operation(type ? 'P' : 'p'); }
esp_err_t esp_wifi_set_wps_status_internal(uint32_t status)
{ return operation(status ? 'Q' : 'q'); }
esp_err_t esp_wifi_disconnect(void)
{ return operation('D') ? ESP_FAIL : ESP_ERR_WIFI_NOT_CONNECT; }

static void borrowed_driver_and_callback_ownership(void)
{
    janos_wps_transport_context_t context = {0};
    assert(janos_wps_transport_ops.init(&context) == ESP_OK);
    assert(context.borrowed && !started);
    assert(janos_wps_transport_ops.init(&context) == ESP_ERR_INVALID_STATE);
    failure = 'C';
    assert(janos_wps_transport_ops.callbacks(&context, true) != ESP_OK);
    assert(callback_installs == 0 && !installed);
    failure = 0;
    assert(janos_wps_transport_ops.callbacks(&context, true) == ESP_OK);
    assert(installed && installed->wps_parse_scan_result(NULL) == false);
    assert(installed->wifi_station_wps_start() == ESP_OK);
    assert(installed->wps_sm_rx_eapol(NULL, NULL, 0) == ESP_OK);
    assert(installed->wps_start_pending() == ESP_OK);
    failure = 'c';
    assert(janos_wps_transport_ops.callbacks(&context, false) != ESP_OK);
    assert(callback_clears == 0 && installed);
    failure = 0;
    assert(janos_wps_transport_ops.callbacks(&context, false) == ESP_OK);
    assert(callback_installs == 1 && callback_clears == 1 && !installed);
    assert(janos_wps_transport_ops.set_mac(&context, session) == ESP_OK);
    assert(janos_wps_transport_ops.set_mac(&context, original) == ESP_OK);
    assert(janos_wps_transport_ops.deinit(&context) == ESP_OK);
    assert(context.restore_verified && !context.borrowed && started);
    assert(init_calls == 0 && deinit_calls == 0);
}

static void partial_setup_can_be_cleaned_and_retried(void)
{
    const char failures[] = "ROMSCAPQT";
    for (size_t index = 0; index < sizeof(failures) - 1; index++) {
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        failure = failures[index];
        assert(!wps_transport_begin(&transport, session, original));
        failure = 0;
        assert(wps_transport_cancel(&transport));
        assert(initialized && started && !context.borrowed && !installed);
        assert(!wps_transport_cleanup_pending(&transport));
        assert(memcmp(current_mac, original, 6) == 0);
        assert(wps_transport_begin(&transport, session, original));
        assert(wps_transport_cancel(&transport));
        assert(initialized && started && !installed);
        assert(!wps_transport_cleanup_pending(&transport));
    }
}

static void cleanup_failures_remain_retryable(void)
{
    const char failures[] = "tqpDacsMS";
    for (size_t index = 0; index < sizeof(failures) - 1; index++) {
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        assert(wps_transport_begin(&transport, session, original));
        failure = failures[index];
        assert(!wps_transport_cancel(&transport));
        assert(wps_transport_cleanup_pending(&transport));
        failure = 0;
        assert(wps_transport_cancel(&transport));
        assert(initialized && started && !context.borrowed && !installed);
        assert(memcmp(current_mac, original, 6) == 0);
        assert(!wps_transport_cleanup_pending(&transport));
    }
}

static void restores_exact_effective_mac_for_each_starting_mode(void)
{
    static const uint8_t starts[][6] = {
        {0x3c, 0xdc, 0x75, 0x85, 0xfd, 0x80},
        {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
        {0x7a, 0x10, 0x20, 0x30, 0x40, 0x50},
    };
    for (size_t mode = 0; mode < sizeof(starts) / sizeof(starts[0]); mode++) {
        memcpy(current_mac, starts[mode], 6);
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        for (unsigned attempt = 0; attempt < 2; attempt++) {
            assert(wps_transport_begin(&transport, session, starts[mode]));
            assert(wps_transport_cancel(&transport));
            assert(memcmp(current_mac, starts[mode], 6) == 0);
            assert(context.restore_verified);
            assert(memcmp(context.restored_mac, starts[mode], 6) == 0);
        }
        fail_once = 'S';
        assert(!wps_transport_begin(&transport, session, starts[mode]));
        assert(memcmp(current_mac, starts[mode], 6) == 0);
        assert(!wps_transport_cleanup_pending(&transport));
    }
    memcpy(current_mac, original, 6);
}

static void composite_setup_failure_retains_failed_cleanup(void)
{
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    failure = 'O';
    second_failure = 'S';
    assert(!wps_transport_begin(&transport, session, original));
    assert(initialized && context.borrowed && !started);
    assert(wps_transport_cleanup_pending(&transport));
    failure = second_failure = 0;
    assert(wps_transport_cancel(&transport));
    assert(initialized && started && !context.borrowed);
    failure = 'T';
    second_failure = 't';
    assert(!wps_transport_begin(&transport, session, original));
    assert(initialized && started && installed && transport.wps_enabled);
    assert(wps_transport_cleanup_pending(&transport));
    failure = second_failure = 0;
    assert(wps_transport_cancel(&transport));
    assert(initialized && started && !installed);
    assert(init_calls == 0 && deinit_calls == 0);
}

static void readback_failure_preserves_pending_ownership(void)
{
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    failure = 'G';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_step, "snapshot_restore") == 0);
    assert(transport.cleanup_error == ESP_FAIL);
    assert(strcmp(transport.cleanup_detail, "verify_get_mac") == 0);
    assert(wps_transport_cleanup_pending(&transport));
    assert(context.borrowed && context.driver_running && !context.restore_verified);
    assert(!installed && init_calls == 0 && deinit_calls == 0);
    failure = 0;
    assert(wps_transport_cancel(&transport));
    assert(transport.cleanup_detail == NULL);
}

/* Retained stress verdict, now a host fixture over the production adapter. */
enum { STRESS_CYCLES = 50, MAX_HEAP_LOSS = 1024, CLEANUP_ATTEMPTS = 3 };

static bool cleanup_transport(wps_transport_t *transport)
{
    bool first_try = true;
    for (unsigned attempt = 0; attempt < CLEANUP_ATTEMPTS; attempt++) {
        if (wps_transport_cancel(transport)) return first_try;
        first_try = false;
    }
    return false;
}

static size_t free_heap(void) { return 100000U - completed * leak_per_cycle; }

static void run_stress(void)
{
    size_t heap_baseline = free_heap();
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    unsigned cycles = 0, mac_restores = 0;
    bool begin_failed = false, mac_restored = false;
    for (unsigned cycle = 0; cycle < STRESS_CYCLES; cycle++) {
        if (!wps_transport_begin(&transport, session, original)) {
            begin_failed = true;
            break;
        }
        if (!cleanup_transport(&transport)) break;
        mac_restored = context.restore_verified &&
                       memcmp(context.restored_mac, original, 6) == 0;
        if (!mac_restored || wps_transport_cleanup_pending(&transport)) break;
        mac_restores++;
        cycles++;
        if (cycles == 1U) heap_baseline = free_heap();
    }
    if (begin_failed && wps_transport_cleanup_pending(&transport))
        (void)cleanup_transport(&transport);
    mac_restored = context.restore_verified &&
                   memcmp(context.restored_mac, original, 6) == 0;
    size_t heap_after = free_heap();
    size_t heap_loss = heap_after < heap_baseline ? heap_baseline - heap_after : 0U;
    bool ok = cycles == STRESS_CYCLES && callback_installs == STRESS_CYCLES &&
              callback_clears == STRESS_CYCLES && mac_restores == STRESS_CYCLES &&
              mac_restored && !wps_transport_cleanup_pending(&transport) &&
              heap_loss <= MAX_HEAP_LOSS && init_calls == 0 && deinit_calls == 0;
    printf("{\"stage\":\"transport_stress\",\"ok\":%s,\"cycles\":%u,"
           "\"callback_installs\":%u,\"callback_clears\":%u,\"mac_restores\":%u,"
           "\"heap_baseline\":%u,\"heap_after\":%u,\"heap_loss\":%u,"
           "\"heap_loss_limit\":%u,\"mac_restored\":%s,\"cleanup_pending\":%s}\n",
           ok ? "true" : "false", cycles, callback_installs, callback_clears,
           mac_restores, (unsigned)heap_baseline, (unsigned)heap_after,
           (unsigned)heap_loss, MAX_HEAP_LOSS, mac_restored ? "true" : "false",
           wps_transport_cleanup_pending(&transport) ? "true" : "false");
    printf("{\"result\":\"%s\",\"done\":true}\n",
           ok ? "transport_stress_verified" : "transport_stress_failed");
    janos_wps_transport_reset(&context);
}

static void exact_baseline_restore(void)
{
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    memset(&station_config, 0x5a, sizeof(station_config));
    wifi_config_t baseline = station_config;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    memset(&station_config, 0x33, sizeof(station_config));
    primary = 6;
    secondary = WIFI_SECOND_CHAN_NONE;
    assert(wps_transport_cancel(&transport));
    assert(storage == WIFI_STORAGE_FLASH);
    assert(mode == WIFI_MODE_STA);
    assert(memcmp(&baseline, &station_config, sizeof(baseline)) == 0);
    assert(primary == 11 && secondary == WIFI_SECOND_CHAN_ABOVE);
    assert(context.restore_verified && !context.snapshot);
    assert(strstr(trace, "ROKMSHFoghG") != NULL);
}

static void reset_baseline(void)
{
    failure = second_failure = fail_once = wrong_field = 0;
    allocation_failure = ignore_restore_write = preserve_disabled_bssid = false;
    assert(started);
    assert(janos_wps_wifi_set_storage(WIFI_STORAGE_FLASH) == ESP_OK);
    mode = WIFI_MODE_STA;
    memset(&station_config, 0x5a, sizeof(station_config));
    primary = 11;
    secondary = WIFI_SECOND_CHAN_ABOVE;
    memcpy(current_mac, original, 6);
    trace_length = 0;
    trace[0] = 0;
    last_esp_error_log[0] = 0;
    all_esp_error_logs[0] = 0;
    all_esp_error_logs_length = 0;
    esp_error_log_count = 0;
}

static void wps_disable_failure_identifies_private_call(void)
{
    const char failures[] = "tpq";
    const char *details[] = {"wps_start_flag", "wps_type", "wps_status"};
    for (size_t i = 0; i < sizeof(failures) - 1U; ++i) {
        reset_baseline();
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        assert(wps_transport_begin(&transport, session, original));
        failure = failures[i];
        assert(!wps_transport_cancel(&transport));
        assert(strcmp(transport.cleanup_step, "wps_disable") == 0);
        assert(strcmp(transport.cleanup_detail, details[i]) == 0);
        assert(transport.cleanup_error == ESP_FAIL);
        failure = 0;
        assert(wps_transport_cancel(&transport));
        assert(transport.cleanup_step == NULL && transport.cleanup_detail == NULL);
    }
}

static void snapshot_fault_matrix(void)
{
    /* Missing snapshot getters must never authorize a MAC-only cleanup. */
    const char getters[] = "oghG";
    for (size_t i = 0; i < sizeof(getters) - 1U; ++i) {
        reset_baseline();
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        failure = getters[i];
        assert(!wps_transport_begin(&transport, session, original));
        assert(wps_transport_cleanup_pending(&transport));
        assert(!context.restore_verified && !context.snapshot);
        assert(strchr(trace, 's') == NULL && strchr(trace, 'R') == NULL);
        failure = 0;
        assert(!wps_transport_cancel(&transport));
        janos_wps_transport_reset(&context);
        assert(!wps_transport_cancel(&transport));
    }
    reset_baseline();
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    allocation_failure = true;
    assert(!wps_transport_begin(&transport, session, original));
    assert(wps_transport_cleanup_pending(&transport));
    assert(trace_length == 0 && !context.snapshot);
    janos_wps_transport_reset(&context);
    allocation_failure = false;
}

static void restore_fault_and_readback_matrix(void)
{
    const char failures[] = "sROKMSHFoghG";
    const char *steps[] = {
        "wifi_stop", "snapshot_restore", "snapshot_restore",
        "snapshot_restore", "mac_restore", "snapshot_restore",
        "snapshot_restore", "snapshot_restore", "snapshot_restore",
        "snapshot_restore", "snapshot_restore", "snapshot_restore",
    };
    const char *details[] = {
        NULL, "restore_ram", "restore_mode", "restore_config", NULL,
        "restore_start", "restore_channel", "restore_storage",
        "verify_get_mode", "verify_get_config", "verify_get_channel",
        "verify_get_mac",
    };
    for (size_t i = 0; i < sizeof(failures) - 1U; ++i) {
        reset_baseline();
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        assert(wps_transport_begin(&transport, session, original));
        memset(&station_config, 0x33, sizeof(station_config));
        primary = 6;
        failure = failures[i];
        assert(!wps_transport_cancel(&transport));
        assert(strcmp(transport.cleanup_step, steps[i]) == 0);
        if (details[i]) assert(strcmp(transport.cleanup_detail, details[i]) == 0);
        else assert(transport.cleanup_detail == NULL);
        assert(transport.cleanup_error == ESP_FAIL);
        assert(wps_transport_cleanup_pending(&transport));
        assert(context.borrowed && context.snapshot && !context.restore_verified);
        failure = 0;
        assert(wps_transport_cancel(&transport));
        assert(transport.cleanup_step == NULL && transport.cleanup_detail == NULL);
        assert(transport.cleanup_error == 0);
        assert(context.restore_verified && !context.snapshot);
        assert(storage == WIFI_STORAGE_FLASH && started);
        assert(primary == 11 && station_config.sta.password[0] == 0x5a);
    }
    const char wrong[] = "ogbhjGsm";
    for (size_t i = 0; i < sizeof(wrong) - 1U; ++i) {
        reset_baseline();
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        assert(wps_transport_begin(&transport, session, original));
        wrong_field = wrong[i];
        assert(!wps_transport_cancel(&transport));
        if (wrong[i] == 'g')
            assert(strcmp(last_esp_error_log,
                           "verify_config ssid_changed=0 password_changed=1 other_count=0 size=184") == 0);
        else if (wrong[i] == 'b')
            assert(strcmp(last_esp_error_log,
                           "verify_config ssid_changed=0 password_changed=0 other_first=183 other_last=183 other_count=1 size=184") == 0);
        else if (wrong[i] == 's')
            assert(strcmp(last_esp_error_log,
                           "verify_config ssid_changed=1 password_changed=0 other_count=0 size=184") == 0);
        else if (wrong[i] == 'm')
            assert(strcmp(last_esp_error_log,
                           "verify_config ssid_changed=0 password_changed=1 other_first=183 other_last=183 other_count=1 size=184") == 0);
        else
            assert(last_esp_error_log[0] == 0);
        assert(strcmp(transport.cleanup_step, "snapshot_restore") == 0);
        assert(strcmp(transport.cleanup_detail,
                      wrong[i] == 'o' ? "verify_mode" :
                      wrong[i] == 'G' ? "verify_mac" :
                      wrong[i] == 'h' || wrong[i] == 'j' ?
                          "verify_channel" : "verify_config") == 0);
        assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
        assert(context.snapshot && context.driver_running);
        const unsigned char *readback = (const unsigned char *)last_config_output;
        for (size_t byte = 0; byte < sizeof(*last_config_output); ++byte)
            assert(readback[byte] == 0);
        wrong_field = 0;
        assert(wps_transport_cancel(&transport));
        assert(context.restore_verified && !context.snapshot);
    }
}

static void restore_retries_identify_internal_stop_and_mac_failures(void)
{
    reset_baseline();
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    wrong_field = 'g';
    assert(!wps_transport_cancel(&transport));
    wrong_field = 0;
    failure = 's';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_step, "snapshot_restore") == 0);
    assert(strcmp(transport.cleanup_detail, "restore_stop") == 0);
    assert(transport.cleanup_error == ESP_FAIL);
    failure = 0;
    assert(wps_transport_cancel(&transport));
    assert(transport.cleanup_detail == NULL);

    reset_baseline();
    context = (janos_wps_transport_context_t){0};
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    failure = 'K';
    assert(!wps_transport_cancel(&transport));
    failure = 'M';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_step, "snapshot_restore") == 0);
    assert(strcmp(transport.cleanup_detail, "restore_mac") == 0);
    assert(transport.cleanup_error == ESP_FAIL);
    failure = 0;
    assert(wps_transport_cancel(&transport));
    assert(transport.cleanup_detail == NULL);
}

static void config_failure_logs_no_secret_values(void)
{
    static const char secret_ssid[] = "LAB_SSID_SENTINEL_47";
    static const char secret_password[] = "LAB_PASSWORD_SENTINEL_9247";
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    memcpy(station_config.sta.ssid, secret_ssid, sizeof(secret_ssid));
    memcpy(station_config.sta.password, secret_password,
           sizeof(secret_password));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    wrong_field = 'm';
    assert(!wps_transport_cancel(&transport));
    assert(esp_error_log_count == 1U);
    assert(strstr(all_esp_error_logs, secret_ssid) == NULL);
    assert(strstr(all_esp_error_logs, secret_password) == NULL);
    assert(strstr(all_esp_error_logs,
                  "ssid_changed=0 password_changed=1") != NULL);
    assert(strcmp(transport.cleanup_detail, "verify_config") == 0);
    wrong_field = 0;
    assert(wps_transport_cancel(&transport));
    assert(esp_error_log_count == 1U);
}

static void inactive_bssid_payload_does_not_hold_radio(void)
{
    static const uint8_t target[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    station_config.sta.bssid_set = true;
    memcpy(station_config.sta.bssid, target, sizeof(target));
    preserve_disabled_bssid = true;
    assert(wps_transport_cancel(&transport));
    assert(context.restore_verified && !context.snapshot);
    assert(!wps_transport_cleanup_pending(&transport));
    assert(!station_config.sta.bssid_set);
    assert(memcmp(station_config.sta.bssid, target, sizeof(target)) == 0);
    assert(last_esp_error_log[0] == 0);
}

static void inactive_bssid_does_not_mask_another_restore_mismatch(void)
{
    static const uint8_t target[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    station_config.sta.bssid_set = true;
    memcpy(station_config.sta.bssid, target, sizeof(target));
    preserve_disabled_bssid = true;
    wrong_field = 'b';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_detail, "verify_config") == 0);
    assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
    assert(strcmp(last_esp_error_log,
                  "verify_config ssid_changed=0 password_changed=0 "
                  "other_first=183 other_last=183 other_count=1 size=184") == 0);
    wrong_field = 0;
    assert(wps_transport_cancel(&transport));
    assert(context.restore_verified && !context.snapshot);
}

static void active_bssid_restores_exactly(void)
{
    static const uint8_t target[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    station_config.sta.bssid_set = true;
    memcpy(station_config.sta.bssid, target, sizeof(target));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    memset(station_config.sta.bssid, 0xee, sizeof(target));
    assert(wps_transport_cancel(&transport));
    assert(context.restore_verified && !context.snapshot);
    assert(station_config.sta.bssid_set);
    assert(memcmp(station_config.sta.bssid, target, sizeof(target)) == 0);
}

static void active_bssid_mismatch_holds_radio(void)
{
    static const uint8_t target[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    station_config.sta.bssid_set = true;
    memcpy(station_config.sta.bssid, target, sizeof(target));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    wrong_field = 'B';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_detail, "verify_config") == 0);
    assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
    wrong_field = 0;
    assert(wps_transport_cancel(&transport));
}

static void bssid_selector_change_holds_radio(void)
{
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    wrong_field = 'f';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_detail, "verify_config") == 0);
    assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
    wrong_field = 0;
    assert(wps_transport_cancel(&transport));
}

static void inactive_bssid_other_mismatch_holds_radio(void)
{
    reset_baseline();
    memset(&station_config, 0, sizeof(station_config));
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    wrong_field = 'b';
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_detail, "verify_config") == 0);
    assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
    wrong_field = 0;
    assert(wps_transport_cancel(&transport));
}

static void terminal_reset_wipes_without_releasing(void)
{
    reset_baseline();
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    failure = 'g';
    assert(!wps_transport_cancel(&transport));
    assert(context.snapshot);
    unsigned before = snapshot_wipes;
    janos_wps_transport_reset(&context);
    assert(snapshot_wipes == before + 1U && !context.snapshot);
    failure = 0;
    assert(!wps_transport_cancel(&transport));
    assert(strcmp(transport.cleanup_step, "snapshot_restore") == 0);
    assert(strcmp(transport.cleanup_detail, "restore_precondition") == 0);
    assert(wps_transport_cleanup_pending(&transport) && !context.restore_verified);
}

static void unsupported_baselines_are_rejected_before_mutation(void)
{
    const wifi_mode_t modes[] = {WIFI_MODE_AP, WIFI_MODE_APSTA};
    for (size_t i = 0; i < 2U; ++i) {
        reset_baseline();
        mode = modes[i];
        janos_wps_transport_context_t context = {0};
        wps_transport_t transport;
        wps_transport_init(&transport, &janos_wps_transport_ops, &context);
        assert(!wps_transport_begin(&transport, session, original));
        assert(!wps_transport_cleanup_pending(&transport));
        assert(!strcmp(trace, "o") && started && mode == modes[i]);
        assert(!context.snapshot);
    }
    reset_baseline();
    assert(janos_wps_wifi_stop() == ESP_OK);
    trace_length = 0;
    trace[0] = 0;
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(!wps_transport_begin(&transport, session, original));
    assert(!wps_transport_cleanup_pending(&transport) && !started && !trace_length);
    assert(janos_wps_wifi_start() == ESP_OK);
}

static int platform_read(void *opaque, uint8_t mac[6])
{ (void)opaque; return esp_wifi_get_mac(WIFI_IF_STA, mac); }

static void full_restore_gates_radio_owner_release(void)
{
    static const lab_platform_ops_t platform_ops = {.read_sta_mac = platform_read};
    const int outcomes[] = {0, -1, -77}; /* success, cancel, protocol timeout */
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        reset_baseline();
        janos_wps_transport_context_t context = {0};
        lab_platform_t platform;
        lab_platform_init(&platform, &platform_ops, NULL, NULL);
        lab_radio_t radio;
        lab_radio_init(&radio, &platform, &janos_wps_transport_ops, &context, original);
        uint32_t owner = 0;
        assert(lab_radio_acquire(&radio, session, 0, &owner));
        assert(lab_radio_mark_running(&radio, owner));
        if (outcomes[i] == -1) lab_radio_cancel(&radio, owner);
        memset(&station_config, 0x33, sizeof(station_config));
        primary = 6;
        /* MAC can be correct while config readback fails: ownership must stay. */
        wrong_field = 'g';
        lab_radio_result_t result = lab_radio_release(&radio, outcomes[i]);
        assert(!result.cleanup_ok && result.quarantined);
        assert(strcmp(radio.cleanup_diag.step, "snapshot_restore") == 0);
        assert(strcmp(radio.cleanup_diag.detail, "verify_config") == 0);
        assert(strcmp(radio.cleanup_diag.error_domain, "esp") == 0);
        assert(radio.cleanup_diag.error == ESP_ERR_INVALID_STATE);
        assert(memcmp(current_mac, original, 6) == 0);
        assert(radio.owner_token == owner && lab_radio_is_quarantined(&radio));
        assert(!context.restore_verified && context.snapshot);
        wrong_field = 0;
        result = lab_radio_release(&radio, outcomes[i]);
        assert(result.cleanup_ok && !result.quarantined);
        assert(radio.cleanup_diag.step == NULL);
        assert(result.workflow_result == outcomes[i]);
        assert(radio.owner_token == 0 && context.restore_verified && !context.snapshot);
        assert(started && storage == WIFI_STORAGE_FLASH && mode == WIFI_MODE_STA);
        assert(primary == 11 && secondary == WIFI_SECOND_CHAN_ABOVE);
        assert(station_config.sta.password[0] == 0x5a);
    }
}

static void cold_prepare_then_snapshot_and_restore(void)
{
    reset_baseline();
    assert(janos_wps_wifi_stop() == ESP_OK);
    assert(janos_wps_wifi_deinit() == ESP_OK);
    assert(!initialized && !started);
    /* Models the existing host prepare hook under the WPS lease. This is
     * baseline establishment, before the borrowed transport transaction. */
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    assert(janos_wps_wifi_init(&config) == ESP_OK);
    assert(esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK);
    wifi_config_t canonical = {0};
    canonical_prepare = true;
    assert(esp_wifi_set_config(WIFI_IF_STA, &canonical) == ESP_OK);
    canonical_prepare = false;
    assert(janos_wps_wifi_start() == ESP_OK);
    trace_length = 0;
    trace[0] = 0;
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    assert(!strncmp(trace, "oghGsRO", 7));
    memset(&station_config, 0x33, sizeof(station_config));
    primary = 6;
    assert(wps_transport_cancel(&transport));
    assert(initialized && started && context.restore_verified);
    assert(storage == WIFI_STORAGE_FLASH && mode == WIFI_MODE_STA);
    assert(memcmp(&station_config, &canonical, sizeof(canonical)) == 0);
    assert(primary == 11 && secondary == WIFI_SECOND_CHAN_ABOVE);
}

static void tracked_storage_is_the_baseline_not_the_temporary_setter(void)
{
    reset_baseline();
    assert(janos_wps_wifi_set_storage(WIFI_STORAGE_RAM) == ESP_OK);
    janos_wps_transport_context_t context = {0};
    wps_transport_t transport;
    wps_transport_init(&transport, &janos_wps_transport_ops, &context);
    assert(wps_transport_begin(&transport, session, original));
    assert(wps_transport_cancel(&transport));
    assert(storage == WIFI_STORAGE_RAM && context.restore_verified);
    assert(strchr(trace, 'F') == NULL);

    reset_baseline();
    fail_once = 'R';
    assert(janos_wps_wifi_set_storage(WIFI_STORAGE_RAM) == ESP_FAIL);
    /* A failed host mutation must not change the tracked FLASH baseline. */
    assert(wps_transport_begin(&transport, session, original));
    assert(wps_transport_cancel(&transport));
    assert(storage == WIFI_STORAGE_FLASH && context.restore_verified);
}

int main(int argc, char **argv)
{
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    assert(janos_wps_wifi_init(&config) == ESP_OK);
    init_calls = 0;
    started = false;
    assert(janos_wps_wifi_start() == ESP_OK);
    completed = 0;
    if (argc == 2 && !strcmp(argv[1], "exact")) {
        reset_baseline();
        exact_baseline_restore();
        snapshot_fault_matrix();
        restore_fault_and_readback_matrix();
        restore_retries_identify_internal_stop_and_mac_failures();
        config_failure_logs_no_secret_values();
        inactive_bssid_payload_does_not_hold_radio();
        inactive_bssid_does_not_mask_another_restore_mismatch();
        active_bssid_restores_exactly();
        active_bssid_mismatch_holds_radio();
        bssid_selector_change_holds_radio();
        inactive_bssid_other_mismatch_holds_radio();
        wps_disable_failure_identifies_private_call();
        terminal_reset_wipes_without_releasing();
        unsupported_baselines_are_rejected_before_mutation();
        full_restore_gates_radio_owner_release();
        cold_prepare_then_snapshot_and_restore();
        tracked_storage_is_the_baseline_not_the_temporary_setter();
        assert(snapshot_allocations == snapshot_wipes);
        puts("PASS: exact idle-STA restore");
        return 0;
    }
    if (argc == 2) {
        if (!strcmp(argv[1], "stress-leak")) leak_per_cycle = 128U;
        else if (!strcmp(argv[1], "stress-cleanup-error")) failure = 'c';
        else if (!strcmp(argv[1], "stress-cleanup-retry")) fail_once = 'c';
        else if (!strcmp(argv[1], "stress-wrong-mac")) ignore_restore_write = true;
        else assert(!strcmp(argv[1], "stress"));
        run_stress();
        free(installed);
        assert(init_calls == 0 && deinit_calls == 0);
        return 0;
    }
    borrowed_driver_and_callback_ownership();
    partial_setup_can_be_cleaned_and_retried();
    cleanup_failures_remain_retryable();
    restores_exact_effective_mac_for_each_starting_mode();
    composite_setup_failure_retains_failed_cleanup();
    readback_failure_preserves_pending_ownership();
    puts("PASS: production ESP adapter rollback, ownership and MAC readback");
    return 0;
}
