/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdk.h"
#include "janos_wps_transport.h"

/* JanOS borrows an initialized, running driver. No path may destroy it. */
static bool initialized = true, started = true, ignore_restore_write;
static char failure, second_failure, fail_once;
static unsigned init_calls, deinit_calls, completed, callback_installs, callback_clears;
static struct wps_funcs *installed;
static const uint8_t original[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
static uint8_t current_mac[6] = {0x02, 1, 2, 3, 4, 5};
static size_t leak_per_cycle;

static int operation(char code)
{
    if (fail_once == code) { fail_once = 0; return ESP_FAIL; }
    return failure == code || second_failure == code ? ESP_FAIL : ESP_OK;
}

esp_err_t esp_wifi_init(const wifi_init_config_t *config)
{ (void)config; init_calls++; return ESP_ERR_INVALID_STATE; }
esp_err_t esp_wifi_deinit(void)
{ deinit_calls++; return ESP_ERR_INVALID_STATE; }
esp_err_t esp_wifi_set_storage(int storage)
{ assert(storage == WIFI_STORAGE_RAM && !started); return operation('R'); }
esp_err_t esp_wifi_set_mode(int mode)
{ assert(mode == WIFI_MODE_STA && !started); return operation('O'); }
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
    assert(wps_transport_cleanup_pending(&transport));
    assert(context.borrowed && context.driver_running && !context.restore_verified);
    assert(!installed && init_calls == 0 && deinit_calls == 0);
    failure = 0;
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
}

int main(int argc, char **argv)
{
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
