#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lab_workflows.h"

typedef struct {
    unsigned mounts;
    unsigned unmounts;
    unsigned allocs;
    unsigned frees;
    unsigned loads;
    unsigned verifies;
    unsigned captures;
    unsigned searches;
    unsigned selftests[4];
    unsigned stored_successes;
    unsigned stored_observations;
    unsigned identity_observations;
    unsigned wiped_nonzero;
    unsigned dirty_frees;
    void *allocation;
    size_t allocation_size;
    bool mount_ok;
    bool cleanup_ok;
    wps_session_result_t capture_result;
    lab_wps_fatal_reason_t capture_fatal_reason;
    wps_session_result_t verify_results[12];
    size_t verify_result_count;
    size_t verify_result_index;
    bool verify_has_credential;
    bool pixie_found;
    bool pixie_cancelled;
    bool session_cancelled;
    uint32_t seen_modes;
    bool seen_rtl_window;
    bool cancel_pending;
    bool cancel_after_verify;
    lab_store_status_t success_store_status;
    lab_store_status_t observation_store_status;
    char seen_pins[12][9];
    char flow[32];
    size_t flow_length;
    char emitted[4096];
    size_t emitted_length;
} fixture_t;

static void capture_output(void *opaque, const char *line)
{
    fixture_t *f = opaque;
    size_t length = strlen(line);
    assert(f->emitted_length + length + 2U < sizeof(f->emitted));
    memcpy(f->emitted + f->emitted_length, line, length);
    f->emitted_length += length;
    f->emitted[f->emitted_length++] = '\n';
    f->emitted[f->emitted_length] = '\0';
}

static int mount_sd(void *opaque)
{
    fixture_t *f = opaque;
    ++f->mounts;
    return f->mount_ok ? 0 : -1;
}

static int unmount_sd(void *opaque)
{
    ++((fixture_t *)opaque)->unmounts;
    return 0;
}

static void *alloc_psram(void *opaque, size_t size)
{
    fixture_t *f = opaque;
    ++f->allocs;
    f->allocation = calloc(1, size);
    f->allocation_size = size;
    return f->allocation;
}

static void free_psram(void *opaque, void *memory)
{
    fixture_t *f = opaque;
    ++f->frees;
    const unsigned char *bytes = memory;
    for (size_t index = 0; index < f->allocation_size; ++index)
        if (bytes[index] != 0) { ++f->dirty_frees; break; }
    f->allocation = NULL;
    f->allocation_size = 0;
    free(memory);
}

static uint64_t now_ms(void *opaque)
{
    (void)opaque;
    return 1234;
}

static bool poll_cancel(void *opaque)
{
    return ((fixture_t *)opaque)->cancel_pending;
}

static const lab_platform_ops_t platform_ops = {
    .sd_mount = mount_sd,
    .sd_unmount = unmount_sd,
    .psram_alloc = alloc_psram,
    .psram_free = free_psram,
    .monotonic_ms = now_ms,
    .poll_cancel = poll_cancel,
};

static size_t load_candidates(void *opaque, const uint8_t bssid[6],
                              const char *ssid, wps_pin_candidate_t *output,
                              size_t capacity, wps_pin_query_stats_t *stats,
                              wps_pin_db_result_t *result)
{
    fixture_t *f = opaque;
    ++f->loads;
    assert(bssid[0] == 0x68);
    assert(ssid == NULL || strcmp(ssid, "LAB") == 0);
    assert(capacity >= 4);
    memset(stats, 0, sizeof(*stats));
    output[0] = (wps_pin_candidate_t){11111115U, WPS_PIN_SOURCE_BROAD, 0};
    output[1] = (wps_pin_candidate_t){22222220U, WPS_PIN_SOURCE_BROAD, 6};
    output[2] = (wps_pin_candidate_t){12345670U, WPS_PIN_SOURCE_COMMON, 0};
    output[3] = (wps_pin_candidate_t){0U, WPS_PIN_SOURCE_COMMON, 0};
    *result = WPS_PIN_DB_OK;
    return 4;
}

static lab_workflow_session_outcome_t verify_pin(
    void *opaque, const uint8_t bssid[6], const char pin[9])
{
    fixture_t *f = opaque;
    assert(bssid[0] == 0x68);
    assert(f->flow_length + 1U < sizeof(f->flow));
    f->flow[f->flow_length++] = 'V';
    f->flow[f->flow_length] = '\0';
    unsigned index = f->verifies++;
    assert(index < 12);
    assert(f->verify_result_index < f->verify_result_count);
    memcpy(f->seen_pins[index], pin, 9);
    lab_workflow_session_outcome_t out = {
        .started = true,
        .cleanup_ok = f->cleanup_ok,
        .quarantined = !f->cleanup_ok,
    };
    out.result.session_result = f->verify_results[f->verify_result_index++];
    memcpy(out.result.identity.manufacturer, "LabVendor", 10);
    memcpy(out.result.identity.model_name, "LabModel", 9);
    memcpy(out.result.identity.device_name, "LabDevice", 10);
    if (f->cancel_after_verify) f->cancel_pending = true;
    out.result.cancelled = f->session_cancelled;
    if (out.result.session_result == WPS_SESSION_SUCCESS &&
        f->verify_has_credential) {
        static const uint8_t key[] = "lab-network-key";
        memcpy(out.result.network_key, key, sizeof(key) - 1U);
        out.result.network_key_len = sizeof(key) - 1U;
        out.result.credential_present = true;
    }
    return out;
}

static lab_workflow_session_outcome_t capture_pixie(
    void *opaque, const uint8_t bssid[6], pixie_bundle_t *bundle)
{
    fixture_t *f = opaque;
    assert(bssid[0] == 0x68);
    assert(f->flow_length + 1U < sizeof(f->flow));
    f->flow[f->flow_length++] = 'C';
    f->flow[f->flow_length] = '\0';
    ++f->captures;
    memset(bundle, 0x5a, sizeof(*bundle));
    lab_workflow_session_outcome_t out = {
        .started = true, .cleanup_ok = f->cleanup_ok,
        .quarantined = !f->cleanup_ok,
    };
    out.result.session_result = f->capture_result;
    out.result.fatal_reason = f->capture_fatal_reason;
    memcpy(out.result.identity.manufacturer, "LabVendor", 10);
    memcpy(out.result.identity.model_name, "LabModel", 9);
    memcpy(out.result.identity.device_name, "LabDevice", 10);
    return out;
}

static bool recover_pixie(void *opaque, const pixie_bundle_t *bundle,
                          const pixie_options_t *options,
                          pixie_result_t *result)
{
    fixture_t *f = opaque;
    assert(f->flow_length + 1U < sizeof(f->flow));
    f->flow[f->flow_length++] = 'S';
    f->flow[f->flow_length] = '\0';
    ++f->searches;
    assert(bundle->pke[0] == 0x5a);
    f->seen_modes = options->modes;
    f->seen_rtl_window = options->rtl_window_set;
    assert(options->should_cancel != NULL);
    assert(options->yield != NULL);
    assert(options->callback_context != NULL);
    options->yield(options->callback_context);
    memset(result, 0, sizeof(*result));
    result->found = f->pixie_found;
    result->cancelled = f->pixie_cancelled ||
                        options->should_cancel(options->callback_context);
    if (result->found) memcpy(result->pin, "12345670", 9);
    return true;
}

static bool selftest(void *opaque, lab_command_kind_t kind)
{
    fixture_t *f = opaque;
    unsigned index = (unsigned)kind - (unsigned)LAB_COMMAND_SELFTEST_DB;
    assert(index < 4);
    ++f->selftests[index];
    return true;
}

static lab_store_status_t store_success(void *opaque,
                                       const lab_result_record_t *record)
{
    fixture_t *f = opaque;
    ++f->stored_successes;
    assert(record->authenticated_m7);
    assert(record->pin != NULL && strlen(record->pin) == 8);
    assert(record->network_key_len != 0);
    assert(strcmp(record->manufacturer, "LabVendor") == 0);
    return f->success_store_status;
}

static lab_store_status_t store_observation(
    void *opaque, const lab_device_observation_t *observation)
{
    fixture_t *f = opaque;
    ++f->stored_observations;
    assert(observation->reason != NULL);
    if (observation->manufacturer[0]) {
        assert(strcmp(observation->manufacturer, "LabVendor") == 0);
        ++f->identity_observations;
    }
    return f->observation_store_status;
}

static void observed_wipe(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;
    fixture_t *f = NULL;
    (void)f;
    while (length--) *bytes++ = 0;
}

static const lab_workflow_ops_t workflow_ops = {
    .load_candidates = load_candidates,
    .verify_pin = verify_pin,
    .capture_pixie = capture_pixie,
    .recover_pixie = recover_pixie,
    .selftest = selftest,
    .store_success = store_success,
    .store_observation = store_observation,
};

static lab_command_t command(lab_command_kind_t kind)
{
    lab_command_t value = {.kind = kind};
    memcpy(value.bssid, (uint8_t[]){0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40}, 6);
    return value;
}

static void execute(lab_workflows_t *workflows, lab_command_t *cmd,
                    lab_secret_vault_t *vault, uint32_t operation,
                    const char *wanted_result, const char *wanted_cleanup)
{
    const char *result = NULL;
    const char *cleanup = NULL;
    assert(lab_workflows_execute(workflows, cmd, operation, vault,
                                 &result, &cleanup));
    if (strcmp(result, wanted_result) != 0 ||
        strcmp(cleanup, wanted_cleanup) != 0)
        fprintf(stderr, "operation %u got result=%s cleanup=%s wanted=%s/%s\n",
                operation, result, cleanup, wanted_result, wanted_cleanup);
    assert(strcmp(result, wanted_result) == 0);
    assert(strcmp(cleanup, wanted_cleanup) == 0);
}

static void sd_is_always_unmounted(void)
{
    assert(lab_workflows_cleanup_succeeded("ok"));
    assert(lab_workflows_cleanup_succeeded("not_required"));
    assert(!lab_workflows_cleanup_succeeded("failed"));
    assert(!lab_workflows_cleanup_succeeded(NULL));

    fixture_t f = {.mount_ok = true, .cleanup_ok = true};
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_workflows_set_emitter(&workflows, capture_output, &f);
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_JWPS_PLAN);
    execute(&workflows, &cmd, &vault, 1, "plan_ready", "ok");
    assert(f.mounts == 1 && f.unmounts == 1);
    assert(f.allocs == 1 && f.frees == 1 && f.loads == 1);
    assert(f.dirty_frees == 0);
    assert(strstr(f.emitted, "\"type\":\"jwps_plan\"") != NULL);
    assert(strstr(f.emitted, "SENSITIVE {\"candidate\":0,\"pin\":\"11111115\"") != NULL);
    assert(strstr(f.emitted, "\"source\":\"broad\"") != NULL);

    f.mount_ok = false;
    execute(&workflows, &cmd, &vault, 2, "sd_mount_error", "not_required");
    assert(f.mounts == 2 && f.unmounts == 1);
    lab_workflows_deinit(&workflows);
}

static void campaign_decisions_and_bounds(void)
{
    fixture_t f = {
        .mount_ok = true, .cleanup_ok = true,
        .verify_results = {WPS_SESSION_PIN_REJECTED,
                           WPS_SESSION_PIN_REJECTED,
                           WPS_SESSION_SUCCESS},
        .verify_result_count = 3,
        .verify_has_credential = true,
    };
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_CAMPAIGN);
    cmd.start_index = 0;
    cmd.count = 3;
    execute(&workflows, &cmd, &vault, 11, "pin_and_m7_verified", "ok");
    assert(f.verifies == 3);
    unsigned candidates = 0U, attempts = 0U, resume = 0U;
    assert(lab_workflows_campaign_progress(&workflows, &candidates, &attempts,
                                           &resume));
    assert(candidates == 4U && attempts == 3U && resume == 2U);
    assert(strcmp(f.seen_pins[0], "11111115") == 0);
    assert(strcmp(f.seen_pins[2], "12345670") == 0);
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_AVAILABLE);

    lab_secret_erase(&vault);
    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_SETUP_LOCKED;
    cmd.start_index = 1;
    cmd.count = 3;
    execute(&workflows, &cmd, &vault, 12, "setup_locked", "ok");
    assert(f.verifies == 1);
    assert(lab_workflows_resume_index(&workflows) == 1);
    assert(lab_workflows_campaign_progress(&workflows, &candidates, &attempts,
                                           &resume));
    assert(candidates == 4U && attempts == 1U && resume == 1U);

    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_TIMEOUT;
    execute(&workflows, &cmd, &vault, 13, "campaign_paused", "ok");
    assert(f.verifies == 1 && lab_workflows_resume_index(&workflows) == 1);

    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_DISCONNECTED;
    execute(&workflows, &cmd, &vault, 131, "campaign_paused", "ok");
    assert(f.verifies == 1 && lab_workflows_resume_index(&workflows) == 1);

    f.verify_result_index = 0;
    f.verifies = 0;
    f.session_cancelled = true;
    f.verify_results[0] = WPS_SESSION_FATAL;
    execute(&workflows, &cmd, &vault, 132, "cancelled", "ok");
    assert(f.verifies == 1 && lab_workflows_resume_index(&workflows) == 1);
    f.session_cancelled = false;

    f.verify_result_index = 0;
    f.verifies = 0;
    f.cleanup_ok = false;
    f.verify_results[0] = WPS_SESSION_PIN_REJECTED;
    execute(&workflows, &cmd, &vault, 14, "pin_rejected", "failed");
    assert(f.verifies == 1 && lab_workflows_resume_index(&workflows) == 1);
    lab_workflows_deinit(&workflows);
}

static void pixie_uses_capture_search_and_fresh_verification(void)
{
    fixture_t f = {.mount_ok = true, .cleanup_ok = true, .pixie_found = true,
                   .verify_results = {WPS_SESSION_SUCCESS},
                   .verify_result_count = 1, .verify_has_credential = true};
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_workflows_set_emitter(&workflows, capture_output, &f);
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_PIXIE);
    execute(&workflows, &cmd, &vault, 21, "pixie_pin_and_m7_verified", "ok");
    assert(f.captures == 1 && f.searches == 1 && f.verifies == 1);
    assert(strcmp(f.flow, "CSV") == 0);
    assert((f.seen_modes & PIXIE_MODE_RTL819X) == 0 && !f.seen_rtl_window);
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_AVAILABLE);
    assert(strstr(f.emitted, "\"operation_id\":21") != NULL);
    assert(strstr(f.emitted, "\"stage\":\"pixie_capture_start\"") != NULL);
    assert(strstr(f.emitted, "\"stage\":\"pixie_capture\"") != NULL);
    assert(strstr(f.emitted, "\"stage\":\"pixie_done\"") != NULL);
    assert(strstr(f.emitted, "\"stage\":\"pixie_verify_attempt\"") != NULL);
    assert(strstr(f.emitted, "\"stage\":\"pixie_verify\"") != NULL);
    assert(strstr(f.emitted, "\"dropped_events\":0") != NULL);
    assert(strstr(f.emitted, "\"coalesced_m3\":0") != NULL);
    assert(strstr(f.emitted, "\"fatal_reason\":\"none\"") != NULL);

    lab_secret_erase(&vault);
    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_PIN_REJECTED;
    cmd.epoch_set = true;
    cmd.epoch = 1700000000U;
    execute(&workflows, &cmd, &vault, 22, "recovered_pin_rejected", "ok");
    assert((f.seen_modes & PIXIE_MODE_RTL819X) != 0 && f.seen_rtl_window);
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_EMPTY);

    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_TIMEOUT;
    f.verify_results[1] = WPS_SESSION_TIMEOUT;
    f.verify_results[2] = WPS_SESSION_TIMEOUT;
    f.verify_result_count = 3;
    cmd.epoch_set = false;
    execute(&workflows, &cmd, &vault, 23, "verification_timeout", "ok");
    assert(strstr(f.emitted, "\"session_result\":\"timeout\"") != NULL);

    f.pixie_cancelled = true;
    execute(&workflows, &cmd, &vault, 24, "cancelled", "ok");
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_EMPTY);

    unsigned captures_before = f.captures;
    cmd.epoch_set = true;
    cmd.epoch = 100;
    execute(&workflows, &cmd, &vault, 25, "invalid_rtl_epoch",
            "not_required");
    assert(f.captures == captures_before);
    lab_workflows_deinit(&workflows);
}

static void pixie_retries_only_fresh_transport_failures(void)
{
    fixture_t f = {
        .mount_ok = true,
        .cleanup_ok = true,
        .pixie_found = true,
        .verify_results = {WPS_SESSION_TIMEOUT, WPS_SESSION_SUCCESS},
        .verify_result_count = 2,
        .verify_has_credential = true,
    };
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_workflows_set_emitter(&workflows, capture_output, &f);
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_PIXIE);

    execute(&workflows, &cmd, &vault, 26, "pixie_pin_and_m7_verified", "ok");

    assert(f.captures == 1 && f.searches == 1 && f.verifies == 2);
    assert(strcmp(f.flow, "CSVV") == 0);
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_AVAILABLE);
    assert(strstr(f.emitted, "\"stage\":\"pixie_verify_retry\"") != NULL);

    lab_secret_erase(&vault);
    memset(f.emitted, 0, sizeof(f.emitted));
    f.emitted_length = 0;
    f.verify_result_index = 0;
    f.verifies = 0;
    f.verify_results[0] = WPS_SESSION_SETUP_LOCKED;
    f.verify_result_count = 1;
    f.verify_has_credential = false;
    execute(&workflows, &cmd, &vault, 27, "verification_setup_locked", "ok");
    assert(f.verifies == 1);
    assert(strstr(f.emitted, "pixie_verify_retry") == NULL);

    lab_secret_erase(&vault);
    lab_workflows_deinit(&workflows);
}

static void pixie_cancels_during_retry_delay(void)
{
    fixture_t f = {
        .mount_ok = true,
        .cleanup_ok = true,
        .pixie_found = true,
        .verify_results = {WPS_SESSION_TIMEOUT, WPS_SESSION_SUCCESS},
        .verify_result_count = 2,
        .cancel_after_verify = true,
    };
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_PIXIE);

    execute(&workflows, &cmd, &vault, 271, "cancelled", "ok");

    assert(f.captures == 1 && f.searches == 1 && f.verifies == 1);
    assert(strcmp(f.flow, "CSV") == 0);
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_EMPTY);
    lab_workflows_deinit(&workflows);
}

static void pixie_stops_after_capture_lock_or_cleanup_failure(void)
{
    fixture_t f = {
        .mount_ok = true,
        .cleanup_ok = true,
        .capture_result = WPS_SESSION_SETUP_LOCKED,
        .pixie_found = true,
    };
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_PIXIE);

    execute(&workflows, &cmd, &vault, 28, "capture_setup_locked", "ok");
    assert(f.captures == 1 && f.searches == 0 && f.verifies == 0);

    f.capture_result = WPS_SESSION_SUCCESS;
    f.cleanup_ok = false;
    execute(&workflows, &cmd, &vault, 29, "pixie_capture_failed", "failed");
    assert(f.captures == 2 && f.searches == 0 && f.verifies == 0);

    lab_workflows_deinit(&workflows);
}

static void known_pin_and_selftests(void)
{
    fixture_t f = {.mount_ok = true, .cleanup_ok = true,
                   .verify_results = {WPS_SESSION_SUCCESS},
                   .verify_result_count = 1, .verify_has_credential = true,
                   .success_store_status = LAB_STORE_OK,
                   .observation_store_status = LAB_STORE_OK};
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_VERIFY);
    memcpy(cmd.pin, "12345670", 9);
    execute(&workflows, &cmd, &vault, 31, "pin_and_m7_verified", "ok");
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_AVAILABLE);
    assert(f.stored_successes == 1);
    assert(strcmp(lab_workflows_storage_result(&workflows), "ok") == 0);
    lab_secret_erase(&vault);
    f.verify_result_index = 0;
    f.cleanup_ok = false;
    execute(&workflows, &cmd, &vault, 311, "pin_and_m7_verified", "failed");
    assert(lab_secret_status(&vault, 1234).state == LAB_SECRET_EMPTY);
    assert(f.stored_successes == 1);
    assert(f.stored_observations == 1);
    assert(f.identity_observations == 1);

    f.cleanup_ok = true;
    f.verify_result_index = 0;
    f.verify_results[0] = WPS_SESSION_SUCCESS;
    f.success_store_status = LAB_STORE_IO_ERROR;
    execute(&workflows, &cmd, &vault, 312, "pin_and_m7_verified", "ok");
    assert(strcmp(lab_workflows_storage_result(&workflows), "io_error") == 0);
    for (unsigned i = 0; i < 4; ++i) {
        cmd.kind = (lab_command_kind_t)(LAB_COMMAND_SELFTEST_DB + i);
        execute(&workflows, &cmd, &vault, 32 + i, "selftest_verified",
                i == 2 ? "ok" : "not_required");
        assert(f.selftests[i] == 1);
    }
    lab_workflows_deinit(&workflows);
}

static void foreground_q_cancels_radio_owner(void)
{
    fixture_t f = {.cancel_pending = true};
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t offline;
    assert(lab_workflows_init_with_ops(&offline, &platform, NULL,
                                       &workflow_ops, &f));
    assert(lab_workflows_poll_cancel(&offline));
    lab_workflows_deinit(&offline);

    lab_radio_t radio;
    memset(&radio, 0, sizeof(radio));
    radio.owner_token = 77;
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, &radio,
                                       &workflow_ops, &f));
    assert(lab_workflows_poll_cancel(&workflows));
    assert(lab_radio_cancel_requested(&radio, 77));
    lab_workflows_deinit(&workflows);
}

static void pixie_reports_adapter_open_failure_reason(void)
{
    fixture_t f = {
        .mount_ok = true,
        .cleanup_ok = true,
        .capture_result = WPS_SESSION_FATAL,
        .capture_fatal_reason = (lab_wps_fatal_reason_t)9,
        .observation_store_status = LAB_STORE_OK,
    };
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &f, NULL);
    lab_workflows_t workflows;
    assert(lab_workflows_init_with_ops(&workflows, &platform, NULL,
                                       &workflow_ops, &f));
    lab_workflows_set_emitter(&workflows, capture_output, &f);
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_command_t cmd = command(LAB_COMMAND_WPS_PIXIE);

    execute(&workflows, &cmd, &vault, 41, "capture_failed", "ok");
    assert(strstr(f.emitted, "\"fatal_reason\":\"target_not_found\"") != NULL);
    assert(f.stored_observations == 1);
    lab_workflows_deinit(&workflows);
}

int main(void)
{
    sd_is_always_unmounted();
    campaign_decisions_and_bounds();
    pixie_uses_capture_search_and_fresh_verification();
    pixie_retries_only_fresh_transport_failures();
    pixie_cancels_during_retry_delay();
    pixie_stops_after_capture_lock_or_cleanup_failure();
    known_pin_and_selftests();
    foreground_q_cancels_radio_owner();
    pixie_reports_adapter_open_failure_reason();
    puts("PASS: WPS lab workflows");
    return 0;
}
