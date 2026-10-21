/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LAB_WORKFLOWS_H
#define LAB_WORKFLOWS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "campaign_runner.h"
#include "lab_command.h"
#include "lab_platform.h"
#include "lab_radio.h"
#include "lab_result_store.h"
#include "lab_secret.h"
#include "lab_wps_session.h"
#include "pixie.h"
#include "wps_pin_db.h"

typedef struct {
    bool started;
    bool cleanup_ok;
    bool quarantined;
    lab_wps_result_t result;
} lab_workflow_session_outcome_t;

typedef struct {
    size_t (*load_candidates)(void *context, const uint8_t bssid[6],
                              const char *ssid,
                              wps_pin_candidate_t *output, size_t capacity,
                              wps_pin_query_stats_t *stats,
                              wps_pin_db_result_t *result);
    lab_workflow_session_outcome_t (*verify_pin)(
        void *context, const uint8_t bssid[6], const char pin[9]);
    lab_workflow_session_outcome_t (*capture_pixie)(
        void *context, const uint8_t bssid[6], pixie_bundle_t *bundle);
    bool (*recover_pixie)(void *context, const pixie_bundle_t *bundle,
                          const pixie_options_t *options,
                          pixie_result_t *result);
    bool (*selftest)(void *context, lab_command_kind_t kind);
    lab_store_status_t (*store_success)(
        void *context, const lab_result_record_t *record);
    lab_store_status_t (*store_observation)(
        void *context, const lab_device_observation_t *observation);
} lab_workflow_ops_t;

typedef void (*lab_workflow_emit_fn)(void *context, const char *line);

typedef struct {
    lab_platform_t *platform;
    lab_radio_t *radio;
    const lab_workflow_ops_t *ops;
    void *ops_context;
    lab_workflow_emit_fn emit;
    void *emit_context;
    uint8_t previous_session_mac[6];
    bool reuse_previous_session_mac;
    unsigned resume_index;
    unsigned candidate_count;
    unsigned attempt_count;
    bool campaign_progress_valid;
    wps_pin_query_stats_t query_stats;
    const char *storage_result;
    lab_wps_identity_t last_identity;
} lab_workflows_t;

bool lab_workflows_init(lab_workflows_t *workflows,
                        lab_platform_t *platform, lab_radio_t *radio);
bool lab_workflows_init_with_ops(lab_workflows_t *workflows,
                                 lab_platform_t *platform, lab_radio_t *radio,
                                 const lab_workflow_ops_t *ops,
                                 void *ops_context);
void lab_workflows_set_emitter(lab_workflows_t *workflows,
                               lab_workflow_emit_fn emit,
                               void *emit_context);
bool lab_workflows_execute(lab_workflows_t *workflows,
                           const lab_command_t *command,
                           uint32_t operation_id,
                           lab_secret_vault_t *vault,
                           const char **operation_result,
                           const char **cleanup_result);
unsigned lab_workflows_resume_index(const lab_workflows_t *workflows);
bool lab_workflows_campaign_progress(const lab_workflows_t *workflows,
                                     unsigned *candidate_count,
                                     unsigned *attempt_count,
                                     unsigned *resume_index);
const char *lab_workflows_storage_result(const lab_workflows_t *workflows);
/* `not_required` means the workflow failed or completed before acquiring the
 * adapter radio.  It is a successful no-op cleanup for the outer lease. */
bool lab_workflows_cleanup_succeeded(const char *cleanup_result);
/* Polls once and latches cancellation on the active radio owner. */
bool lab_workflows_poll_cancel(lab_workflows_t *workflows);
void lab_workflows_deinit(lab_workflows_t *workflows);

#endif
