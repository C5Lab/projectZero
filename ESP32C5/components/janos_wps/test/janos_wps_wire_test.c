/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_wire.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char output[512];
    assert(janos_wps_format_accepted(output, sizeof(output), 7U,
                                     "wps_verify"));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"accepted\"," 
        "\"run_id\":7,\"operation\":\"wps_verify\"}") == 0);

    janos_wps_service_status_t status = {0};
    status.phase = JANOS_WPS_SERVICE_IDLE;
    status.operation_id = 7U;
    status.generation = 7U;
    memcpy(status.operation_result, "success", 8U);
    memcpy(status.cleanup_result, "restored", 9U);
    memcpy(status.storage_result, "mount_error", 12U);
    status.lease.state = JANOS_RADIO_LEASE_IDLE;
    janos_wps_memory_snapshot_t memory = {
        .bulk_peak_bytes = 24576U,
        .secret_peak_bytes = 24U,
    };
    assert(janos_wps_format_status(output, sizeof(output), &status, &memory));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"wps_status\"," 
        "\"phase\":\"idle\",\"run_id\":7,\"generation\":7," 
        "\"operation_result\":\"success\",\"cleanup_result\":\"restored\"," 
        "\"bulk_bytes\":0,\"bulk_peak_bytes\":24576," 
        "\"secret_bytes\":0,\"secret_peak_bytes\":24," 
        "\"allocation_failures\":0}") == 0);
    assert(janos_wps_format_terminal(output, sizeof(output), &status, &memory));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"terminal\"," 
        "\"run_id\":7,\"operation_result\":\"success\"," 
        "\"cleanup_result\":\"restored\",\"lease_state\":\"released\"," 
        "\"bulk_bytes\":0,\"bulk_peak_bytes\":24576," 
        "\"secret_bytes\":0,\"secret_peak_bytes\":24," 
        "\"allocation_failures\":0}") == 0);
    assert(janos_wps_format_storage(output, sizeof(output), &status));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"wps_storage\"," 
        "\"run_id\":7,\"storage_result\":\"mount_error\"}") == 0);
    assert(janos_wps_format_campaign_progress(output, sizeof(output), 7U,
                                               10U, 3U, 6U));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"wps_campaign\"," 
        "\"run_id\":7,\"candidate_count\":10,\"attempt_count\":3,"
        "\"resume_index\":6}") == 0);
    status.secret.state = LAB_SECRET_AVAILABLE;
    status.secret.operation_id = 7U;
    status.secret.remaining_ms = 298000U;
    assert(janos_wps_format_secret_status(output, sizeof(output), &status));
    assert(strcmp(output,
        "{\"schema_version\":1,\"record_type\":\"secret_status\"," 
        "\"state\":\"available\",\"run_id\":7,\"remaining_ms\":298000}") == 0);

    const char reveal_key[] = {'q', '"', '\\', '\r', '\n', '\t',
                               '\x1b', '\x01', 'z', '\0'};
    assert(janos_wps_format_secret_reveal(output, sizeof(output), 7U,
                                          "12345678", reveal_key));
    assert(strcmp(output,
        "SENSITIVE operation_id=7 recovered_pin=12345678 "
        "network_key=\"q\\\"\\\\\\r\\n\\t\\u001b\\u0001z\"") == 0);

    char short_output[32];
    memset(short_output, 0x5a, sizeof(short_output));
    assert(!janos_wps_format_secret_reveal(short_output,
                                            sizeof(short_output), 7U,
                                            "12345678", reveal_key));
    assert(short_output[sizeof(short_output) - 1U] == '\0');
    assert(!janos_wps_format_secret_reveal(output, sizeof(output), 0U,
                                            "12345678", reveal_key));
    assert(!janos_wps_format_secret_reveal(output, sizeof(output), 7U,
                                            NULL, reveal_key));
    assert(!janos_wps_format_secret_reveal(output, sizeof(output), 7U,
                                            "12345678", NULL));
    puts("PASS: JanOS WPS exact wire contract");
    return 0;
}
