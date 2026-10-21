/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_wire.h"

#include <stdio.h>
#include <string.h>

static bool fits(int written, size_t capacity)
{
    return written >= 0 && (size_t)written < capacity;
}

static const char *phase_name(janos_wps_service_phase_t phase)
{
    static const char *const names[] = {
        "idle", "preparing", "running", "cleanup", "quarantined"
    };
    return (unsigned)phase < sizeof(names) / sizeof(names[0]) ? names[phase] :
                                                               "invalid";
}

bool janos_wps_format_accepted(char *output, size_t capacity,
                               uint32_t operation_id,
                               const char *operation_name)
{
    if (!output || capacity == 0U || !operation_name) return false;
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"accepted\"," 
        "\"run_id\":%u,\"operation\":\"%s\"}",
        (unsigned)operation_id, operation_name), capacity);
}

bool janos_wps_format_status(char *output, size_t capacity,
                             const janos_wps_service_status_t *status,
                             const janos_wps_memory_snapshot_t *memory)
{
    if (!output || capacity == 0U || !status || !memory ||
        status->operation_result[0] == '\0' ||
        status->cleanup_result[0] == '\0') return false;
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"wps_status\"," 
        "\"phase\":\"%s\",\"run_id\":%u,\"generation\":%u," 
        "\"operation_result\":\"%s\",\"cleanup_result\":\"%s\"," 
        "\"bulk_bytes\":%u,\"bulk_peak_bytes\":%u," 
        "\"secret_bytes\":%u,\"secret_peak_bytes\":%u," 
        "\"allocation_failures\":%u}",
        phase_name(status->phase), (unsigned)status->operation_id,
        (unsigned)status->generation, status->operation_result,
        status->cleanup_result, (unsigned)memory->bulk_bytes,
        (unsigned)memory->bulk_peak_bytes, (unsigned)memory->secret_bytes,
        (unsigned)memory->secret_peak_bytes,
        (unsigned)memory->failed_allocations), capacity);
}

bool janos_wps_format_terminal(char *output, size_t capacity,
                               const janos_wps_service_status_t *status,
                               const janos_wps_memory_snapshot_t *memory)
{
    if (!output || capacity == 0U || !status || !memory ||
        status->operation_result[0] == '\0' ||
        status->cleanup_result[0] == '\0') return false;
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"terminal\"," 
        "\"run_id\":%u,\"operation_result\":\"%s\"," 
        "\"cleanup_result\":\"%s\",\"lease_state\":\"%s\"," 
        "\"bulk_bytes\":%u,\"bulk_peak_bytes\":%u," 
        "\"secret_bytes\":%u,\"secret_peak_bytes\":%u," 
        "\"allocation_failures\":%u}",
        (unsigned)status->operation_id, status->operation_result,
        status->cleanup_result,
        status->lease.state == JANOS_RADIO_LEASE_IDLE ? "released" : "retained",
        (unsigned)memory->bulk_bytes, (unsigned)memory->bulk_peak_bytes,
        (unsigned)memory->secret_bytes, (unsigned)memory->secret_peak_bytes,
        (unsigned)memory->failed_allocations), capacity);
}

bool janos_wps_format_storage(char *output, size_t capacity,
                              const janos_wps_service_status_t *status)
{
    if (!output || capacity == 0U || !status ||
        status->storage_result[0] == '\0')
        return false;
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"wps_storage\"," 
        "\"run_id\":%u,\"storage_result\":\"%s\"}",
        (unsigned)status->operation_id, status->storage_result), capacity);
}

bool janos_wps_format_campaign_progress(char *output, size_t capacity,
                                        uint32_t operation_id,
                                        unsigned candidate_count,
                                        unsigned attempt_count,
                                        unsigned resume_index)
{
    if (!output || capacity == 0U || operation_id == 0U) return false;
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"wps_campaign\"," 
        "\"run_id\":%u,\"candidate_count\":%u,\"attempt_count\":%u,"
        "\"resume_index\":%u}",
        (unsigned)operation_id, candidate_count, attempt_count,
        resume_index), capacity);
}

bool janos_wps_format_secret_status(char *output, size_t capacity,
                                    const janos_wps_service_status_t *status)
{
    if (!output || capacity == 0U || !status) return false;
    const char *state = status->secret.state == LAB_SECRET_AVAILABLE ?
        "available" : status->secret.state == LAB_SECRET_EXPIRED ?
        "expired" : "empty";
    return fits(snprintf(output, capacity,
        "{\"schema_version\":1,\"record_type\":\"secret_status\"," 
        "\"state\":\"%s\",\"run_id\":%u,\"remaining_ms\":%llu}",
        state, (unsigned)status->secret.operation_id,
        (unsigned long long)status->secret.remaining_ms), capacity);
}

bool janos_wps_format_secret_reveal(char *output, size_t capacity,
                                    uint32_t operation_id, const char *pin,
                                    const char *network_key)
{
    if (!output || capacity == 0U || operation_id == 0U || !pin ||
        !network_key)
        return false;

    int written = snprintf(output, capacity,
        "SENSITIVE operation_id=%u recovered_pin=%s network_key=\"",
        (unsigned)operation_id, pin);
    if (!fits(written, capacity)) return false;
    size_t used = (size_t)written;

    for (const unsigned char *cursor = (const unsigned char *)network_key;
         *cursor != '\0'; ++cursor) {
        char encoded[7] = {0};
        const char *fragment = encoded;
        size_t fragment_len = 0U;
        switch (*cursor) {
        case '"': fragment = "\\\""; fragment_len = 2U; break;
        case '\\': fragment = "\\\\"; fragment_len = 2U; break;
        case '\b': fragment = "\\b"; fragment_len = 2U; break;
        case '\f': fragment = "\\f"; fragment_len = 2U; break;
        case '\n': fragment = "\\n"; fragment_len = 2U; break;
        case '\r': fragment = "\\r"; fragment_len = 2U; break;
        case '\t': fragment = "\\t"; fragment_len = 2U; break;
        default:
            if (*cursor < 0x20U || *cursor == 0x7fU) {
                (void)snprintf(encoded, sizeof(encoded), "\\u%04x", *cursor);
                fragment_len = 6U;
            } else {
                encoded[0] = (char)*cursor;
                fragment_len = 1U;
            }
            break;
        }
        if (fragment_len >= capacity - used) {
            output[capacity - 1U] = '\0';
            return false;
        }
        memcpy(output + used, fragment, fragment_len);
        used += fragment_len;
    }

    if (capacity - used < 2U) {
        output[capacity - 1U] = '\0';
        return false;
    }
    output[used++] = '"';
    output[used] = '\0';
    return true;
}

