/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janos_wps_memory.h"
#include "janos_wps_service.h"

bool janos_wps_format_accepted(char *output, size_t capacity,
                               uint32_t operation_id,
                               const char *operation_name);
bool janos_wps_format_status(char *output, size_t capacity,
                             const janos_wps_service_status_t *status,
                             const janos_wps_memory_snapshot_t *memory);
bool janos_wps_format_terminal(char *output, size_t capacity,
                               const janos_wps_service_status_t *status,
                               const janos_wps_memory_snapshot_t *memory);
bool janos_wps_format_storage(char *output, size_t capacity,
                              const janos_wps_service_status_t *status);
bool janos_wps_format_campaign_progress(char *output, size_t capacity,
                                        uint32_t operation_id,
                                        unsigned candidate_count,
                                        unsigned attempt_count,
                                        unsigned resume_index);
bool janos_wps_format_secret_status(char *output, size_t capacity,
                                    const janos_wps_service_status_t *status);
bool janos_wps_format_secret_reveal(char *output, size_t capacity,
                                    uint32_t operation_id, const char *pin,
                                    const char *network_key);

