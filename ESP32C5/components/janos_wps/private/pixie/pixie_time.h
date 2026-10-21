/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdint.h>

typedef enum {
    PIXIE_TIME_OK = 0,
    PIXIE_TIME_ABSENT,
    PIXIE_TIME_IMPLAUSIBLE,
    PIXIE_TIME_INVALID_ARGUMENT,
} pixie_time_result_t;

typedef struct {
    uint32_t start;
    uint32_t end;
} pixie_rtl_window_t;

pixie_time_result_t pixie_rtl_window_from_epoch(uint32_t epoch,
                                                pixie_rtl_window_t *window);
