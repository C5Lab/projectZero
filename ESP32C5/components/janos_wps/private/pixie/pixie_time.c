/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "pixie_time.h"

#include <stddef.h>

enum {
    RTL_WINDOW_SECONDS = 86400U,
    PLAUSIBLE_EPOCH_MIN = 1577836800U, /* 2020-01-01 */
    PLAUSIBLE_EPOCH_MAX = 4102444800U, /* 2100-01-01 */
};

pixie_time_result_t pixie_rtl_window_from_epoch(uint32_t epoch,
                                                pixie_rtl_window_t *window)
{
    if (window == NULL) return PIXIE_TIME_INVALID_ARGUMENT;
    window->start = 0U;
    window->end = 0U;
    if (epoch == 0U) return PIXIE_TIME_ABSENT;
    if (epoch < PLAUSIBLE_EPOCH_MIN || epoch > PLAUSIBLE_EPOCH_MAX ||
        epoch < RTL_WINDOW_SECONDS || epoch > UINT32_MAX - RTL_WINDOW_SECONDS)
        return PIXIE_TIME_IMPLAUSIBLE;
    window->start = epoch + RTL_WINDOW_SECONDS;
    window->end = epoch - RTL_WINDOW_SECONDS;
    return PIXIE_TIME_OK;
}
