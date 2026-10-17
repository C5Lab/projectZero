/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdint.h>

#define JANOS_WPS_IDF_MAJOR 6
#define JANOS_WPS_IDF_MINOR 0
#define JANOS_WPS_IDF_PATCH 1

#define JANOS_WPS_FEATURE_KNOWN_PIN      (1u << 0)
#define JANOS_WPS_FEATURE_FRAGMENTATION  (1u << 1)
#define JANOS_WPS_FEATURE_SECRET_VAULT   (1u << 2)
#define JANOS_WPS_FEATURE_RESULT_STORE   (1u << 3)

#define JANOS_WPS_FEATURES                                              \
    (JANOS_WPS_FEATURE_KNOWN_PIN | JANOS_WPS_FEATURE_FRAGMENTATION |    \
     JANOS_WPS_FEATURE_SECRET_VAULT | JANOS_WPS_FEATURE_RESULT_STORE)

static inline uint32_t janos_wps_build_contract(void)
{
    return JANOS_WPS_FEATURES;
}

